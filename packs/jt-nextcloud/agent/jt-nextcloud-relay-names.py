#!/usr/bin/env python3
"""jt-nextcloud-relay-names: the user id -> display name table for the jt-nextcloud log relay.

Copyright Jason Tools Co., Ltd. / AGPL-3.0-or-later

On an LDAP directory every Nextcloud user id is a UUID, so an alert says
"3094106c-645c-...". This asks Nextcloud itself (occ user:list, run as the
owner of config.php) for each id's display name and writes the rsyslog lookup
table /etc/jt-nextcloud/names.json. jt-nextcloud-relay.conf adds
"userName":"<name>" after "user":"<id>" in the relayed copy, and the pack shows
data.userName next to the id. No app password and no network access needed.

Install as /usr/local/sbin/jt-nextcloud-relay-names and run it from cron
(every 30 minutes). The table is rewritten, and rsyslog sent HUP to reload it,
only when it changes.

  jt-nextcloud-relay-names            rebuild the table
  jt-nextcloud-relay-names --list     print the table
  --nextcloud DIR                     Nextcloud's directory (default /var/www/nextcloud)
"""
import argparse
import json
import os
import pwd
import re
import subprocess
import sys
import tempfile

TABLE = '/etc/jt-nextcloud/names.json'


def clean_name(name):
    """A display name the relay can put inside a JSON string as it is: no quote, backslash or
    control character (the relay copies it byte for byte), whitespace collapsed, at most 64."""
    name = re.sub(r'[\x00-\x1f\x7f"\\]+', ' ', name or '')
    return re.sub(r'\s+', ' ', name).strip()[:64]


def occ_users(nextcloud, php):
    config = os.path.join(nextcloud, 'config', 'config.php')
    owner = pwd.getpwuid(os.stat(config).st_uid).pw_name
    cmd = ['runuser', '-u', owner, '--', php, os.path.join(nextcloud, 'occ'),
           'user:list', '--output=json', '--limit=100000']
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise SystemExit('occ user:list failed: %s' % (r.stderr or r.stdout).strip()[:300])
    return json.loads(r.stdout)


def build(users):
    table = {}
    for uid, name in users.items():
        if not isinstance(uid, str) or not uid or len(uid) > 128 or '"' in uid or '\\' in uid:
            continue
        name = clean_name(name if isinstance(name, str) else '')
        if name and name != uid:
            table[uid] = name
    return {'version': 1, 'nomatch': '', 'type': 'string',
            'table': [{'index': k, 'value': table[k]} for k in sorted(table)]}


def write_if_changed(path, data):
    body = json.dumps(data, ensure_ascii=False, indent=1) + '\n'
    try:
        with open(path, encoding='utf-8') as fh:
            if fh.read() == body:
                return False
    except FileNotFoundError:
        pass
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.names.')
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write(body)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    return True


def main():
    ap = argparse.ArgumentParser(description='Nextcloud user id -> display name table for the jt-nextcloud relay')
    ap.add_argument('--nextcloud', default='/var/www/nextcloud')
    ap.add_argument('--php', default='php')
    ap.add_argument('--table', default=TABLE)
    ap.add_argument('--users-json', help='read occ user:list JSON from this file instead (tests)')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--no-reload', action='store_true', help='do not send rsyslog HUP (tests)')
    a = ap.parse_args()
    if a.users_json:
        with open(a.users_json, encoding='utf-8') as fh:
            users = json.load(fh)
    else:
        users = occ_users(a.nextcloud, a.php)
    data = build(users)
    if a.list:
        for e in data['table']:
            print('%s: %s' % (e['index'], e['value']))
        return 0
    if write_if_changed(a.table, data) and not a.no_reload:
        subprocess.run(['systemctl', 'kill', '-s', 'HUP', 'rsyslog.service'], check=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
