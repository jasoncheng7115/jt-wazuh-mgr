#!/usr/bin/env python3
"""jt-rustdesk-names: the RustDesk ID -> host name table for the jt-rustdesk log relay.

Copyright Jason Tools Co., Ltd. / AGPL-3.0-or-later

The open-source RustDesk server only knows a device by its ID. This builds the
rsyslog lookup table (/etc/jt-rustdesk/names.json) that jt-rustdesk-relay.conf
uses to append " jt_host=<name>" to hbbs.log lines, from two sources:

  1. /etc/jt-rustdesk/names, one "ID: name" per line (# starts a comment); it wins.
  2. the note column of hbbs's own database (read-only; this never writes to it).

Install as /usr/local/sbin/jt-rustdesk-names and run it from cron every 10 minutes.
The table is rewritten, and rsyslog sent HUP to reload it, only when it changes.

  jt-rustdesk-names                  rebuild the table
  jt-rustdesk-names --set ID NAME    add or change one entry in the names file, then rebuild
  jt-rustdesk-names --remove ID      remove one entry from the names file, then rebuild
  jt-rustdesk-names --list           print the table as rsyslog sees it
"""
import argparse
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile

NAMES = '/etc/jt-rustdesk/names'
TABLE = '/etc/jt-rustdesk/names.json'
DB = '/var/lib/rustdesk-server/db_v2.sqlite3'
ID_RE = re.compile(r'^[A-Za-z0-9_-]{6,32}$')     # must match the relay's re_extract


def clean_name(name):
    """A host name the relay can append to a log line as one token."""
    name = re.sub(r'[^A-Za-z0-9._-]+', '-', (name or '').strip()).strip('-.')
    return name[:63]


def safe_file(path):
    """The names file is trusted input to every alert: root-owned, nobody else can write, no symlink."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise SystemExit('%s must be a regular file, not a link' % path)
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise SystemExit('%s must be owned by root and not writable by group or others' % path)


def read_names(path):
    names = {}
    if not os.path.exists(path):
        return names
    safe_file(path)
    with open(path, encoding='utf-8') as fh:
        for n, line in enumerate(fh, 1):
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            rid, sep, name = line.partition(':')
            rid, name = rid.strip(), clean_name(name)
            if not sep or not ID_RE.match(rid) or not name:
                print('%s:%d: ignored (expected "ID: name")' % (path, n), file=sys.stderr)
                continue
            names[rid] = name
    return names


def read_notes(db):
    if not os.path.exists(db):
        return {}
    try:
        con = sqlite3.connect('file:%s?mode=ro' % db, uri=True, timeout=5)
        rows = con.execute("SELECT id, note FROM peer WHERE note IS NOT NULL AND note <> ''").fetchall()
        con.close()
    except sqlite3.Error as e:
        print('cannot read %s: %s' % (db, e), file=sys.stderr)
        return {}
    return {rid: clean_name(note) for rid, note in rows if ID_RE.match(rid or '') and clean_name(note)}


def build(names_path, db):
    table = read_notes(db)
    table.update(read_names(names_path))           # the names file wins
    return {'version': 1, 'nomatch': '', 'type': 'string',
            'table': [{'index': k, 'value': table[k]} for k in sorted(table)]}


def write_if_changed(path, data):
    body = json.dumps(data, ensure_ascii=True, indent=1) + '\n'
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


def edit_names(path, rid, name=None):
    if not ID_RE.match(rid):
        raise SystemExit('not a RustDesk ID: %s' % rid)
    lines = []
    if os.path.exists(path):
        safe_file(path)
        with open(path, encoding='utf-8') as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.split('#', 1)[0].partition(':')[0].strip() != rid]
    else:
        lines = ['# RustDesk ID: host name (jt-rustdesk). One per line; this file wins over the hbbs note column.']
    if name is not None:
        name = clean_name(name)
        if not name:
            raise SystemExit('the name is empty after removing characters a log line cannot carry')
        lines.append('%s: %s' % (rid, name))
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.names.')
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description='RustDesk ID -> host name table for the jt-rustdesk relay')
    ap.add_argument('--names', default=NAMES)
    ap.add_argument('--table', default=TABLE)
    ap.add_argument('--db', default=DB)
    ap.add_argument('--set', nargs=2, metavar=('ID', 'NAME'))
    ap.add_argument('--remove', metavar='ID')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--no-reload', action='store_true', help='do not send rsyslog HUP (tests)')
    a = ap.parse_args()
    if a.set:
        edit_names(a.names, a.set[0], a.set[1])
    elif a.remove:
        edit_names(a.names, a.remove)
    data = build(a.names, a.db)
    if a.list:
        for e in data['table']:
            print('%s: %s' % (e['index'], e['value']))
        return 0
    if write_if_changed(a.table, data) and not a.no_reload:
        subprocess.run(['systemctl', 'kill', '-s', 'HUP', 'rsyslog.service'], check=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
