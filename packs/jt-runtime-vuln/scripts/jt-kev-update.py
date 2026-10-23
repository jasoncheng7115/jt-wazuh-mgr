#!/usr/bin/env python3
# jt-kev-update - keep a CDB list of CISA's Known Exploited Vulnerabilities
# Part of the jt-runtime-vuln rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
"""Write etc/lists/jt-kev (one CVE per line) from CISA's KEV catalogue, so that
rule 133200 can raise any Wazuh vulnerability detection of a known exploited
CVE to level 12, whatever severity the feed gives it (or none yet).

Downloads at most once a day with If-Modified-Since, from CISA and, when that
fails, from CISA's own GitHub mirror. A catalogue that parses to fewer than
half the entries of the last good one is refused, and the list is left alone.
After a change the ruleset of this node is reloaded (that recompiles the CDB
list); cluster workers get the file from the master and reload through their
own jt-ioc --reload-if-stale job, or a cron line running this script with
--reload-if-changed. Problems are written to analysisd's queue as events for
rules 133210-133213.

    jt-kev-update.py --wazuh-path /var/ossec              normal run (cron, master)
    jt-kev-update.py --wazuh-path /var/ossec --check      print what would change
    jt-kev-update.py --wazuh-path /var/ossec --reload-if-changed   (cluster workers)
"""

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

VERSION = '1.0'
PROG = 'jt-kev-update'
LIST_NAME = 'jt-kev'
URLS = ('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json')
FETCH_EVERY = 20 * 3600
STALE_DAYS = 7
STALE_REMIND = 3 * 86400
TIMEOUT = 60
CVE = re.compile(r'^CVE-\d{4}-\d{4,}$')
SYSTEM_CA_BUNDLES = ('/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt',
                     '/etc/ssl/ca-bundle.pem', '/etc/ssl/cert.pem', '/usr/local/share/certs/ca-root-nss.crt')


def log(msg):
    sys.stderr.write('%s %s: %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), PROG, msg))


def verifying_context():
    context = ssl.create_default_context()
    if not context.cert_store_stats().get('x509_ca'):
        for bundle in SYSTEM_CA_BUNDLES:
            if os.path.isfile(bundle):
                try:
                    context.load_verify_locations(cafile=bundle)
                    break
                except (ssl.SSLError, OSError):
                    continue
    return context


def fetch(urls, since=None):
    """(catalogue dict or None if not modified, url, last-modified) or raises."""
    errors = []
    for url in urls:
        headers = {'User-Agent': '%s/%s (jt-wazuh-mgr)' % (PROG, VERSION)}
        if since:
            headers['If-Modified-Since'] = since
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=TIMEOUT,
                                        context=verifying_context()) as r:
                return json.loads(r.read().decode('utf-8')), url, r.headers.get('Last-Modified') or ''
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return None, url, since
            errors.append('%s: HTTP %d' % (url, exc.code))
        except Exception as exc:
            errors.append('%s: %s' % (url, exc))
    raise OSError('; '.join(errors))


def build(catalogue):
    """CDB body: "CVE-YYYY-NNNN:vendor product (added YYYY-MM-DD)", sorted."""
    lines = {}
    for v in catalogue.get('vulnerabilities') or []:
        cve = str(v.get('cveID') or '').strip().upper()
        if not CVE.match(cve):
            continue
        label = '%s %s (added %s)' % (v.get('vendorProject') or '', v.get('product') or '', v.get('dateAdded') or '')
        label = re.sub(r'[^\w .()/+-]', ' ', label)          # no ':' or quotes in a CDB value
        lines[cve] = ' '.join(label.split())[:120]
    return ''.join('%s:%s\n' % (k, lines[k]) for k in sorted(lines)), len(lines)


def write_list(path, body):
    tmp = path + '.jt-new.tmp'        # .tmp: skipped by the cluster, never used by the compiler
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(body)
    try:
        import grp
        import pwd
        os.chown(tmp, pwd.getpwnam('wazuh').pw_uid, grp.getgrnam('wazuh').gr_gid)
    except Exception:
        pass
    os.chmod(tmp, 0o660)
    os.replace(tmp, path)


def reload_ruleset(wazuh):
    python = os.path.join(wazuh, 'framework', 'python', 'bin', 'python3')
    code = ('import asyncio\n'
            'from wazuh.core.analysis import send_reload_ruleset_msg as s\n'
            'r = asyncio.run(s({"module": "api"}))\n'
            'print("ok" if r.success else "failed", "; ".join(r.warnings or r.errors or []))\n')
    try:
        out = subprocess.run([python, '-c', code], capture_output=True, text=True, timeout=300)
    except Exception as exc:
        log('ruleset reload failed: %s' % exc)
        return False
    result = ((out.stdout or '').strip().splitlines() or [(out.stderr or '').strip()[-200:]])[-1]
    log('ruleset reload: %s' % result)
    return result.startswith('ok')


def send(wazuh, event):
    msg = '1:jt-runtime:%s' % json.dumps({'jt_runtime': dict(event, event='kev')}, sort_keys=True,
                                          separators=(',', ':'))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.connect(os.path.join(wazuh, 'queue', 'sockets', 'queue'))
        s.send(msg.encode('utf-8'))
    finally:
        s.close()


def load_state(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(state, fh, sort_keys=True)
    os.replace(tmp, path)


def report(wazuh, state, now, ok, detail=''):
    """failing once, stale (list older than STALE_DAYS) every three days, recovered once."""
    h = state.setdefault('health', {})
    if ok:
        state['ok'] = now
        if h.get('failing_since'):
            send(wazuh, {'state': 'recovered', 'hours': int((now - h['failing_since']) / 3600)})
        state['health'] = {}
        return
    if not h.get('failing_since'):
        h['failing_since'] = now
        send(wazuh, {'state': 'failing', 'detail': detail[:300]})
    age_days = (now - state.get('ok', now)) / 86400
    if age_days >= STALE_DAYS and now - h.get('stale_reported', 0) >= STALE_REMIND:
        h['stale_reported'] = now
        send(wazuh, {'state': 'stale', 'days': int(age_days), 'detail': detail[:300]})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--wazuh-path', default='/var/ossec')
    ap.add_argument('--url', action='append', help='catalogue URL (repeatable; default CISA, then its GitHub mirror)')
    ap.add_argument('--force', action='store_true', help='download even if fetched within 20 hours')
    ap.add_argument('--check', action='store_true', help='download and compare, write nothing')
    ap.add_argument('--reload-if-changed', action='store_true',
                    help='cluster worker: no download; reload when the list the master synced changed')
    args = ap.parse_args(argv)
    wazuh = args.wazuh_path
    path = os.path.join(wazuh, 'etc', 'lists', LIST_NAME)
    state_path = os.path.join(wazuh, 'var', 'jt-kev.state')
    state = load_state(state_path)
    now = int(time.time())
    state.setdefault('ok', now)        # staleness counts from the first run

    if args.reload_if_changed:
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return 0
        if mtime > state.get('reloaded_mtime', 0) + 0.001 and reload_ruleset(wazuh):
            state['reloaded_mtime'] = mtime
            save_state(state_path, state)
        return 0

    if not args.force and not args.check and now - state.get('fetched', 0) < FETCH_EVERY \
            and os.path.isfile(path):
        return 0
    try:
        catalogue, url, modified = fetch(args.url or URLS, None if (args.force or args.check or not os.path.isfile(path))
                                         else state.get('last_modified'))
    except OSError as exc:
        log('download failed: %s' % exc)
        if not args.check:
            report(wazuh, state, now, False, str(exc))
            save_state(state_path, state)
        return 1
    state['fetched'] = now
    if catalogue is None:
        log('not modified since %s' % state.get('last_modified'))
        report(wazuh, state, now, True)
        save_state(state_path, state)
        return 0
    body, count = build(catalogue)
    last = state.get('count', 0)
    if count < 100 or (last and count < last // 2):
        msg = 'refused: %d entries from %s (last good list had %d)' % (count, url, last)
        log(msg)
        if not args.check:
            report(wazuh, state, now, False, msg)
            save_state(state_path, state)
        return 1
    try:
        with open(path, encoding='utf-8') as fh:
            old = fh.read()
    except OSError:
        old = ''
    added = sorted(set(re.findall(r'^(CVE-[^:]+):', body, re.M)) - set(re.findall(r'^(CVE-[^:]+):', old, re.M)))
    if args.check:
        print('%d entries (%s), %d new: %s' % (count, catalogue.get('catalogVersion', '?'), len(added),
                                               ' '.join(added[:20])))
        return 0
    state.update(last_modified=modified, count=count, catalog=catalogue.get('catalogVersion', ''))
    if body != old:
        write_list(path, body)
        state['written'] = now
        log('%s: %d CVEs, %d new (catalogue %s)' % (path, count, len(added), state['catalog']))
        if reload_ruleset(wazuh):
            state['reloaded_mtime'] = os.path.getmtime(path)
    report(wazuh, state, now, True)
    save_state(state_path, state)
    return 0


if __name__ == '__main__':
    sys.exit(main())
