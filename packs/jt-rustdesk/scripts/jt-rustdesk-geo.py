#!/usr/bin/env python3
# jt-rustdesk-geo - keep the CDB list of "home country" IPv4 prefixes for jt-rustdesk
# Part of the jt-rustdesk rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
"""Write etc/lists/jt-rustdesk-home from a regional internet registry's
delegated statistics, so that rules 133607 / 133608 can tell a RustDesk client
registering from a home-country address from one registering from abroad.

The countries come from etc/jt-packs/jt-rustdesk.conf ("countries = TW, JP";
TW when the file is missing). The registry file is APNIC's by default (all of
Asia-Pacific; give another registry's delegated-*-extended-latest URL with
--url for other regions). Each allocated or assigned IPv4 block becomes the
keys address_match_key can find: whole octets, the block expanded to the next
octet boundary down (a /25 is written as its /24). Downloads at most once a
day. A result with fewer than half the keys of the last good one is refused
and the list is left alone. After a change the ruleset of this node is
reloaded (that recompiles the list); cluster workers get the file from the
master and reload with --reload-if-changed from their own cron line. Problems
are written to analysisd's queue as events for rules 133690-133692.

    jt-rustdesk-geo.py --wazuh-path /var/ossec              normal run (cron, master)
    jt-rustdesk-geo.py --wazuh-path /var/ossec --check      print what would change
    jt-rustdesk-geo.py --wazuh-path /var/ossec --from-file F   build from a local copy
    jt-rustdesk-geo.py --wazuh-path /var/ossec --reload-if-changed   (cluster workers)
"""

import argparse
import ipaddress
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
PROG = 'jt-rustdesk-geo'
LIST_NAME = 'jt-rustdesk-home'
URL = 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest'
FETCH_EVERY = 20 * 3600
STALE_DAYS = 14
STALE_REMIND = 3 * 86400
TIMEOUT = 120
COUNTRY = re.compile(r'^[A-Z]{2}$')
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


def read_countries(path):
    """Countries from the settings file: "countries = TW, JP". TW when absent."""
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip()
                if '=' in line:
                    key, value = (x.strip() for x in line.split('=', 1))
                    if key == 'countries':
                        found = [c.strip().upper() for c in value.replace(',', ' ').split()]
                        good = [c for c in found if COUNTRY.match(c)]
                        if good:
                            return sorted(set(good))
    except OSError:
        pass
    return ['TW']


def fetch(url):
    headers = {'User-Agent': '%s/%s (jt-wazuh-mgr)' % (PROG, VERSION)}
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=TIMEOUT,
                                context=verifying_context()) as r:
        return r.read().decode('ascii', 'replace')


def networks(text, countries):
    """IPv4 networks allocated or assigned to the countries, from a delegated-stats file."""
    out = []
    for line in text.splitlines():
        parts = line.strip().split('|')
        if len(parts) < 7 or parts[2] != 'ipv4' or parts[1] not in countries:
            continue
        if parts[6] not in ('allocated', 'assigned'):
            continue
        try:
            start = ipaddress.IPv4Address(parts[3])
            count = int(parts[4])
        except (ValueError, ipaddress.AddressValueError):
            continue
        if count < 1:
            continue
        end = ipaddress.IPv4Address(int(start) + count - 1)
        out.extend(ipaddress.summarize_address_range(start, end))
    return out


def cdb_keys(net):
    """address_match_key finds the whole address and each octet prefix ("1.34.", "1.", ...).
    A block on an octet boundary is one key; others are expanded to the next boundary down;
    a /25 to /32 is written as its /24 (good enough for a country)."""
    plen = net.prefixlen
    if plen < 8:
        return ['%d.' % (int(net.network_address) >> 24) for net in net.subnets(new_prefix=8)]
    target = 8 if plen <= 8 else 16 if plen <= 16 else 24
    if plen > 24:
        net = net.supernet(new_prefix=24)
        plen = 24
    keep = target // 8
    return ['.'.join(str(sub.network_address).split('.')[:keep]) + '.'
            for sub in net.subnets(new_prefix=target)]


def build(text, countries):
    keys = {}
    for net in networks(text, countries):
        for key in cdb_keys(net):
            keys[key] = 'home'
    # a longer prefix under a shorter one is redundant
    shorts = {k for k in keys if k.count('.') < 3}
    body = []
    for k in sorted(keys, key=lambda k: [int(x) for x in k.rstrip('.').split('.')]):
        parts = k.rstrip('.').split('.')
        if any('.'.join(parts[:n]) + '.' in shorts for n in range(1, len(parts))):
            continue
        body.append('%s:%s\n' % (k, keys[k]))
    return ''.join(body), len(body)


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
    msg = '1:jt-rustdesk-geo:%s' % json.dumps({'jt_rustdesk_geo': event}, sort_keys=True, separators=(',', ':'))
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
    ap.add_argument('--url', default=URL, help='delegated statistics URL (default APNIC)')
    ap.add_argument('--from-file', help='build from a local delegated statistics file, no download')
    ap.add_argument('--force', action='store_true', help='download even if fetched within 20 hours')
    ap.add_argument('--check', action='store_true', help='build and compare, write nothing')
    ap.add_argument('--reload-if-changed', action='store_true',
                    help='cluster worker: no download; reload when the list the master synced changed')
    args = ap.parse_args(argv)
    wazuh = args.wazuh_path
    path = os.path.join(wazuh, 'etc', 'lists', LIST_NAME)
    state_path = os.path.join(wazuh, 'var', 'jt-rustdesk-geo.state')
    state = load_state(state_path)
    now = int(time.time())
    state.setdefault('ok', now)

    if args.reload_if_changed:
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return 0
        if mtime > state.get('reloaded_mtime', 0) + 0.001 and reload_ruleset(wazuh):
            state['reloaded_mtime'] = mtime
            save_state(state_path, state)
        return 0

    countries = read_countries(os.path.join(wazuh, 'etc', 'jt-packs', 'jt-rustdesk.conf'))
    if not args.from_file and not args.force and not args.check and \
            now - state.get('fetched', 0) < FETCH_EVERY and state.get('countries') == countries:
        return 0
    try:
        if args.from_file:
            with open(args.from_file, encoding='ascii', errors='replace') as fh:
                text = fh.read()
        else:
            text = fetch(args.url)
    except Exception as exc:
        log('download failed: %s' % exc)
        if not args.check:
            report(wazuh, state, now, False, str(exc))
            save_state(state_path, state)
        return 1
    if not args.from_file:
        state['fetched'] = now
    body, count = build(text, countries)
    last = state.get('count', 0) if state.get('countries') == countries else 0
    if count < 1 or (last and count < last // 2):
        msg = 'refused: %d prefixes for %s (last good list had %d)' % (count, ','.join(countries), last)
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
    if args.check:
        print('%d prefixes for %s; %s' % (count, ','.join(countries), 'unchanged' if body == old else 'would change'))
        return 0
    state.update(count=count, countries=countries)
    if body != old:
        write_list(path, body)
        log('%s: %d prefixes for %s' % (path, count, ','.join(countries)))
        if reload_ruleset(wazuh):
            state['reloaded_mtime'] = os.path.getmtime(path)
    report(wazuh, state, now, True)
    save_state(state_path, state)
    return 0


if __name__ == '__main__':
    sys.exit(main())
