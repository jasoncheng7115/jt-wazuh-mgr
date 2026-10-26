#!/usr/bin/env python3
# jt-zimbra-baseline-check - is the Zimbra web-file baseline still the right one?
# Part of the jt-zimbra rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
"""Report Zimbra servers whose release is not covered by etc/lists/zimbra-webfiles.

Rule 100802 calls any jsp, jar, class or war file under Zimbra's web
directories that is not in the baseline "strongly suggests a web shell" (level
14). Every Zimbra upgrade renames its version-stamped jars
(zm-taglib-10.1.20.<stamp>.jar becomes zm-taglib-10.1.21.<stamp>.jar), so
until the list is regenerated each legitimate change to those files raises
100802 at level 14, and a real web shell would be lost in that noise. Nothing
told anyone the list was out of date: one server ran 10.1.21 for eight weeks
against a 10.1.20 baseline.

This script needs no access to the Zimbra servers. It reads the package
inventory syscollector already keeps on this manager node (wazuh-db, SELECT
only), derives each server's Zimbra release, and reads the releases the list
covers: the marker keys jt-zimbra-baseline.sh writes (jt-zimbra-release/X.Y.Z)
and, for a list made another way, the version stamps in its jar names. One
JSON event per change goes to analysisd's queue for the rules in
zz-133300-jt_zimbra_baseline_rules.xml. The events are the manager's own
(location jt-zimbra-baseline) and name the server in their fields: analysisd
drops queue events that claim to come from an agent once any agent is
registered.

Run it on every node of a cluster: each node keeps the inventory of the agents
connected to it and the script handles only those. The list itself is copied
to every node by the cluster.

    jt-zimbra-baseline-check.py --wazuh-path /var/ossec            normal run (cron)
    jt-zimbra-baseline-check.py --wazuh-path /var/ossec --dry-run  print, send and save nothing
    jt-zimbra-baseline-check.py --wazuh-path /var/ossec --list     what the inventory and list hold
"""

import argparse
import json
import os
import re
import socket
import struct
import sys
import time

VERSION = '1.0'
PROG = 'jt-zimbra-baseline-check'
LOCATION = 'jt-zimbra-baseline'
FIELD = 'jt_zimbra_baseline'
LIST = 'zimbra-webfiles'
REMIND_DAYS = 7

# Packages whose version is the Zimbra release the web directories come from.
# The release packages (zimbra-core, zimbra-store) carry "10.1.20.GA.10120...";
# a patch release updates the web packages first ("10.1.21.1789476131-1.u20"),
# and their jars are the ones renamed, so the highest of these wins.
RELEASE_PACKAGES = re.compile(
    r'^zimbra-(?:core|store|patch|mbox-(?:webclient-war|admin-console-war|service|war|store-libs)'
    r'|common-core-jar|common-mbox-conf)$')
RELEASE = re.compile(r'^(?:\d+:)?(\d+)\.(\d+)\.(\d+)(?:[.\-_]|$)')
STAMPED_JAR = re.compile(r'-(\d+)\.(\d+)\.(\d+)\.\d{9,}\.jar$')
MARKER = re.compile(r'^jt-zimbra-release/(\d+)\.(\d+)\.(\d+)$')


def log(msg):
    sys.stderr.write('%s %s: %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), PROG, msg))


def release_of(version):
    """'10.1.20.GA.10120.UBUNTU22.64' -> (10, 1, 20); not a Zimbra release -> None.
    Zimbra's third-party packages (zimbra-jetty-distribution 9.4.57...,
    zimbra-openssl 3.0.x) never reach this: only RELEASE_PACKAGES are read."""
    m = RELEASE.match(version or '')
    if not m:
        return None
    key = tuple(int(x) for x in m.groups())
    return key if key[0] >= 8 else None


def text(key):
    return '%d.%d.%d' % key


def server_release(packages):
    """The release of one server's web directories, and the packages it came from."""
    best, names = None, []
    for p in packages:
        key = release_of(p.get('version'))
        if key is None or not RELEASE_PACKAGES.match(p.get('name') or ''):
            continue
        if best is None or key > best:
            best, names = key, []
        if key == best:
            names.append('%s %s' % (p['name'], p['version']))
    return best, sorted(names)


def covered_releases(lines):
    """Releases a baseline covers: its marker keys, else its stamped jar names."""
    markers, stamps, entries = set(), set(), 0
    for line in lines:
        key = line.split(':', 1)[0].strip()
        if not key:
            continue
        m = MARKER.match(key)
        if m:
            markers.add(tuple(int(x) for x in m.groups()))
            continue
        entries += 1
        s = STAMPED_JAR.search(key)
        if s:
            stamps.add(tuple(int(x) for x in s.groups()))
    return (markers or stamps), entries, 'markers' if markers else 'jar names'


def read_list(path):
    with open(path, encoding='utf-8', errors='replace') as fh:
        return fh.read().splitlines()


# ---------------------------------------------------------------- wazuh-db

def wdb_query(path, query):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    try:
        s.connect(path)
        body = query.encode('utf-8')
        s.sendall(struct.pack('<I', len(body)) + body)
        head = b''
        while len(head) < 4:
            chunk = s.recv(4 - len(head))
            if not chunk:
                raise OSError('wazuh-db closed the connection')
            head += chunk
        size = struct.unpack('<I', head)[0]
        data = b''
        while len(data) < size:
            chunk = s.recv(min(65536, size - len(data)))
            if not chunk:
                raise OSError('wazuh-db closed the connection')
            data += chunk
    finally:
        s.close()
    reply = data.decode('utf-8', 'replace')
    status, _, payload = reply.partition(' ')
    if status != 'ok':
        raise OSError('wazuh-db: %s' % reply[:200])
    return json.loads(payload or '[]')


def local_node(wazuh):
    """This node's cluster name, or None when the cluster is disabled."""
    try:
        with open(os.path.join(wazuh, 'etc', 'ossec.conf'), encoding='utf-8', errors='replace') as fh:
            conf = fh.read()
    except OSError:
        return None
    m = re.search(r'<cluster>(.*?)</cluster>', re.sub(r'<!--.*?-->', '', conf, flags=re.S), re.S)
    if not m or re.search(r'<disabled>\s*yes\s*</disabled>', m.group(1)):
        return None
    n = re.search(r'<node_name>\s*([^<\s]+)\s*</node_name>', m.group(1))
    return n.group(1) if n else None


def inventory(wdb, node):
    """{agent id: {name, ip, status, packages}} for the agents with Zimbra packages."""
    agents = wdb_query(wdb, 'global sql SELECT id, name, ip, node_name, connection_status FROM agent')
    out = {}
    for a in agents:
        aid = int(a.get('id', -1))
        if aid < 0 or a.get('connection_status') == 'never_connected':
            continue
        if aid != 0 and node and a.get('node_name') != node:
            continue
        try:
            rows = wdb_query(wdb, "agent %03d sql SELECT name, version FROM sys_programs "
                                  "WHERE name LIKE 'zimbra-%%'" % aid)
        except OSError as exc:
            log('agent %03d: %s' % (aid, exc))
            continue
        if rows:
            out['%03d' % aid] = {'name': a.get('name') or '', 'ip': a.get('ip') or 'any',
                                 'status': a.get('connection_status') or '', 'packages': rows}
    return out


# ---------------------------------------------------------------- state and events

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
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def send(queue, event, dry=False):
    msg = '1:%s:%s' % (LOCATION, json.dumps({FIELD: event}, sort_keys=True, separators=(',', ':')))
    if dry:
        print(msg)
        return
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.connect(queue)
        s.send(msg.encode('utf-8'))
    finally:
        s.close()


def evaluate(inv, covered, entries, source, previous, now):
    """Events to send and the new per-server state.

    stale: the server's release is not in the list. Reported when first seen
    or when the release changes, then once a week while it lasts. covered: the
    list knows the release; reported once (level 2) when first seen and once
    (level 3) when a stale server becomes covered again.
    """
    events, state = [], {}
    cov = ','.join(text(k) for k in sorted(covered))
    for aid, agent in sorted(inv.items()):
        release, pkgs = server_release(agent['packages'])
        if release is None:
            continue
        status = 'covered' if release in covered else 'stale'
        before = previous.get(aid) or {}
        if not before:
            change = 'new'
        elif before.get('release') != text(release) or before.get('status') != status:
            change = 'fixed' if status == 'covered' and before.get('status') == 'stale' else 'changed'
        elif status == 'stale' and now - before.get('alerted', 0) >= REMIND_DAYS * 86400:
            change = 'reminder'
        else:
            change = None
        rec = {'release': text(release), 'status': status, 'agent_name': agent['name'],
               'alerted': before.get('alerted', 0),
               'since': before.get('since') if before.get('status') == status else now}
        if change:
            ev = {'event': 'baseline', 'status': status, 'change': change, 'release': text(release),
                  'covered': cov, 'list_entries': entries, 'covered_from': source,
                  'agent_id': aid, 'agent_name': agent['name'], 'agent_ip': agent['ip'],
                  'packages': '; '.join(pkgs)[:300],
                  'since': time.strftime('%Y-%m-%d', time.localtime(rec['since'] or now))}
            if before.get('release') and before['release'] != text(release):
                ev['previous_release'] = before['release']
            events.append(ev)
            rec['alerted'] = now
        state[aid] = rec
    return events, state


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--wazuh-path', default='/var/ossec')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--list', action='store_true')
    args = ap.parse_args(argv)
    wazuh = args.wazuh_path
    wdb = os.path.join(wazuh, 'queue', 'db', 'wdb')
    queue = os.path.join(wazuh, 'queue', 'sockets', 'queue')
    list_path = os.path.join(wazuh, 'etc', 'lists', LIST)
    state_path = os.path.join(wazuh, 'var', 'jt-zimbra-baseline.state')
    now = int(time.time())

    def report(event):
        if args.list:
            return
        try:
            send(queue, event, dry=args.dry_run)
        except OSError as exc:
            log('cannot write to the analysisd queue: %s' % exc)

    try:
        inv = inventory(wdb, local_node(wazuh))
    except (OSError, ValueError) as exc:
        log('cannot read the inventory: %s' % exc)
        report({'event': 'status', 'state': 'wdb_error', 'detail': str(exc)[:300]})
        return 2
    if not inv:
        log('no agent of this node has Zimbra packages')
        return 0

    state = load_state(state_path)
    try:
        lines = read_list(list_path)
        covered, entries, source = covered_releases(lines)
        error = '' if covered else 'the list names no Zimbra release (no marker key, no version-stamped jar)'
    except OSError as exc:
        covered, entries, source, error = set(), 0, '', '%s: %s' % (type(exc).__name__, exc)

    if args.list:
        print('list: %d entries, covers %s (from %s)%s' % (
            entries, ', '.join(text(k) for k in sorted(covered)) or 'nothing', source or '-',
            ' -- ' + error if error else ''))
        for aid, a in sorted(inv.items()):
            release, pkgs = server_release(a['packages'])
            print('%s %-20s %-8s %s' % (aid, a['name'], text(release) if release else '-', '; '.join(pkgs)))
        return 0

    if error:
        # without a usable list every Zimbra server is unprotected by 100802's
        # baseline: say so on the first failure and then once a day
        h = state.get('list_error') or {}
        if not h or now - h.get('reported', 0) >= 86400:
            report({'event': 'status', 'state': 'list_error', 'detail': error[:300],
                    'servers': ','.join(sorted(a['name'] for a in inv.values()))[:300]})
            h = {'reported': now, 'since': h.get('since') or now}
        state['list_error'] = h
        if not args.dry_run:
            save_state(state_path, state)
        return 1
    if state.pop('list_error', None):
        report({'event': 'status', 'state': 'list_ok', 'detail': 'the list is readable again'})

    events, servers = evaluate(inv, covered, entries, source, state.get('servers') or {}, now)
    for ev in events:
        report(ev)
    state['servers'] = servers
    state['version'] = VERSION
    if not args.dry_run:
        save_state(state_path, state)
    log('%d Zimbra servers, list covers %s, %d events' % (
        len(servers), ', '.join(text(k) for k in sorted(covered)), len(events)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
