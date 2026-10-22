#!/usr/bin/env python3
# jt-php-versions - compare the PHP installed on every agent with php.net
# Part of the jt-php rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
"""Report agents whose PHP is behind the latest security release of its branch,
or on a branch php.net no longer supports.

Wazuh's vulnerability detection waits for its CVE feed. A PHP security release
is public hours or days before the feed lists it, and packages that follow
upstream versions (deb.sury.org, Remi, FreeBSD ports, Alpine, Windows builds)
are often matched late or not at all. This script needs no feed: it reads the
package inventory that syscollector already keeps on this manager node and the
release list php.net publishes, and writes one JSON event per finding into
analysisd's queue for the rules in zz-133100-jt_php_rules.xml. The events are
the manager's own (location jt-php) and name the agent in their fields:
analysisd drops events from the local queue that claim to come from an agent
("[id] (name) ip->location") as soon as any agent is registered (4.14.9).

It only reads: the wazuh-db socket (SELECT statements) and php.net. It writes
its state file and events. Run it on every node of a cluster: each node keeps
the inventory of the agents connected to it, and the script handles only
those (by the node name in the agent table).

    jt-php-versions.py --wazuh-path /var/ossec            normal run (cron)
    jt-php-versions.py --wazuh-path /var/ossec --dry-run  print, send and save nothing
    jt-php-versions.py --wazuh-path /var/ossec --list     what the inventory holds now
"""

import argparse
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.request

VERSION = '1.0.2'
PROG = 'jt-php-versions'
LOCATION = 'jt-php'
PHPNET = 'https://www.php.net/releases/'
REMIND_DAYS = 7           # a host still behind is reminded once a week
STALE_HOURS = 48          # php.net unreachable this long: release data too old to trust
STALE_REMIND_HOURS = 72   # and then repeated every three days
CACHE_HOURS = 20          # release data is fetched again after this
TIMEOUT = 30
# Wazuh's own python (/var/ossec/framework/python) has an empty CA store; the
# system bundle is loaded explicitly when the default one holds nothing.
SYSTEM_CA_BUNDLES = ('/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt',
                     '/etc/ssl/ca-bundle.pem', '/etc/ssl/cert.pem', '/usr/local/share/certs/ca-root-nss.crt')

# Package names that carry the PHP runtime itself, not an extension:
#   Debian/Ubuntu (distribution or deb.sury.org): php8.2, php8.2-fpm, php8.2-cli,
#     php8.2-cgi, php8.2-common, libapache2-mod-php8.2, php (metapackage)
#   RHEL/Fedora/Remi: php, php-cli, php-fpm, php-common, php82-php-fpm (SCL)
#   FreeBSD: php83, php83-... extensions are left out
#   Alpine: php82, php82-fpm      macOS Homebrew: php, php@8.2
#   Windows: "PHP 8.2.12" (installer display name)
RUNTIME = re.compile(
    r'^(?:php(?:\d+(?:\.\d+)?)?(?:-php)?(?:-(?:cli|fpm|cgi|common|embed|phpdbg|litespeed|apache2handler))?'
    r'|libapache2-mod-php(?:\d+(?:\.\d+)?)?|mod_php\d*|lsphp\d+|php@\d+\.\d+|php \d+\.\d+.*)$', re.I)
UPSTREAM_VERSION = re.compile(r'^(?:\d+:)?(\d+)\.(\d+)\.(\d+)')
SURY = re.compile(r'deb\.sury\.org|\+0~\d{8}\.\d+\+debian\d+~1\.gbp')
# a package that serves web requests; "cli"/"common" alone do not
WEB_SAPI = re.compile(r'fpm|cgi|mod[-_]php|apache2handler|litespeed|lsphp|embed', re.I)
CLI_ONLY = re.compile(r'^php(?:\d+(?:\.\d+)?)?(?:-php)?-(?:cli|common|phpdbg)$', re.I)
DISTRO = re.compile(r'[~+]deb\d+u\d+|ubuntu\d|\.el\d|\.fc\d|\.amzn|\.mga\d|suse|\.sle|\+b\d+$')


def log(msg):
    sys.stderr.write('%s %s: %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), PROG, msg))


# ---------------------------------------------------------------- versions

def vkey(v):
    m = UPSTREAM_VERSION.match(v or '')
    return tuple(int(x) for x in m.groups()) if m else None


def branch_of(v):
    k = vkey(v)
    return '%d.%d' % k[:2] if k else None


def classify(version, fmt):
    """upstream: the packager ships php.net's versions, so php.net's release
    list is the yardstick. distro: Debian, Ubuntu, RHEL and the like keep a
    version and backport fixes into it; their own advisories (and Wazuh's
    vulnerability detection) are the yardstick, not php.net."""
    if SURY.search(version) or 'remi' in version.lower():
        return 'upstream'
    if DISTRO.search(version):
        return 'distro'
    return 'upstream'


def packager(version, fmt):
    v = version.lower()
    if SURY.search(version):
        return 'deb.sury.org'
    if 'remi' in v:
        return 'remi'
    if 'ubuntu' in v:
        return 'ubuntu'
    if re.search(r'deb\d+u\d+|~deb\d+', v):
        return 'debian'
    if re.search(r'\.el\d', v):
        return 'rhel'
    return fmt or 'unknown'


# ---------------------------------------------------------------- php.net

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


def fetch_json(url):
    req = urllib.request.Request(url, headers={'User-Agent': '%s/%s (jt-wazuh-mgr)' % (PROG, VERSION)})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=verifying_context()) as r:
        return json.loads(r.read().decode('utf-8'))


def fetch_releases(base, branches):
    """{'active': {branch: latest}, 'branches': {branch: {version: [tags]}}}"""
    active = {}
    for major in fetch_json(base + 'active.php').values():
        for br, info in major.items():
            active[br] = info['version']
    if not active:
        raise ValueError('php.net listed no supported branch')
    hist = {}
    for br in sorted(set(branches) | set(active)):
        data = fetch_json('%sindex.php?json&version=%s&max=200' % (base, br))
        if isinstance(data, dict) and 'version' in data and 'tags' in data:   # a single release
            data = {data['version']: data}
        if not isinstance(data, dict) or not data:
            continue
        hist[br] = {v: list((d or {}).get('tags') or []) for v, d in data.items() if vkey(v)}
    return {'active': active, 'branches': hist, 'fetched': int(time.time())}


def assess(installed, br, releases):
    """status, latest, newer security releases for one upstream-tracking install."""
    active = releases['active']
    hist = releases['branches'].get(br) or {}
    known = sorted((v for v in hist), key=vkey)
    latest = active.get(br) or (known[-1] if known else None)
    newer = [v for v in known if vkey(v) > vkey(installed)]
    security = [v for v in newer if 'security' in hist.get(v, [])]
    if br not in active:
        return 'eol', latest, security
    if security:
        return 'behind_security', latest, security
    if newer or (latest and vkey(latest) > vkey(installed)):
        return 'behind', latest, security
    return 'current', latest, security


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
    text = data.decode('utf-8', 'replace')
    status, _, payload = text.partition(' ')
    if status != 'ok':
        raise OSError('wazuh-db: %s' % text[:200])
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
    agents = wdb_query(wdb, 'global sql SELECT id, name, ip, node_name, connection_status, os_platform FROM agent')
    out = {}
    for a in agents:
        aid = int(a.get('id', -1))
        if aid < 0 or a.get('connection_status') == 'never_connected':
            continue
        # agent 000 is this node itself; any other agent belongs to the node it reports to
        if aid != 0 and node and a.get('node_name') != node:
            continue
        try:
            rows = wdb_query(wdb, "agent %03d sql SELECT name, version, format FROM sys_programs "
                                  "WHERE name LIKE '%%php%%' OR name LIKE '%%PHP%%'" % aid)
        except OSError as exc:
            log('agent %03d: %s' % (aid, exc))
            continue
        pkgs = [r for r in rows if RUNTIME.match(r.get('name') or '') and vkey(r.get('version'))]
        if pkgs:
            out['%03d' % aid] = {'name': a.get('name') or '', 'ip': a.get('ip') or 'any',
                                 'status': a.get('connection_status') or '', 'packages': pkgs,
                                 'platform': (a.get('os_platform') or '').lower()}
    return out


def sapi(names):
    """web: a package serves requests (FPM, CGI, mod_php...); cli: only the
    command line and shared files are installed. A bare runtime package (php on
    RHEL, Homebrew, FreeBSD's php83, a Windows build) brings the web SAPIs too."""
    if any(WEB_SAPI.search(n) for n in names):
        return 'web'
    if names and all(CLI_ONLY.match(n) for n in names):
        return 'cli'
    return 'web'


def findings(inv):
    """{key: finding} with one finding per agent, PHP branch and packaging kind."""
    found = {}
    for aid, agent in inv.items():
        groups = {}
        for p in agent['packages']:
            version = p['version'] or ''
            name = p['name']
            if name.lower().startswith('php ') and not vkey(version):
                version = name.split(' ', 1)[1]
            br = branch_of(version)
            if not br:
                continue
            kind = classify(version, p.get('format'))
            g = groups.setdefault((br, kind), {'versions': {}, 'packages': set(), 'packager': set()})
            up = '%d.%d.%d' % vkey(version)
            g['versions'][up] = version
            g['packages'].add(name)
            g['packager'].add(packager(version, p.get('format')))
        for (br, kind), g in groups.items():
            installed = max(g['versions'], key=vkey)
            found['%s|%s|%s' % (aid, br, kind)] = {
                'agent_id': aid, 'agent_name': agent['name'], 'agent_ip': agent['ip'],
                'agent_status': agent['status'], 'branch': br, 'kind': kind, 'installed': installed,
                'package_version': g['versions'][installed],
                'packages': ','.join(sorted(g['packages']))[:300],
                'packager': ','.join(sorted(g['packager'])),
                # PHP on a macOS workstation (Homebrew, MAMP) is a developer's tool,
                # not a server other machines reach
                'sapi': 'desktop' if agent.get('platform') == 'darwin' else sapi(g['packages']),
                'oldest': min(g['versions'], key=vkey) if len(g['versions']) > 1 else ''}
    return found


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
    body = json.dumps({'jt_php': event}, sort_keys=True, separators=(',', ':'))
    msg = '1:%s:%s' % (LOCATION, body)
    if dry:
        print(msg)
        return
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.connect(queue)
        s.send(msg.encode('utf-8'))
    finally:
        s.close()


def evaluate(found, releases, previous, now):
    """Events to send, and the new per-finding state."""
    events, state = [], {}
    for key, f in sorted(found.items()):
        before = previous.get(key) or {}
        if f['kind'] == 'upstream':
            status, latest, security = assess(f['installed'], f['branch'], releases)
        else:
            latest = releases['active'].get(f['branch'])
            if not latest:
                hist = releases['branches'].get(f['branch']) or {}
                latest = max(hist, key=vkey) if hist else None
            status, security = ('distro' if f['branch'] in releases['active'] else 'distro_eol'), []
        # a distribution package does not change when php.net releases
        fingerprint = '%s|%s|%s' % (status, f['installed'], latest if f['kind'] == 'upstream' else '')
        bad = status in ('behind_security', 'eol')
        if not before:
            change = 'new'
        elif before.get('fingerprint') != fingerprint:
            change = 'changed'
        elif bad and now - before.get('alerted', 0) >= REMIND_DAYS * 86400:
            change = 'reminder'
        else:
            change = None
        rec = {'fingerprint': fingerprint, 'status': status, 'alerted': before.get('alerted', 0),
               'agent_name': f['agent_name'], 'agent_ip': f['agent_ip'],
               'since': before.get('since') if before.get('status') == status else now}
        if change:
            ev = dict(f, event='version', change=change, status=status, latest=latest or '',
                      security_releases=len(security), missing=','.join(security[-8:]),
                      since=time.strftime('%Y-%m-%d', time.localtime(rec['since'] or now)))
            if change != 'new' and before.get('status') and before.get('status') != status:
                ev['previous_status'] = before['status']
            if change == 'changed' and before.get('status') in ('behind_security', 'eol', 'behind') \
                    and status in ('current', 'distro'):
                ev['change'] = 'fixed'
            events.append((ev, f))
            rec['alerted'] = now
        state[key] = rec
    for key, before in sorted(previous.items()):
        if key not in found and before.get('status') in ('behind_security', 'eol', 'behind', 'distro_eol'):
            aid, br, kind = key.split('|')
            events.append(({'event': 'version', 'change': 'fixed', 'status': 'removed', 'branch': br,
                            'kind': kind, 'agent_id': aid, 'agent_name': before.get('agent_name') or '',
                            'agent_ip': before.get('agent_ip') or '',
                            'previous_status': before.get('status'),
                            'installed': before.get('fingerprint', '').split('|')[1]}, None))
    return events, state


def release_events(old, new):
    """One event per branch whose latest release changed since the last run."""
    out = []
    if not old:
        return out
    hist = new.get('branches', {})
    for br, latest in sorted(new.get('active', {}).items()):
        was = old.get('active', {}).get(br)
        if was and vkey(latest) > vkey(was):
            tags = hist.get(br, {}).get(latest, [])
            out.append({'event': 'release', 'branch': br, 'latest': latest, 'previous': was,
                        'security': 'yes' if 'security' in tags else 'no'})
    for br in sorted(set(old.get('active', {})) - set(new.get('active', {}))):
        out.append({'event': 'release', 'branch': br, 'latest': '', 'previous': old['active'][br],
                    'security': 'no', 'eol': 'yes'})
    return out


def health(state, ok, error, now):
    """status events for php.net being unreachable, on change and every three days."""
    h = state.get('health') or {}
    if ok:
        if h.get('failing_since'):
            hours = int((now - h['failing_since']) / 3600)
            state['health'] = {}
            return [{'event': 'status', 'state': 'recovered', 'hours': hours, 'detail': 'php.net release data read again'}]
        return []
    since = h.get('failing_since') or now
    hours = int((now - since) / 3600)
    stale = hours >= STALE_HOURS
    out = []
    if not h.get('failing_since'):
        out.append({'event': 'status', 'state': 'failing', 'hours': 0, 'detail': error[:300]})
        h['reported'] = now
    elif stale and (not h.get('stale_reported') or now - h['stale_reported'] >= STALE_REMIND_HOURS * 3600):
        out.append({'event': 'status', 'state': 'stale', 'hours': hours, 'detail': error[:300]})
        h['stale_reported'] = now
    h['failing_since'] = since
    h['last_error'] = error[:300]
    state['health'] = h
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--wazuh-path', default='/var/ossec')
    ap.add_argument('--source', default=PHPNET, help='php.net releases base URL (a mirror ending in /)')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--force-fetch', action='store_true')
    args = ap.parse_args(argv)
    wazuh = args.wazuh_path
    wdb = os.path.join(wazuh, 'queue', 'db', 'wdb')
    queue = os.path.join(wazuh, 'queue', 'sockets', 'queue')
    state_path = os.path.join(wazuh, 'var', 'jt-php.state')
    now = int(time.time())
    node = local_node(wazuh)

    try:
        inv = inventory(wdb, node)
    except (OSError, ValueError) as exc:
        log('cannot read the inventory: %s' % exc)
        if not args.dry_run and not args.list:
            try:
                send(queue, {'event': 'status', 'state': 'wdb_error', 'detail': str(exc)[:300]})
            except OSError:
                pass
        return 2
    if args.list:
        for aid, a in sorted(inv.items()):
            for p in a['packages']:
                print('%s %-24s %-28s %-50s %s' % (aid, a['name'], p['name'], p['version'], p.get('format') or ''))
        return 0

    state = load_state(state_path)
    old_rel = state.get('releases') or {}
    found = findings(inv)
    branches = {f['branch'] for f in found.values()}
    releases, error = old_rel, ''
    need = args.force_fetch or not old_rel or now - old_rel.get('fetched', 0) >= CACHE_HOURS * 3600 \
        or not branches <= set(old_rel.get('branches', {}))
    if need:
        try:
            releases = fetch_releases(args.source, branches)
        except Exception as exc:          # network, TLS, JSON: all mean "no fresh data"
            error = '%s: %s' % (type(exc).__name__, exc)
            log('php.net: %s' % error)
    events = [(e, None) for e in health(state, not error, error, now)] if need else []
    if not releases or now - releases.get('fetched', 0) > STALE_HOURS * 3600:
        # no release data, or too old to say a host is current: report health only
        if not args.dry_run:
            for ev, _ in events:
                send(queue, ev)
            save_state(state_path, state)
        else:
            for ev, _ in events:
                send(queue, ev, dry=True)
        return 1
    if releases is not old_rel:
        events += [(e, None) for e in release_events(old_rel, releases)]
    found_events, finding_state = evaluate(found, releases, state.get('findings') or {}, now)
    events += found_events
    state['findings'] = finding_state
    state['releases'] = releases
    state['version'] = VERSION
    for ev, agent in events:
        try:
            send(queue, ev, dry=args.dry_run)
        except OSError as exc:
            log('cannot write to the analysisd queue: %s' % exc)
            return 2
    if not args.dry_run:
        save_state(state_path, state)
    log('%d agents with PHP, %d findings, %d events' % (len(inv), len(found), len(events)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
