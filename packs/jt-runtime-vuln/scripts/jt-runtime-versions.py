#!/usr/bin/env python3
# jt-runtime-versions - compare the Node.js, Python and OpenVPN installed on
# every agent with the projects' own release data.
# Part of the jt-runtime-vuln rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
"""Report agents whose Node.js, Python or OpenVPN is behind a security release
of its branch, or on a branch its project no longer supports.

Wazuh's vulnerability detection matches CVEs from its own feed. On
2026-10-22 it had none of the ten CVEs Node.js fixed the day before, and
packages that carry the project's own version numbers (NodeSource, the
python.org and nodejs.org installers, Homebrew, deadsnakes) are the ones such
feeds match last. This script needs no CVE feed: it compares the package
inventory syscollector already keeps on this manager node with

  Node.js  https://nodejs.org/dist/index.json      every release, with a
           "security" flag
           https://raw.githubusercontent.com/nodejs/Release/main/schedule.json
           start and end of support per major line
  Python   https://peps.python.org/api/release-cycle.json   status per branch
           (bugfix, security, end-of-life)
           https://www.python.org/api/v2/downloads/release/  published releases
  OpenVPN  https://api.github.com/repos/OpenVPN/openvpn/releases   every
           release with its notes; a release whose notes name a CVE is a
           security release
           https://community.openvpn.net/openvpn/wiki/SupportedVersions
           support type per branch (full stable, old stable, unsupported)

OpenVPN 3 (openvpn3 on Linux, OpenVPN Connect) is a different product with
its own numbering and is not compared. On OPNsense and pfSense the openvpn
package comes with the firewall's firmware, so the fix arrives with a firmware
update; the alert says so. The OpenVPN data is optional: when it cannot be
read the previous copy is used and a "failing" status event says why, while
Node.js and Python are still checked.

and writes one JSON event per finding into analysisd's queue (location
jt-runtime) for the rules in zz-133200-jt_runtime_vuln_rules.xml. The events
are the manager's own and name the agent in their fields: analysisd drops
queue events that claim an agent's identity once agents are registered.

It only reads: the wazuh-db socket (SELECT statements) and the URLs above. Run
it on every node of a cluster; each node handles the agents connected to it.

    jt-runtime-versions.py --wazuh-path /var/ossec            normal run (cron)
    jt-runtime-versions.py --wazuh-path /var/ossec --dry-run  print, send and save nothing
    jt-runtime-versions.py --wazuh-path /var/ossec --list     what the inventory holds now
"""

import argparse
import datetime
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.request

VERSION = '1.1'
PROG = 'jt-runtime-versions'
LOCATION = 'jt-runtime'
REMIND_DAYS = 7
STALE_HOURS = 48
STALE_REMIND_HOURS = 72
CACHE_HOURS = 20
TIMEOUT = 30
SYSTEM_CA_BUNDLES = ('/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt',
                     '/etc/ssl/ca-bundle.pem', '/etc/ssl/cert.pem', '/usr/local/share/certs/ca-root-nss.crt')

SOURCES = {
    'node_index': 'https://nodejs.org/dist/index.json',
    'node_schedule': 'https://raw.githubusercontent.com/nodejs/Release/main/schedule.json',
    'python_cycle': 'https://peps.python.org/api/release-cycle.json',
    'python_releases': 'https://www.python.org/api/v2/downloads/release/?is_published=true',
    'openvpn_releases': 'https://api.github.com/repos/OpenVPN/openvpn/releases?per_page=100',
    'openvpn_support': 'https://community.openvpn.net/openvpn/wiki/SupportedVersions',
}
# Support types on OpenVPN's "Supported versions" page that still get releases
OPENVPN_SUPPORTED = ('full stable support', 'old stable support')
OPENVPN_TYPES = r'(Full stable support|Old stable support|git tree only|[Uu]nsupported|Under development)'
CVE = re.compile(r'CVE-\d{4}-\d{4,}')

UPSTREAM_VERSION = re.compile(r'^(?:\d+:)?(\d+)\.(\d+)\.(\d+)')
# Distribution builds keep a version and backport fixes into it
DISTRO = re.compile(r'[~+]dfsg|ubuntu\d|[~+]deb\d+u\d+|~deb\d|\.el\d|\.fc\d|\.amzn|\.mga\d|suse|\.sle|\+b\d+$')
# Builds that carry the project's own version numbers
UPSTREAM_MARK = re.compile(r'nodesource|deadsnakes|\+(?:focal|jammy|noble|bionic|bookworm|trixie)\d', re.I)

# Fixes that come without a CVE the vulnerability feeds can match: a package
# installed with pip (format pypi, so not a distribution package that reads
# the system's CA store) below these versions is reported.
MINIMUMS = {
    ('pypi', 'certifi'): ('2026.10.19', 'drops the "emSign ECC Root CA - G3" root, under which a compromised '
                                        'intermediate CA could issue certificates for any domain (October 2026)'),
    ('pypi', 'pip'): ('26.2.2', 'vendors certifi; 26.2.2 carries certifi 2026.10.19 (emSign CA compromise, October 2026)'),
    ('pypi', 'uv'): ('0.13.4', 'embedded CA roots without the compromised emSign ECC Root CA - G3 (October 2026)'),
    ('pypi', 'sigstore'): ('4.5.1', 'trust roots without the compromised emSign ECC Root CA - G3 (October 2026)'),
}

RUNTIMES = {
    'node': {
        'label': 'Node.js',
        # nodejs (deb, rpm), node (Homebrew, Alpine), node@22 (Homebrew), node22 (FreeBSD),
        # "Node.js" (Windows installer)
        'names': re.compile(r'^(?:nodejs|node|node@\d+|node\d{2}|nodejs\d{2}|Node\.js)$', re.I),
        'like': ("name LIKE 'node%'", "name LIKE 'Node.js%'"),
    },
    'python': {
        'label': 'Python',
        # python3.12 (deb, rpm), python3 (rpm: Fedora/RHEL ship the interpreter under it),
        # python@3.12 (Homebrew), python312 (FreeBSD), "Python 3.12.10 (64-bit)" (Windows)
        'names': re.compile(r'^(?:python3\.\d+|python3|python@3\.\d+|python3\d{1,2}|Python 3\.\d+\.\d+ \((?:64|32)-bit\))$'),
        'like': ("name LIKE 'python3%'", "name LIKE 'python@3%'", "name LIKE 'Python 3%'"),
    },
    'openvpn': {
        'label': 'OpenVPN',
        # openvpn (deb, rpm, FreeBSD/OPNsense/pfSense pkg, Homebrew), openvpn-mbedtls (FreeBSD
        # flavour), "OpenVPN 2.6.14-I001 amd64" (Windows installer). Not openvpn3 or
        # "OpenVPN Connect": OpenVPN 3 is another product with its own versions.
        'names': re.compile(r'^(?:openvpn|openvpn-mbedtls|OpenVPN \d+\.\d+\.\d+\S* \S+)$'),
        'like': ("name LIKE 'openvpn%'",),
    },
}


def log(msg):
    sys.stderr.write('%s %s: %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), PROG, msg))


def vkey(v):
    m = UPSTREAM_VERSION.match(v or '')
    return tuple(int(x) for x in m.groups()) if m else None


def pkey(v):
    """Any dotted version (2026.10.19, 26.2, 0.13.4) as a tuple, for MINIMUMS."""
    m = re.match(r'^(?:\d+:)?(\d+(?:\.\d+)*)', v or '')
    return tuple(int(x) for x in m.group(1).split('.')) if m else None


def branch_of(runtime, v):
    k = vkey(v)
    if not k:
        return None
    return str(k[0]) if runtime == 'node' else '%d.%d' % k[:2]


def classify(version, fmt=''):
    """upstream: the package carries the project's own versions (NodeSource,
    deadsnakes, Homebrew, FreeBSD ports, the Windows installers), so the
    project's release list is the yardstick. distro: a Debian, Ubuntu, RHEL or
    Fedora archive package, which keeps its version and takes backported fixes;
    "3.10.12-1~22.04.18" or "3.9.2-3" carry no obvious mark, so deb and rpm are
    distribution packages unless a third-party mark says otherwise."""
    if UPSTREAM_MARK.search(version):
        return 'upstream'
    if (fmt or '').lower() in ('deb', 'rpm') or DISTRO.search(version):
        return 'distro'
    return 'upstream'


def packager(version, fmt):
    v = version.lower()
    for mark, name in (('nodesource', 'nodesource'), ('deadsnakes', 'deadsnakes'), ('ubuntu', 'ubuntu'),
                       ('dfsg', 'debian'), ('~deb', 'debian'), ('.el', 'rhel'), ('.fc', 'fedora')):
        if mark in v:
            return name
    if re.search(r'\+(?:focal|jammy|noble|bionic)\d', v):
        return 'deadsnakes'
    return fmt or 'unknown'


# ---------------------------------------------------------------- release data

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


def node_releases(index, schedule, today):
    """{'active': {major: latest}, 'branches': {major: {version: [tags]}}}"""
    hist, latest = {}, {}
    for r in index:
        v = (r.get('version') or '').lstrip('v')
        k = vkey(v)
        if not k or k[0] == 0:
            continue
        major = str(k[0])
        hist.setdefault(major, {})[v] = ['security'] if r.get('security') else []
        if major not in latest or k > vkey(latest[major]):
            latest[major] = v
    active = {}
    for line, info in schedule.items():
        major = line.lstrip('v')
        if major in latest and info.get('start', '9999') <= today <= info.get('end', '0000'):
            active[major] = latest[major]
    if not active:
        raise ValueError('nodejs.org listed no supported line')
    return {'active': active, 'branches': hist}


def python_releases(cycle, releases):
    hist = {}
    for r in releases:
        m = re.match(r'^Python (\d+\.\d+\.\d+)$', (r.get('name') or '').strip())
        if not m:
            continue                       # pre-releases, install manager, docs
        v = m.group(1)
        hist.setdefault(branch_of('python', v), {})[v] = []
    active = {}
    for br, info in cycle.items():
        status = info.get('status')
        if status in ('bugfix', 'security') and br in hist:
            active[br] = max(hist[br], key=vkey)
            if status == 'security':
                # a branch that only takes security fixes releases for nothing else
                for v in hist[br]:
                    hist[br][v] = ['security']
    if not active:
        raise ValueError('python.org listed no supported branch')
    return {'active': active, 'branches': hist}


def openvpn_support(page):
    """{'2.7': 'full stable support', '2.6': 'old stable support', '2.5': 'unsupported', ...}
    from the "Supported versions" wiki page (HTML or text): one table row per
    branch, starting "X.Y.0 - "."""
    text = re.sub(r'<[^>]+>', ' ', page)
    text = re.sub(r'&nbsp;|&#160;', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    starts = [(m.start(), '%s.%s' % m.groups()) for m in re.finditer(r'\b(\d+)\.(\d+)\.0 - ', text)]
    out = {}
    for i, (pos, br) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else pos + 400
        m = re.search(OPENVPN_TYPES, text[pos:end])
        if m and br not in out:
            out[br] = m.group(1).lower()
    if not any(t in OPENVPN_SUPPORTED for t in out.values()):
        raise ValueError('the OpenVPN supported-versions page listed no supported branch')
    return out


def openvpn_releases(releases, support):
    """GitHub releases -> {'active': {branch: latest}, 'branches': {branch: {version: [tags]}},
    'cves': {version: [CVE ids]}}. Tags are compared by version, not by date."""
    hist, cves = {}, {}
    for r in releases:
        if r.get('draft') or r.get('prerelease'):
            continue
        m = re.match(r'^v?(\d+\.\d+\.\d+)$', (r.get('tag_name') or '').strip())
        if not m:
            continue                       # _rc, _beta, _alpha
        v = m.group(1)
        found = sorted(set(CVE.findall(r.get('body') or '')))
        hist.setdefault(branch_of('openvpn', v), {})[v] = ['security'] if found else []
        if found:
            cves[v] = found
    active = {}
    for br, kind in support.items():
        if kind in OPENVPN_SUPPORTED and br in hist:
            active[br] = max(hist[br], key=vkey)
    if not active:
        raise ValueError('no supported OpenVPN branch has a release on GitHub')
    return {'active': active, 'branches': hist, 'cves': cves, 'support': support}


def fetch_text(url):
    req = urllib.request.Request(url, headers={'User-Agent': '%s/%s (jt-wazuh-mgr)' % (PROG, VERSION)})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=verifying_context()) as r:
        return r.read().decode('utf-8', 'replace')


def fetch_releases(sources, today, old=None):
    """Node.js and Python must be read; OpenVPN falls back to the previous copy
    (or is left out on a first run) and reports why in 'partial_error'."""
    out = {
        'node': node_releases(fetch_json(sources['node_index']), fetch_json(sources['node_schedule']), today),
        'python': python_releases(fetch_json(sources['python_cycle']), fetch_json(sources['python_releases'])),
        'fetched': int(time.time()),
    }
    try:
        out['openvpn'] = openvpn_releases(fetch_json(sources['openvpn_releases']),
                                          openvpn_support(fetch_text(sources['openvpn_support'])))
    except Exception as exc:
        out['partial_error'] = 'OpenVPN: %s: %s' % (type(exc).__name__, exc)
        if (old or {}).get('openvpn'):
            out['openvpn'] = old['openvpn']
    return out


def assess(installed, br, rel):
    active, hist = rel['active'], rel['branches'].get(br) or {}
    known = sorted(hist, key=vkey)
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


def host_kind(agent):
    """desktop: a macOS or Windows client, where these runtimes are a
    developer's or user's tool; server: everything else."""
    platform = (agent.get('os_platform') or '').lower()
    name = agent.get('os_name') or ''
    if platform == 'darwin' or (platform == 'windows' and 'server' not in name.lower()):
        return 'desktop'
    return 'server'


def inventory(wdb, node):
    agents = wdb_query(wdb, 'global sql SELECT id, name, ip, node_name, connection_status, '
                            'os_platform, os_name FROM agent')
    like = ' OR '.join([c for r in RUNTIMES.values() for c in r['like']] +
                       ["(format = '%s' AND name = '%s')" % k for k in MINIMUMS])
    out = {}
    for a in agents:
        aid = int(a.get('id', -1))
        if aid < 0 or a.get('connection_status') == 'never_connected':
            continue
        if aid != 0 and node and a.get('node_name') != node:
            continue
        try:
            rows = wdb_query(wdb, 'agent %03d sql SELECT name, version, format, location FROM sys_programs WHERE %s'
                             % (aid, like))
        except OSError as exc:
            log('agent %03d: %s' % (aid, exc))
            continue
        pkgs = []
        for r in rows:
            if ((r.get('format') or ''), (r.get('name') or '').lower()) in MINIMUMS:
                pkgs.append(dict(r, runtime='package'))
                continue
            for rt, spec in RUNTIMES.items():
                if spec['names'].match(r.get('name') or ''):
                    pkgs.append(dict(r, runtime=rt))
        if pkgs:
            out['%03d' % aid] = {'name': a.get('name') or '', 'ip': a.get('ip') or '',
                                 'status': a.get('connection_status') or '', 'kind': host_kind(a),
                                 'platform': (a.get('os_platform') or '').lower(), 'packages': pkgs}
    return out


def package_version(p):
    """The upstream version a package carries; Windows installers put it in the name."""
    name, version = p.get('name') or '', p.get('version') or ''
    m = re.match(r'^(?:Python|OpenVPN) (\d+\.\d+\.\d+)[ -]', name)
    if m:
        return m.group(1)
    if p.get('format') == 'rpm' and name == 'python3' and not vkey(version):
        return ''
    return version


def firmware_note(runtime, agent):
    """Where the fix comes from, when that is not the package itself."""
    if runtime == 'openvpn' and agent.get('platform') in ('bsd', 'freebsd'):
        return 'on OPNsense or pfSense the fix comes with the firewall firmware update'
    return ''


def findings(inv):
    found = {}
    for aid, agent in inv.items():
        groups = {}
        for p in agent['packages']:
            if p['runtime'] == 'package':
                name, version = (p.get('name') or '').lower(), p.get('version') or ''
                minimum, reason = MINIMUMS[(p.get('format'), name)]
                where = (p.get('location') or '').rsplit('/', 1)[0][:160]
                status = 'below_minimum' if pkey(version) and pkey(version) < pkey(minimum) else 'current'
                found['%s|package|%s|%s' % (aid, name, where)] = {
                    'agent_id': aid, 'agent_name': agent['name'], 'agent_ip': agent['ip'],
                    'agent_status': agent['status'], 'host': agent['kind'], 'runtime': 'package',
                    'label': '%s (%s)' % (name, p.get('format')), 'branch': name, 'kind': 'package',
                    'installed': version, 'package_version': version, 'packages': name, 'packager': p.get('format'),
                    'minimum': minimum, 'reason': reason, 'location': where, 'fixed_status': status}
                continue
            # Debian/Ubuntu "python3" is the metapackage of the default python3.X
            if p['runtime'] == 'python' and p.get('format') == 'deb' and p['name'] == 'python3':
                continue
            version = package_version(p)
            br = branch_of(p['runtime'], version)
            if not br:
                continue
            kind = classify(version, p.get('format'))
            g = groups.setdefault((p['runtime'], br, kind), {'versions': {}, 'packages': set(), 'packager': set()})
            up = '%d.%d.%d' % vkey(version)
            g['versions'][up] = version
            g['packages'].add(p['name'])
            g['packager'].add(packager(version, p.get('format')))
        for (rt, br, kind), g in groups.items():
            installed = max(g['versions'], key=vkey)
            found['%s|%s|%s|%s' % (aid, rt, br, kind)] = {
                'agent_id': aid, 'agent_name': agent['name'], 'agent_ip': agent['ip'],
                'agent_status': agent['status'], 'host': agent['kind'],
                'runtime': rt, 'label': RUNTIMES[rt]['label'], 'branch': br, 'kind': kind,
                'installed': installed, 'package_version': g['versions'][installed],
                'packages': ','.join(sorted(g['packages']))[:300],
                'packager': ','.join(sorted(g['packager'])),
                'note': firmware_note(rt, agent)}
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
    msg = '1:%s:%s' % (LOCATION, json.dumps({'jt_runtime': event}, sort_keys=True, separators=(',', ':')))
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
    events, state = [], {}
    for key, f in sorted(found.items()):
        before = previous.get(key) or {}
        rel = releases.get(f['runtime']) or {}
        if f['kind'] != 'package' and not rel:
            if before:
                state[key] = before        # no release data for this runtime yet: keep, say nothing
            continue
        if f['kind'] == 'package':
            status, latest, security = f['fixed_status'], f['minimum'], []
        elif f['kind'] == 'upstream':
            status, latest, security = assess(f['installed'], f['branch'], rel)
        else:
            latest = rel['active'].get(f['branch'])
            status, security = ('distro' if f['branch'] in rel['active'] else 'distro_eol'), []
        fingerprint = '%s|%s|%s' % (status, f['installed'], latest if f['kind'] == 'upstream' else '')
        bad = status in ('behind_security', 'eol', 'below_minimum')
        if not before:
            change = 'new'
        elif before.get('fingerprint') != fingerprint:
            change = 'changed'
        elif bad and now - before.get('alerted', 0) >= REMIND_DAYS * 86400:
            change = 'reminder'
        else:
            change = None
        rec = {'fingerprint': fingerprint, 'status': status, 'alerted': before.get('alerted', 0),
               'agent_name': f['agent_name'], 'agent_ip': f['agent_ip'], 'label': f['label'],
               'since': before.get('since') if before.get('status') == status else now}
        if change:
            ev = dict(f, event='version', change=change, status=status, latest=latest or '',
                      security_releases=len(security), missing=','.join(security[-8:]),
                      since=time.strftime('%Y-%m-%d', time.localtime(rec['since'] or now)))
            if change != 'new' and before.get('status') and before.get('status') != status:
                ev['previous_status'] = before['status']
            fixed = sorted({c for v in security for c in (rel.get('cves') or {}).get(v, [])})
            if fixed:
                ev['cve_count'] = len(fixed)
                ev['cves'] = ','.join(fixed[:12]) + (',...' if len(fixed) > 12 else '')
            if change == 'changed' and before.get('status') in ('behind_security', 'eol', 'behind', 'below_minimum') \
                    and status in ('current', 'distro'):
                ev['change'] = 'fixed'
            events.append(ev)
            rec['alerted'] = now
        state[key] = rec
    for key, before in sorted(previous.items()):
        if key not in found and before.get('status') in ('behind_security', 'eol', 'behind', 'distro_eol',
                                                         'below_minimum'):
            aid, rt, br, kind = key.split('|', 3)
            events.append({'event': 'version', 'change': 'fixed', 'status': 'removed', 'runtime': rt,
                           'label': before.get('label') or (RUNTIMES[rt]['label'] if rt in RUNTIMES else br),
                           'branch': br, 'kind': kind if rt in RUNTIMES else 'package',
                           'agent_id': aid, 'agent_name': before.get('agent_name') or '',
                           'agent_ip': before.get('agent_ip') or '', 'previous_status': before.get('status'),
                           'installed': before.get('fingerprint', '').split('|')[1]})
    return events, state


def release_events(old, new):
    out = []
    for rt in RUNTIMES:
        o, n = (old or {}).get(rt) or {}, new.get(rt) or {}
        if not o:
            continue
        for br, latest in sorted(n.get('active', {}).items()):
            was = o.get('active', {}).get(br)
            if was and vkey(latest) > vkey(was):
                tags = n.get('branches', {}).get(br, {}).get(latest, [])
                out.append({'event': 'release', 'runtime': rt, 'label': RUNTIMES[rt]['label'], 'branch': br,
                            'latest': latest, 'previous': was, 'security': 'yes' if 'security' in tags else 'no'})
        for br in sorted(set(o.get('active', {})) - set(n.get('active', {}))):
            out.append({'event': 'release', 'runtime': rt, 'label': RUNTIMES[rt]['label'], 'branch': br,
                        'latest': '', 'previous': o['active'][br], 'security': 'no', 'eol': 'yes'})
    return out


def health(state, ok, error, now):
    h = state.get('health') or {}
    if ok:
        if h.get('failing_since'):
            hours = int((now - h['failing_since']) / 3600)
            state['health'] = {}
            return [{'event': 'status', 'state': 'recovered', 'hours': hours,
                     'detail': 'release data read again'}]
        return []
    since = h.get('failing_since') or now
    hours = int((now - since) / 3600)
    out = []
    if not h.get('failing_since'):
        out.append({'event': 'status', 'state': 'failing', 'hours': 0, 'detail': error[:300]})
    elif hours >= STALE_HOURS and (not h.get('stale_reported') or now - h['stale_reported'] >= STALE_REMIND_HOURS * 3600):
        out.append({'event': 'status', 'state': 'stale', 'hours': hours, 'detail': error[:300]})
        h['stale_reported'] = now
    h['failing_since'] = since
    h['last_error'] = error[:300]
    state['health'] = h
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--wazuh-path', default='/var/ossec')
    for key, url in SOURCES.items():
        ap.add_argument('--' + key.replace('_', '-'), default=url, help='mirror of %s' % url)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--force-fetch', action='store_true')
    args = ap.parse_args(argv)
    wazuh = args.wazuh_path
    wdb = os.path.join(wazuh, 'queue', 'db', 'wdb')
    queue = os.path.join(wazuh, 'queue', 'sockets', 'queue')
    state_path = os.path.join(wazuh, 'var', 'jt-runtime.state')
    now = int(time.time())
    today = datetime.date.today().isoformat()

    try:
        inv = inventory(wdb, local_node(wazuh))
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
                print('%s %-24s %-7s %-8s %-28s %-40s %s' % (aid, a['name'], a['kind'], p['runtime'], p['name'],
                                                         p['version'], p.get('format') or ''))
        return 0

    state = load_state(state_path)
    old_rel = state.get('releases') or {}
    releases, error = old_rel, ''
    if args.force_fetch or not old_rel or now - old_rel.get('fetched', 0) >= CACHE_HOURS * 3600 \
            or any(rt not in old_rel for rt in RUNTIMES):
        try:
            releases = fetch_releases({k: getattr(args, k) for k in SOURCES}, today, old_rel)
            error = releases.pop('partial_error', '')
            if error:
                log('release data: %s (the previous OpenVPN data is used)' % error)
        except Exception as exc:
            error = '%s: %s' % (type(exc).__name__, exc)
            log('release data: %s' % error)
        events = health(state, not error, error, now)
    else:
        events = []
    if not releases or now - releases.get('fetched', 0) > STALE_HOURS * 3600:
        for ev in events:
            send(queue, ev, dry=args.dry_run)
        if not args.dry_run:
            save_state(state_path, state)
        return 1
    if releases is not old_rel:
        events += release_events(old_rel, releases)
    found_events, finding_state = evaluate(findings(inv), releases, state.get('findings') or {}, now)
    events += found_events
    state.update(findings=finding_state, releases=releases, version=VERSION)
    for ev in events:
        try:
            send(queue, ev, dry=args.dry_run)
        except OSError as exc:
            log('cannot write to the analysisd queue: %s' % exc)
            return 2
    if not args.dry_run:
        save_state(state_path, state)
    log('%d agents with Node.js, Python or OpenVPN, %d findings, %d events'
        % (len(inv), len(finding_state), len(events)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
