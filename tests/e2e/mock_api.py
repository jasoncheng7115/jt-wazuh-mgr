#!/usr/bin/env python3
"""Serve the real web UI against a mocked, stateful Wazuh API, for browser tests.

The point of an end-to-end test here is the front end: roughly twelve thousand
lines of JavaScript embedded in a Python string, which the unit tests can only
check for parse validity. Everything a person actually does -- clicking a tab,
selecting agents, confirming a dialog, reading a table -- runs code no other
layer touches.

Three things this deliberately does not do:

  - It never talks to a Wazuh manager. Every API response is invented here.
  - It never reads the real ruleset. The rules endpoints have their paths
    hardcoded to /var/ossec, and the machine running these tests is usually a
    live manager, so open/listdir are intercepted for those two directories.
  - It never writes outside its temporary directory.

The state is real state: creating a group makes it appear in later responses,
so a journey can assert on what it just did rather than on a fixture.
"""

import base64
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for extra in ('/tmp/vendor',):
    if os.path.isdir(extra):
        sys.path.insert(0, extra)

# The node list is labelled with the host's own name; on a build host that is a
# real internal name. Replaced before the app can read it.
socket.gethostname = lambda: 'wazuh-manager'
socket.getfqdn = lambda *a: 'wazuh-manager'

import builtins  # noqa: E402
import lib.web_ui as web_ui  # noqa: E402

PORT = int(os.environ.get('E2E_PORT', '5178'))
WORKDIR = tempfile.mkdtemp(prefix='jt-e2e-')

# --------------------------------------------------------------------------
# Ruleset on disk, kept small enough to assert on exactly
# --------------------------------------------------------------------------

BUILTIN_RULES = {
    '0015-ossec_rules.xml': '''<group name="ossec,">
  <rule id="501" level="3">
    <if_sid>500</if_sid>
    <options>no_full_log</options>
    <description>Agent started.</description>
  </rule>
  <rule id="502" level="3">
    <if_sid>500</if_sid>
    <description>Manager started.</description>
  </rule>
</group>
''',
    '0095-sshd_rules.xml': '''<group name="syslog,sshd,">
  <rule id="5700" level="0" noalert="1">
    <decoded_as>sshd</decoded_as>
    <description>SSHD messages grouped.</description>
  </rule>
  <rule id="5760" level="5">
    <if_sid>5700</if_sid>
    <match>Failed password</match>
    <description>sshd: authentication failed.</description>
  </rule>
</group>
''',
}

CUSTOM_RULES = {
    'local_rules.xml': '''<group name="local,">
  <rule id="100010" level="10">
    <if_sid>5760</if_sid>
    <srcip>203.0.113.0/24</srcip>
    <description>Repeated authentication failure from the documentation range.</description>
  </rule>
</group>
''',
    'zz-906100-jt_portable_rules.xml': '''<group name="jt_portable,">
  <rule id="906100" level="6">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image">Downloads</field>
    <description>Portable executable started from Downloads.</description>
  </rule>
</group>
''',
}

DECODERS = {
    'sshd_decoders.xml': '''<decoder name="sshd">
  <program_name>^sshd</program_name>
</decoder>
<decoder name="sshd-failed">
  <parent>sshd</parent>
  <regex>^Failed password for (\\S+) from (\\S+) port</regex>
  <order>dstuser, srcip</order>
</decoder>
''',
}

CDB_LISTS = {
    'audit-keys': 'wazuh_fim:1\naudit_key:2\n',
    'jt-approved-portable': '# Approved portable executables, matched by path.\n',
}


def build_workdir():
    for sub in ('etc/rules', 'etc/lists', 'etc/decoders', 'etc/jt-packs', 'logs', 'var/upgrade'):
        os.makedirs(os.path.join(WORKDIR, sub), exist_ok=True)
    with io.open(os.path.join(WORKDIR, 'etc/ossec.conf'), 'w', encoding='utf-8') as fh:
        fh.write('<ossec_config>\n  <global>\n    <jsonout_output>yes</jsonout_output>\n'
                 '  </global>\n  <ruleset>\n'
                 '    <decoder_dir>ruleset/decoders</decoder_dir>\n'
                 '    <rule_dir>ruleset/rules</rule_dir>\n'
                 '    <list>etc/lists/audit-keys</list>\n'
                 '  </ruleset>\n</ossec_config>\n')
    for name, body in CDB_LISTS.items():
        with io.open(os.path.join(WORKDIR, 'etc/lists', name), 'w', encoding='utf-8') as fh:
            fh.write(body)
    for name, body in DECODERS.items():
        with io.open(os.path.join(WORKDIR, 'etc/decoders', name), 'w', encoding='utf-8') as fh:
            fh.write(body)
    with io.open(os.path.join(WORKDIR, 'logs/ossec.log'), 'w', encoding='utf-8') as fh:
        fh.write('2026/09/01 10:00:00 wazuh-analysisd: INFO: Started (pid: 1234).\n'
                 '2026/09/01 10:00:01 wazuh-remoted: INFO: Started (pid: 1235).\n'
                 '2026/09/01 10:05:00 wazuh-analysisd: WARNING: Rule 100010 loaded.\n')


BUILTIN_DIR = '/var/ossec/ruleset/rules/'
CUSTOM_DIR = '/var/ossec/etc/rules/'
DECODER_DIRS = ('/var/ossec/ruleset/decoders/', '/var/ossec/etc/decoders/')

_real_open, _real_listdir, _real_isdir, _real_isfile = (
    builtins.open, os.listdir, os.path.isdir, os.path.isfile)


def _redirect(path):
    """Map a hardcoded /var/ossec path onto the temporary tree."""
    p = str(path)
    if p.startswith('/var/ossec/'):
        return os.path.join(WORKDIR, p[len('/var/ossec/'):])
    return None


def fake_open(path, *a, **kw):
    p, base = str(path), os.path.basename(str(path))
    if p.startswith(BUILTIN_DIR) and base in BUILTIN_RULES:
        return io.StringIO(BUILTIN_RULES[base])
    if p.startswith(CUSTOM_DIR) and base in CUSTOM_RULES:
        return io.StringIO(CUSTOM_RULES[base])
    mapped = _redirect(p)
    if mapped and _real_isfile(mapped):
        return _real_open(mapped, *a, **kw)
    if mapped and ('w' in str(a[0] if a else kw.get('mode', 'r'))):
        os.makedirs(os.path.dirname(mapped), exist_ok=True)
        return _real_open(mapped, *a, **kw)
    return _real_open(path, *a, **kw)


def fake_listdir(path):
    p = str(path)
    if p == BUILTIN_DIR:
        return list(BUILTIN_RULES)
    if p == CUSTOM_DIR:
        return list(CUSTOM_RULES)
    mapped = _redirect(p)
    if mapped and _real_isdir(mapped):
        return _real_listdir(mapped)
    return _real_listdir(path)


def fake_isdir(path):
    p = str(path)
    if p in (BUILTIN_DIR, CUSTOM_DIR) or p in DECODER_DIRS:
        return True
    mapped = _redirect(p)
    if mapped:
        return _real_isdir(mapped)
    return _real_isdir(path)


def fake_isfile(path):
    p, base = str(path), os.path.basename(str(path))
    if p.startswith(BUILTIN_DIR) and base in BUILTIN_RULES:
        return True
    if p.startswith(CUSTOM_DIR) and base in CUSTOM_RULES:
        return True
    mapped = _redirect(p)
    if mapped:
        return _real_isfile(mapped)
    return _real_isfile(path)


builtins.open, os.listdir = fake_open, fake_listdir
os.path.isdir, os.path.isfile = fake_isdir, fake_isfile

# --------------------------------------------------------------------------
# Cluster state
# --------------------------------------------------------------------------

AGENTS = [
    ('000', 'wazuh-manager', '127.0.0.1',  'active',       'Ubuntu', '24.04', 'v4.14.7', [],                  'node-01'),
    ('001', 'web-01',        '10.0.10.11', 'active',       'Ubuntu', '24.04', 'v4.14.7', ['default', 'web'],  'node-01'),
    ('002', 'db-01',         '10.0.10.12', 'active',       'Debian', '12',    'v4.14.7', ['default', 'db'],   'node-01'),
    ('003', 'mail-01',       '10.0.10.13', 'active',       'Ubuntu', '22.04', 'v4.14.7', ['default', 'mail'], 'node-01'),
    ('004', 'dc-01',         '10.0.20.10', 'active',       'Microsoft Windows Server 2022', '10.0.20348', 'v4.14.7', ['default', 'windows'], 'node-02'),
    ('005', 'file-01',       '10.0.20.11', 'active',       'Microsoft Windows Server 2019', '10.0.17763', 'v4.14.7', ['default', 'windows'], 'node-02'),
    ('006', 'proxy-01',      '10.0.10.14', 'active',       'Alpine', '3.20',  'v4.14.6', ['default'],         'node-01'),
    ('007', 'build-01',      '10.0.10.15', 'disconnected', 'Rocky Linux', '9', 'v4.14.6', ['default'],        'node-01'),
    ('008', 'laptop-07',     '10.0.30.24', 'active',       'macOS', '15.3',   'v4.14.7', ['default'],         'node-02'),
    ('009', 'firewall-01',   '10.0.0.1',   'active',       'FreeBSD', '14.3', 'v4.14.7', ['default'],         'node-01'),
    ('010', 'kiosk-02',      '10.0.30.31', 'disconnected', 'Microsoft Windows 11', '10.0.22631', 'v4.13.0', ['default', 'windows'], 'node-02'),
    ('011', 'backup-01',     '10.0.10.16', 'active',       'Debian', '12',    'v4.14.7', ['default'],         'node-01'),
]

STATE = {
    'groups': {'default': 12, 'web': 1, 'db': 1, 'mail': 1, 'windows': 3},
    'users': [
        {'id': 1, 'username': 'wazuh', 'allow_run_as': False, 'roles': [1]},
        {'id': 2, 'username': 'wazuh-wui', 'allow_run_as': True, 'roles': [1, 2]},
        {'id': 100, 'username': 'soc-analyst', 'allow_run_as': False, 'roles': [3]},
    ],
    'next_user_id': 101,
    'restarted': [],
    'deleted': [],
    'upgraded': [],
    'peer_conf': {},
}

NODES = [
    {'name': 'node-01', 'type': 'master', 'version': '4.14.7', 'ip': '10.0.1.10'},
    {'name': 'node-02', 'type': 'worker', 'version': '4.14.7', 'ip': '10.0.1.11'},
]

ROLES = [
    {'id': 1, 'name': 'administrator'}, {'id': 2, 'name': 'readonly'},
    {'id': 3, 'name': 'agents_admin'},  {'id': 4, 'name': 'agents_readonly'},
]

PACKAGES = {
    '001': [('openssl', '3.0.13-0ubuntu3.4', 'amd64', 'Ubuntu Developers', 'deb'),
            ('nginx', '1.24.0-2ubuntu7', 'amd64', 'Ubuntu Developers', 'deb')],
    '002': [('openssl', '3.0.11-1~deb12u2', 'amd64', 'Debian OpenSSL Team', 'deb')],
    '004': [('OpenSSL', '3.0.15', 'x86_64', 'The OpenSSL Project', 'win')],
}


def agent_item(a):
    aid, name, ip, status, osname, osver, ver, groups, node = a
    platform = ('windows' if 'Windows' in osname else
                'darwin' if osname == 'macOS' else
                'freebsd' if osname == 'FreeBSD' else 'linux')
    return {
        'id': aid, 'name': name, 'ip': ip, 'status': status,
        'os': {'name': osname, 'platform': platform, 'version': osver,
               'arch': 'x86_64', 'uname': '%s %s' % (osname, osver)},
        'version': 'Wazuh ' + ver, 'group': groups, 'node_name': node,
        'group_config_status': 'synced', 'manager': 'node-01',
        'dateAdd': '2026-01-14T09:12:00Z', 'lastKeepAlive': '2026-08-31T10:58:11Z',
        'registerIP': ip, 'configSum': 'ab12cd34ef56', 'mergedSum': '78ab90cd12ef',
    }


def items(rows, failed=None):
    return {'data': {'affected_items': rows, 'total_affected_items': len(rows),
                     'failed_items': failed or [], 'total_failed_items': len(failed or [])},
            'error': 0}


def fake_authenticate(self):
    payload = base64.urlsafe_b64encode(json.dumps(
        {'iat': int(time.time()), 'exp': int(time.time()) + 900}).encode()).rstrip(b'=').decode()
    self.token = 'eyJhbGciOiJIUzI1NiJ9.%s.demo' % payload
    return True


def fake_request(self, method, endpoint, data=None, params=None):
    ep = endpoint.split('?')[0]
    p = params or {}

    if ep == '/agents' and method == 'GET':
        rows = [agent_item(a) for a in AGENTS if a[0] not in STATE['deleted']]
        wanted = p.get('agents_list') or (
            endpoint.split('agents_list=')[1].split('&')[0] if 'agents_list=' in endpoint else None)
        if wanted and wanted != '*':
            ids = str(wanted).split(',')
            rows = [r for r in rows if r['id'] in ids]
        if p.get('status'):
            rows = [r for r in rows if r['status'] == p['status']]
        if p.get('group'):
            rows = [r for r in rows if p['group'] in r['group']]
        return items(rows)

    if ep == '/agents' and method == 'DELETE':
        ids = str(p.get('agents_list', '')).split(',')
        STATE['deleted'].extend([i for i in ids if i])
        return items([{'id': i} for i in ids if i])

    if ep == '/agents/restart':
        ids = (data or {}).get('agents_list') or str(p.get('agents_list', '')).split(',')
        STATE['restarted'].extend(ids)
        return items([{'id': i} for i in ids if i])

    if ep in ('/agents/upgrade', '/agents/upgrade_custom'):
        ids = str(p.get('agents_list', '')).split(',')
        STATE['upgraded'].extend(ids)
        return items([{'agent': i, 'task_id': 100 + n} for n, i in enumerate(ids) if i])

    if ep == '/agents/upgrade_result':
        return items([{'agent': '001', 'status': 'Updated', 'message': 'Agent upgraded successfully'}])

    if ep == '/agents/summary/status':
        live = [a for a in AGENTS if a[0] not in STATE['deleted']]
        return {'data': {'connection': {
            'active': sum(1 for a in live if a[3] == 'active'),
            'disconnected': sum(1 for a in live if a[3] == 'disconnected'),
            'pending': 0, 'never_connected': 0, 'total': len(live)}}, 'error': 0}

    if ep == '/agents/summary/os':
        return items(['ubuntu', 'debian', 'windows', 'darwin', 'alpine'])

    if ep == '/groups' and method == 'GET':
        return items([{'name': n, 'count': c, 'mergedSum': 'aa11bb22', 'configSum': 'cc33dd44'}
                      for n, c in sorted(STATE['groups'].items())])
    if ep == '/groups' and method == 'POST':
        name = (data or {}).get('group_id') or p.get('group_id')
        if name:
            STATE['groups'].setdefault(name, 0)
        return items([{'message': 'Group created'}])
    if ep.startswith('/groups/') and method == 'DELETE':
        STATE['groups'].pop(ep.split('/')[2], None)
        return items([{'message': 'Group deleted'}])
    if ep.startswith('/groups/') and ep.endswith('/files'):
        return items([{'filename': 'agent.conf', 'hash': 'e3b0c44298fc'},
                      {'filename': 'merged.mg', 'hash': '9f86d081884c'}])
    if ep.startswith('/groups/') and ep.endswith('/agents'):
        gname = ep.split('/')[2]
        return items([agent_item(a) for a in AGENTS if gname in a[7]])

    if ep == '/cluster/nodes':
        return items(NODES)
    if ep == '/cluster/local/info':
        return items([{'node': 'node-01', 'cluster': 'wazuh-cluster', 'type': 'master'}])
    if ep == '/cluster/status':
        return {'data': {'enabled': 'yes', 'running': 'yes'}, 'error': 0}
    if ep == '/cluster/healthcheck':
        return items([{'name': n['name'], 'type': n['type'],
                       'status': {'last_keep_alive': '2026-08-31T10:59:00Z',
                                  'sync_integrity_free': 'ready'}} for n in NODES])
    if ep == '/cluster/ruleset/synchronization':
        return items([{'name': n['name'], 'synced': True} for n in NODES])
    if ep in ('/cluster/analysisd/reload', '/manager/analysisd/reload'):
        # The warning case is what makes this endpoint worth testing: analysisd
        # reports an unusable rule on an otherwise successful reload.
        if os.environ.get('E2E_RELOAD_WARNING'):
            msg = ("List 'etc/lists/jt-probe' could not be loaded. "
                   "Rule '906100' will be ignored.")
        else:
            msg = 'Ruleset reload request sent successfully.'
        return items([{'name': n['name'], 'msg': msg} for n in NODES])
    if ep.startswith('/cluster/') and ep.endswith('/status'):
        return items([{d: 'running' for d in (
            'wazuh-analysisd', 'wazuh-remoted', 'wazuh-db', 'wazuh-modulesd',
            'wazuh-monitord', 'wazuh-logcollector', 'wazuh-execd',
            'wazuh-syscheckd', 'wazuh-clusterd')}])
    if '/daemons/stats' in ep:
        return items([{'name': d, 'metrics': {'uptime': 864000, 'events_processed': 91234}}
                      for d in ('wazuh-analysisd', 'wazuh-remoted', 'wazuh-db')])
    if 'configuration/validation' in ep:
        return items([{'status': 'OK'}])

    if ep == '/manager/status':
        return items([{d: 'running' for d in (
            'wazuh-analysisd', 'wazuh-remoted', 'wazuh-db', 'wazuh-modulesd',
            'wazuh-monitord', 'wazuh-logcollector', 'wazuh-execd', 'wazuh-syscheckd')}])
    if ep == '/manager/info':
        return items([{'version': 'v4.14.7', 'type': 'manager', 'name': 'node-01'}])

    if ep == '/security/users' and method == 'GET':
        return items(STATE['users'])
    if ep == '/security/users' and method == 'POST':
        u = {'id': STATE['next_user_id'], 'allow_run_as': False, 'roles': [],
             'username': (data or {}).get('username', 'new-user')}
        STATE['next_user_id'] += 1
        STATE['users'].append(u)
        return items([u])
    if ep.startswith('/security/users/') and method == 'DELETE':
        uid = ep.rstrip('/').split('/')[-1]
        STATE['users'] = [u for u in STATE['users'] if str(u['id']) != str(uid)]
        return items([{'id': uid}])
    if ep == '/security/roles':
        return items(ROLES)

    if '/syscollector/' in ep:
        aid = ep.split('/')[2]
        if ep.endswith('/packages'):
            rows = PACKAGES.get(aid, [])
            search = p.get('search')
            if search:
                rows = [r for r in rows if search.lower() in r[0].lower()]
            return items([{'name': n, 'version': v, 'architecture': a, 'vendor': ven, 'format': f}
                          for n, v, a, ven, f in rows])
        if ep.endswith('/os'):
            for a in AGENTS:
                if a[0] == aid:
                    return items([{'os': {'name': a[4], 'version': a[5]},
                                   'architecture': 'x86_64', 'hostname': a[1]}])
        return items([])

    if ep.startswith('/agents/') and ep.endswith('/key'):
        return items([{'id': ep.split('/')[2], 'key': 'REDACTED-DEMO-KEY'}])

    if ep == '/logtest':
        return {'error': 0, 'data': {'token': 'e2e-token', 'output': {
            'rule': {'id': '5760', 'level': 5, 'description': 'sshd: authentication failed.',
                     'groups': ['syslog', 'sshd', 'authentication_failed']},
            'predecoder': {'program_name': 'sshd'},
            'decoder': {'name': 'sshd'},
            'data': {'srcip': '203.0.113.9', 'dstuser': 'root'}}, 'messages': []}}

    return items([])


def fake_request_raw(self, method, endpoint, body=None, params=None,
                     content_type='application/octet-stream'):
    if '/configuration' in endpoint:
        node = endpoint.split('/')[2]
        if method == 'GET':
            return True, STATE['peer_conf'].get(
                node, io.open(os.path.join(WORKDIR, 'etc/ossec.conf'), encoding='utf-8').read())
        STATE['peer_conf'][node] = body
        return True, 'ok'
    if '/files/' in endpoint:
        return True, '<agent_config>\n  <localfile>\n    <location>/var/log/syslog</location>\n' \
                     '    <log_format>syslog</log_format>\n  </localfile>\n</agent_config>\n'
    return True, ''


web_ui.WazuhAPISession.authenticate = fake_authenticate
web_ui.WazuhAPISession.request = fake_request
web_ui.WazuhAPISession.request_raw = fake_request_raw
web_ui.WazuhAPISession.get_nodes = lambda _self: NODES

_real_cfg = web_ui.get_config


class Cfg:
    def __init__(self, real):
        self._r = real

    def __getattr__(self, k):
        if k == 'wazuh_path':
            return WORKDIR
        return getattr(self._r, k)


web_ui.get_config = lambda: Cfg(_real_cfg())

if __name__ == '__main__':
    build_workdir()
    sys.stderr.write('E2E workdir: %s\n' % WORKDIR)
    # Start it the way production does. app.run() on its own skips
    # harden_wsgi_server, and the Server header then advertises werkzeug's
    # version -- so the tests would be measuring a different program from the
    # one that ships. Found by an E2E check that read the header.
    if hasattr(web_ui, 'harden_wsgi_server'):
        web_ui.harden_wsgi_server()
    app = web_ui.create_app()
    app.run(host='127.0.0.1', port=PORT, debug=False, threaded=True)
