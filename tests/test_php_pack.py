"""jt-php 1.0.1: the version checker's logic, offline, and the rule patterns that
the sandbox cannot replay (Windows eventchannel events).

Whether a host alerts, alerts again next week, or is reported fixed is decided
by jt-php-versions.py, not by analysisd, so that is what these tests pin down:
which packages count as the PHP runtime, upstream versus distribution
packages, command-line-only installs, security versus bug-fix releases, the
new / changed / reminder / fixed / removed states, php.net outages, and the
cluster node filter. wazuh-db, the queue and php.net are replaced by fakes.
"""

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True      # no __pycache__ inside the shipped pack

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACK = os.path.join(ROOT, 'packs', 'jt-php')
SCRIPT = os.path.join(PACK, 'scripts', 'jt-php-versions.py')
RULES = os.path.join(PACK, 'rules', 'zz-133100-jt_php_rules.xml')

_spec = importlib.util.spec_from_file_location('jt_php_versions', SCRIPT)
jp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jp)

DAY = 86400
T0 = 1792641600      # 2026-10-22

RELEASES = {
    'active': {'8.2': '8.2.35', '8.3': '8.3.36', '8.4': '8.4.27', '8.5': '8.5.12'},
    'branches': {
        '8.2': {'8.2.35': ['security'], '8.2.34': ['security'], '8.2.29': ['security']},
        '8.4': {'8.4.27': ['security'], '8.4.26': ['security'], '8.4.25': [], '8.4.24': ['security']},
        '8.3': {'8.3.36': ['security'], '8.3.35': ['security']},
        '8.1': {'8.1.34': ['security'], '8.1.33': ['security']},
        '7.4': {'7.4.33': ['security']},
    },
    'fetched': T0,
}


def pkg(name, version, fmt='deb'):
    return {'name': name, 'version': version, 'format': fmt}


def inv(*packages, aid='005', name='web1'):
    return {aid: {'name': name, 'ip': '10.0.0.5', 'status': 'active', 'packages': list(packages)}}


class RuntimePackages(unittest.TestCase):

    def test_runtime_names(self):
        for name in ('php8.2', 'php8.2-fpm', 'php8.2-cli', 'php8.2-cgi', 'php8.2-common',
                     'libapache2-mod-php8.2', 'php', 'php-fpm', 'php83', 'php82-php-fpm',
                     'php@8.2', 'PHP 8.2.12', 'lsphp83'):
            self.assertTrue(jp.RUNTIME.match(name), name)

    def test_extensions_are_not_the_runtime(self):
        for name in ('php8.2-curl', 'php8.2-mysql', 'php83-pdo_mysql', 'php-pear', 'phpmyadmin',
                     'php-symfony-console', 'libphp-phpmailer'):
            self.assertFalse(jp.RUNTIME.match(name), name)

    def test_metapackage_versions_are_skipped(self):
        found = jp.findings(inv(pkg('php', '2:8.3+93ubuntu2'), pkg('php-common', '2:93ubuntu2')))
        self.assertEqual(found, {})

    def test_upstream_or_distribution(self):
        cases = {
            '8.2.29-1+ubuntu22.04.1+deb.sury.org+1': 'upstream',
            '1:8.0.29-1+0~20230609.54+debian10~1.gbp7b07ff': 'upstream',
            '8.3.20-1.el9.remi': 'upstream',
            '8.3.23': 'upstream',                  # FreeBSD pkg
            '8.2.29-r0': 'upstream',               # Alpine
            '8.1.2-1ubuntu2.22': 'distro',
            '8.2.29-1~deb12u1': 'distro',
            '7.4.33-1+deb11u5': 'distro',
            '8.0.30-1.el9_2': 'distro',
        }
        for version, kind in cases.items():
            self.assertEqual(jp.classify(version, 'deb'), kind, version)

    def test_sapi(self):
        self.assertEqual(jp.sapi({'php8.3-cli', 'php8.3-common'}), 'cli')
        self.assertEqual(jp.sapi({'php8.3-cli', 'php8.3-fpm'}), 'web')
        self.assertEqual(jp.sapi({'libapache2-mod-php8.1'}), 'web')
        self.assertEqual(jp.sapi({'php83'}), 'web')          # FreeBSD core package carries CGI and FPM
        self.assertEqual(jp.sapi({'php'}), 'web')

    def test_php_on_a_mac_is_a_desktop_install(self):
        mac = {'039': {'name': 'mac1', 'ip': '10.0.0.9', 'status': 'active', 'platform': 'darwin',
                       'packages': [pkg('php', '8.5.9', 'pkg')]}}
        self.assertEqual(jp.findings(mac)['039|8.5|upstream']['sapi'], 'desktop')
        linux = {'005': dict(mac['039'], platform='ubuntu')}
        self.assertEqual(jp.findings(linux)['005|8.5|upstream']['sapi'], 'web')

    def test_one_finding_per_branch_and_kind(self):
        found = jp.findings(inv(pkg('php8.1-fpm', '8.1.2-1ubuntu2.22'),
                                pkg('php8.1-fpm', '8.1.34-8+ubuntu22.04.1+deb.sury.org+1'),
                                pkg('php8.2-fpm', '8.2.29-1+ubuntu22.04.1+deb.sury.org+1'),
                                pkg('libapache2-mod-php8.2', '8.2.29-1+ubuntu22.04.1+deb.sury.org+1')))
        self.assertEqual(sorted(found), ['005|8.1|distro', '005|8.1|upstream', '005|8.2|upstream'])
        self.assertEqual(found['005|8.2|upstream']['packages'], 'libapache2-mod-php8.2,php8.2-fpm')
        self.assertEqual(found['005|8.2|upstream']['packager'], 'deb.sury.org')


class Assessment(unittest.TestCase):

    def test_behind_a_security_release(self):
        status, latest, sec = jp.assess('8.2.29', '8.2', RELEASES)
        self.assertEqual((status, latest, sec), ('behind_security', '8.2.35', ['8.2.34', '8.2.35']))

    def test_bug_fix_releases_are_not_counted_as_security(self):
        status, latest, sec = jp.assess('8.4.24', '8.4', RELEASES)
        self.assertEqual(sec, ['8.4.26', '8.4.27'])

    def test_behind_a_bug_fix_release_only(self):
        rel = json.loads(json.dumps(RELEASES))
        rel['branches']['8.4']['8.4.28'] = []
        rel['active']['8.4'] = '8.4.28'
        self.assertEqual(jp.assess('8.4.27', '8.4', rel)[0], 'behind')

    def test_current(self):
        self.assertEqual(jp.assess('8.3.36', '8.3', RELEASES)[0], 'current')

    def test_unsupported_branch(self):
        self.assertEqual(jp.assess('8.1.34', '8.1', RELEASES)[0], 'eol')
        self.assertEqual(jp.assess('7.4.33', '7.4', RELEASES)[0], 'eol')


class States(unittest.TestCase):

    def run_once(self, packages, previous, now, releases=RELEASES):
        found = jp.findings(inv(*packages))
        events, state = jp.evaluate(found, releases, previous, now)
        return [e for e, _ in events], state

    def test_first_run_reports_everything_once(self):
        events, state = self.run_once([pkg('php8.2-fpm', '8.2.29-1+ubuntu22.04.1+deb.sury.org+1'),
                                       pkg('php8.3-fpm', '8.3.36-1+ubuntu22.04.1+deb.sury.org+1')], {}, T0)
        self.assertEqual(sorted((e['branch'], e['status'], e['change']) for e in events),
                         [('8.2', 'behind_security', 'new'), ('8.3', 'current', 'new')])
        again, _ = self.run_once([pkg('php8.2-fpm', '8.2.29-1+ubuntu22.04.1+deb.sury.org+1'),
                                  pkg('php8.3-fpm', '8.3.36-1+ubuntu22.04.1+deb.sury.org+1')], state, T0 + 3600)
        self.assertEqual(again, [])

    def test_weekly_reminder_only_for_bad_states(self):
        p = [pkg('php8.2-fpm', '8.2.29-1+ubuntu22.04.1+deb.sury.org+1'),
             pkg('php8.3-fpm', '8.3.36-1+ubuntu22.04.1+deb.sury.org+1')]
        _, state = self.run_once(p, {}, T0)
        events, state = self.run_once(p, state, T0 + 6 * DAY)
        self.assertEqual(events, [])
        events, state = self.run_once(p, state, T0 + 7 * DAY)
        self.assertEqual([(e['branch'], e['change']) for e in events], [('8.2', 'reminder')])
        self.assertEqual(self.run_once(p, state, T0 + 8 * DAY)[0], [])

    def test_a_new_release_makes_a_current_host_behind(self):
        p = [pkg('php8.3-fpm', '8.3.36-1+ubuntu22.04.1+deb.sury.org+1')]
        _, state = self.run_once(p, {}, T0)
        rel = json.loads(json.dumps(RELEASES))
        rel['branches']['8.3']['8.3.37'] = ['security']
        rel['active']['8.3'] = '8.3.37'
        events, _ = self.run_once(p, state, T0 + DAY, rel)
        self.assertEqual([(e['status'], e['change'], e.get('previous_status')) for e in events],
                         [('behind_security', 'changed', 'current')])

    def test_update_and_removal_are_reported_fixed(self):
        _, state = self.run_once([pkg('php8.2-fpm', '8.2.29-1+ubuntu22.04.1+deb.sury.org+1'),
                                  pkg('php7.4-fpm', '1:7.4.33-21+ubuntu22.04.1+deb.sury.org+1')], {}, T0)
        events, _ = self.run_once([pkg('php8.2-fpm', '8.2.35-1+ubuntu22.04.1+deb.sury.org+1')], state, T0 + DAY)
        got = sorted((e['branch'], e['change'], e['status'], e.get('previous_status')) for e in events)
        self.assertEqual(got, [('7.4', 'fixed', 'removed', 'eol'), ('8.2', 'fixed', 'current', 'behind_security')])

    def test_distribution_packages_ignore_new_php_releases(self):
        p = [pkg('php8.2-fpm', '8.2.29-1~deb12u1')]
        events, state = self.run_once(p, {}, T0)
        self.assertEqual([(e['status'], e['change']) for e in events], [('distro', 'new')])
        rel = json.loads(json.dumps(RELEASES))
        rel['branches']['8.2']['8.2.36'] = ['security']
        rel['active']['8.2'] = '8.2.36'
        self.assertEqual(self.run_once(p, state, T0 + DAY, rel)[0], [])
        self.assertEqual(self.run_once(p, state, T0 + 30 * DAY, rel)[0], [])    # no reminders either

    def test_distribution_package_on_an_unsupported_branch(self):
        events, _ = self.run_once([pkg('php7.4-fpm', '7.4.33-1+deb11u5')], {}, T0)
        self.assertEqual(events[0]['status'], 'distro_eol')


class Releases(unittest.TestCase):

    def test_release_events(self):
        old = {'active': {'8.2': '8.2.34', '8.1': '8.1.34'}}
        new = {'active': {'8.2': '8.2.35'}, 'branches': {'8.2': {'8.2.35': ['security']}}}
        events = jp.release_events(old, new)
        self.assertEqual(events[0], {'event': 'release', 'branch': '8.2', 'latest': '8.2.35',
                                     'previous': '8.2.34', 'security': 'yes'})
        self.assertEqual(events[1]['branch'], '8.1')
        self.assertEqual(events[1].get('eol'), 'yes')
        self.assertEqual(jp.release_events({}, new), [])          # first run: no history to compare

    def test_php_net_outage(self):
        state = {}
        first = jp.health(state, False, 'URLError: timed out', T0)
        self.assertEqual([e['state'] for e in first], ['failing'])
        self.assertEqual(jp.health(state, False, 'URLError: timed out', T0 + 6 * 3600), [])
        stale = jp.health(state, False, 'URLError: timed out', T0 + 48 * 3600)
        self.assertEqual([(e['state'], e['hours']) for e in stale], [('stale', 48)])
        self.assertEqual(jp.health(state, False, 'x', T0 + 60 * 3600), [])
        self.assertEqual([e['state'] for e in jp.health(state, False, 'x', T0 + 120 * 3600)], ['stale'])
        back = jp.health(state, True, '', T0 + 121 * 3600)
        self.assertEqual([(e['state'], e['hours']) for e in back], [('recovered', 121)])
        self.assertEqual(jp.health(state, True, '', T0 + 122 * 3600), [])


class Plumbing(unittest.TestCase):

    def test_cluster_node_name(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, 'etc'))
            conf = os.path.join(d, 'etc', 'ossec.conf')
            with open(conf, 'w') as fh:
                fh.write('<ossec_config><cluster><name>wazuh</name><node_name>node-a</node_name>'
                         '<disabled>no</disabled></cluster></ossec_config>')
            self.assertEqual(jp.local_node(d), 'node-a')
            with open(conf, 'w') as fh:
                fh.write('<ossec_config><cluster><node_name>node-a</node_name>'
                         '<disabled>yes</disabled></cluster></ossec_config>')
            self.assertIsNone(jp.local_node(d))
            with open(conf, 'w') as fh:
                fh.write('<ossec_config><!-- <cluster><node_name>x</node_name></cluster> --></ossec_config>')
            self.assertIsNone(jp.local_node(d))

    def test_inventory_keeps_only_this_nodes_agents(self):
        queries = []

        def fake(path, query):
            queries.append(query)
            if query.startswith('global'):
                return [{'id': 0, 'name': 'mgr', 'node_name': 'node-a', 'connection_status': 'active'},
                        {'id': 5, 'name': 'web1', 'ip': '10.0.0.5', 'node_name': 'node-a', 'connection_status': 'active'},
                        {'id': 6, 'name': 'win1', 'ip': '10.0.0.6', 'node_name': 'node-b', 'connection_status': 'active'},
                        {'id': 7, 'name': 'new', 'node_name': 'node-a', 'connection_status': 'never_connected'}]
            return [pkg('php8.2-fpm', '8.2.29-1+ubuntu22.04.1+deb.sury.org+1'), pkg('php8.2-curl', '8.2.29')]
        orig = jp.wdb_query
        jp.wdb_query = fake
        try:
            got = jp.inventory('/nonexistent', 'node-a')
        finally:
            jp.wdb_query = orig
        self.assertEqual(sorted(got), ['000', '005'])
        self.assertEqual([p['name'] for p in got['005']['packages']], ['php8.2-fpm'])
        self.assertFalse(any('agent 006' in q or 'agent 007' in q for q in queries))
        self.assertTrue(all(q.startswith(('global sql SELECT', 'agent')) and ' sql SELECT ' in q for q in queries))

    def test_events_are_the_managers_own(self):
        """analysisd drops queue events written as "[id] (name) ip->location"
        once any agent is registered (4.14.9, measured), so every event is the
        manager's and names the agent in its fields."""
        sent = []

        class FakeSocket:
            def __init__(self, *a): pass
            def connect(self, path): pass
            def send(self, data): sent.append(data.decode())
            def close(self): pass
        orig = jp.socket.socket
        jp.socket.socket = FakeSocket
        try:
            jp.send('/q', {'event': 'version', 'agent_id': '005', 'agent_name': 'web1'})
        finally:
            jp.socket.socket = orig
        self.assertEqual(sent, ['1:jt-php:{"jt_php":{"agent_id":"005","agent_name":"web1","event":"version"}}'])


class DigestHost(unittest.TestCase):
    """The version events are the manager's alerts; jt-alert-digest 1.12 files
    them under the host the event names."""

    def test_digest_groups_by_the_reported_host(self):
        spec = importlib.util.spec_from_file_location(
            'jt_alert_digest_for_php', os.path.join(ROOT, 'packs', 'jt-alert-digest', 'scripts', 'jt-alert-digest.py'))
        dg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dg)
        groups = {}
        rule = {'id': '133102', 'level': 12, 'description': '[HIGH] jt-php: web1: PHP 8.2.29 is missing security release 8.2.35'}
        for name, aid in (('web1', '005'), ('web2', '006')):
            dg.add_alert(groups, {'agent': {'id': '000', 'name': 'manager'}, 'rule': rule, 'location': 'jt-php',
                                  'data': {'jt_php': {'agent_name': name, 'agent_id': aid, 'agent_ip': '10.0.0.5'}}},
                         rule, 12)
        other = {'id': '5715', 'level': 3, 'description': 'sshd: authentication success.'}
        dg.add_alert(groups, {'agent': {'id': '005', 'name': 'web1'}, 'rule': other,
                              'data': {'jt_php': {'agent_name': 'not-this'}}}, other, 3)
        self.assertEqual(sorted(groups), [('133102', 'web1'), ('133102', 'web2'), ('5715', 'web1')])
        self.assertEqual(groups[('133102', 'web2')]['agent_id'], '006')


class WindowsRules(unittest.TestCase):
    """wazuh-logtest cannot replay eventchannel events (4.14), so the two Sysmon
    rules are checked here against values shaped as the decoder writes them:
    two backslashes per separator."""

    @classmethod
    def setUpClass(cls):
        cls.rules = {r.get('id'): r for r in ET.parse(RULES).getroot().iter('rule')}

    def fields(self, rid):
        return {f.get('name'): re.compile(f.text) for f in self.rules[rid].findall('field')}

    def hits(self, rid, parent, image):
        f = self.fields(rid)
        return bool(f['win.eventdata.parentImage'].search(parent) and f['win.eventdata.image'].search(image))

    def test_php_cgi_starting_a_shell(self):
        self.assertTrue(self.hits('133160', 'C:\\\\xampp\\\\php\\\\php-cgi.exe', 'C:\\\\Windows\\\\System32\\\\cmd.exe'))
        self.assertTrue(self.hits('133160', 'C:\\\\Apache24\\\\bin\\\\httpd.exe', 'C:\\\\Windows\\\\System32\\\\whoami.exe'))
        self.assertTrue(self.hits('133160', 'C:\\\\php\\\\php-cgi.exe',
                                  'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe'))

    def test_near_misses(self):
        self.assertFalse(self.hits('133160', 'C:\\\\xampp\\\\php\\\\php-cgi.exe', 'C:\\\\Program Files\\\\Git\\\\cmd\\\\git.exe'))
        self.assertFalse(self.hits('133160', 'C:\\\\xampp\\\\php\\\\php.exe', 'C:\\\\Windows\\\\System32\\\\cmd.exe'))
        self.assertFalse(self.hits('133160', 'C:\\\\Windows\\\\explorer.exe', 'C:\\\\Windows\\\\System32\\\\cmd.exe'))
        self.assertTrue(self.hits('133161', 'C:\\\\tools\\\\php\\\\php.exe', 'C:\\\\Windows\\\\System32\\\\cmd.exe'))

    def test_hung_under_the_level_0_siblings_of_61603(self):
        for rid in ('133160', '133161'):
            self.assertEqual(self.rules[rid].find('if_sid').text, '61603,92025,92028,92042,92069')


if __name__ == '__main__':
    unittest.main()
