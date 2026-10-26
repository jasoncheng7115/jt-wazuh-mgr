"""jt-zimbra 3.5: the check that tells when the web-file baseline no longer
covers a Zimbra server's release, and the script that builds the baseline from
Zimbra's own packages. Offline: no wazuh-db, no Zimbra server."""

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True      # no __pycache__ inside the shipped pack

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACK = os.path.join(ROOT, 'packs', 'jt-zimbra')
SCRIPT = os.path.join(PACK, 'scripts', 'jt-zimbra-baseline-check.py')
GENERATOR = os.path.join(PACK, 'agent', 'jt-zimbra-baseline.sh')

spec = importlib.util.spec_from_file_location('jt_zimbra_baseline_check', SCRIPT)
zb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(zb)

DAY = 86400


class Releases(unittest.TestCase):

    def test_release_from_package_versions_seen_on_servers(self):
        cases = {
            '10.1.20.GA.10120.UBUNTU22.64': (10, 1, 20),          # zimbra-core / zimbra-store
            '10.1.21.1789476131-1.u20': (10, 1, 21),             # a patch's web package
            '10.1.20.1783079738-1.u22': (10, 1, 20),             # zimbra-common-core-jar
            '9.0.0.GA.4178.UBUNTU20.64': (9, 0, 0),
            '8.8.15.GA.3869.RHEL8_64': (8, 8, 15),
            '1:10.1.20.GA.10120.UBUNTU22.64': (10, 1, 20),       # epoch
            '9.4.57.v20241219-1zimbra8.7b1.22.04': (9, 4, 57),   # shape only; the package filter keeps it out
            '2.4.62-1zimbra8.7b5.22.04': None,                   # third-party, below 8
            '': None, 'GA': None,
        }
        for version, want in cases.items():
            with self.subTest(version=version):
                self.assertEqual(zb.release_of(version), want)

    def test_server_release_takes_the_highest_web_package_and_ignores_third_party_ones(self):
        pkgs = [{'name': 'zimbra-core', 'version': '10.1.20.GA.10120.UBUNTU20.64'},
                {'name': 'zimbra-mbox-webclient-war', 'version': '10.1.21.1789476131-1.u20'},
                {'name': 'zimbra-jetty-distribution', 'version': '9.4.57.v20241219-1zimbra8.7b1.20.04'},
                {'name': 'zimbra-openjdk', 'version': '17.0.12-1zimbra8.8b1.20.04'},
                {'name': 'zimbra-httpd', 'version': '2.4.62-1zimbra8.7b5.20.04'}]
        release, names = zb.server_release(pkgs)
        self.assertEqual(release, (10, 1, 21))
        self.assertEqual(names, ['zimbra-mbox-webclient-war 10.1.21.1789476131-1.u20'])
        self.assertEqual(zb.server_release([{'name': 'zimbra-openjdk', 'version': '17.0.12'}]), (None, []))

    def test_covered_releases_from_stamped_jar_names(self):
        lines = ['/opt/zimbra/jetty_base/webapps/zimbra/WEB-INF/lib/zm-taglib-10.1.20.1762506875.jar:legit',
                 '/opt/zimbra/jetty_base/webapps/service/WEB-INF/lib/zm-taglib-10.1.17.1762506875.jar:legit',
                 '/opt/zimbra/jetty_base/webapps/service/WEB-INF/lib/antlr4-runtime-4.7.1.jar:legit',
                 '/opt/zimbra/jetty_base/webapps/zimbra/public/login.jsp:legit', '']
        covered, entries, source = zb.covered_releases(lines)
        self.assertEqual(covered, {(10, 1, 20), (10, 1, 17)})
        self.assertEqual((entries, source), (4, 'jar names'))

    def test_marker_keys_win_over_jar_names(self):
        lines = ['jt-zimbra-release/10.1.21:legit',
                 '/opt/zimbra/jetty_base/webapps/zimbra/WEB-INF/lib/zm-taglib-10.1.20.1762506875.jar:legit']
        covered, entries, source = zb.covered_releases(lines)
        self.assertEqual((covered, entries, source), ({(10, 1, 21)}, 1, 'markers'))

    def test_the_shipped_list_names_its_releases(self):
        with open(os.path.join(PACK, 'lists', 'zimbra-webfiles'), encoding='utf-8') as fh:
            covered, entries, _ = zb.covered_releases(fh.read().splitlines())
        self.assertIn((10, 1, 20), covered)
        self.assertGreater(entries, 100)


class Evaluate(unittest.TestCase):
    NOW = 1800000000

    def inv(self, version, name='mail9'):
        return {'009': {'name': name, 'ip': '10.0.0.9', 'status': 'active',
                        'packages': [{'name': 'zimbra-store', 'version': version}]}}

    def run_eval(self, version, covered, previous, now=None):
        return zb.evaluate(self.inv(version), covered, 494, 'jar names', previous, now or self.NOW)

    def test_a_stale_server_is_reported_then_reminded_weekly(self):
        events, state = self.run_eval('10.1.21.1789476131-1.u20', {(10, 1, 20)}, {})
        self.assertEqual([(e['status'], e['change'], e['release'], e['covered']) for e in events],
                         [('stale', 'new', '10.1.21', '10.1.20')])
        self.assertEqual(events[0]['agent_name'], 'mail9')
        again, state2 = self.run_eval('10.1.21.1789476131-1.u20', {(10, 1, 20)}, state, self.NOW + DAY)
        self.assertEqual(again, [])
        later, _ = self.run_eval('10.1.21.1789476131-1.u20', {(10, 1, 20)}, state2, self.NOW + 7 * DAY)
        self.assertEqual([e['change'] for e in later], ['reminder'])

    def test_regenerating_the_list_reports_fixed_once(self):
        _, state = self.run_eval('10.1.21.1789476131-1.u20', {(10, 1, 20)}, {})
        events, state = self.run_eval('10.1.21.1789476131-1.u20', {(10, 1, 21)}, state, self.NOW + 3600)
        self.assertEqual([(e['status'], e['change']) for e in events], [('covered', 'fixed')])
        events, _ = self.run_eval('10.1.21.1789476131-1.u20', {(10, 1, 21)}, state, self.NOW + 9 * DAY)
        self.assertEqual(events, [])

    def test_an_upgrade_makes_a_covered_server_stale(self):
        _, state = self.run_eval('10.1.20.GA.10120.UBUNTU22.64', {(10, 1, 20)}, {})
        events, _ = self.run_eval('10.1.21.1789476131-1.u20', {(10, 1, 20)}, state, self.NOW + DAY)
        self.assertEqual([(e['status'], e['change'], e.get('previous_release')) for e in events],
                         [('stale', 'changed', '10.1.20')])

    def test_a_covered_server_is_reported_once_at_first_sight(self):
        events, state = self.run_eval('10.1.20.GA.10120.UBUNTU22.64', {(10, 1, 20)}, {})
        self.assertEqual([(e['status'], e['change']) for e in events], [('covered', 'new')])
        again, _ = self.run_eval('10.1.20.GA.10120.UBUNTU22.64', {(10, 1, 20)}, state, self.NOW + 30 * DAY)
        self.assertEqual(again, [])


class Events(unittest.TestCase):

    def test_events_are_the_managers_own(self):
        sent = []

        class FakeSocket:
            def __init__(self, *a):
                pass

            def connect(self, path):
                pass

            def send(self, data):
                sent.append(data.decode())

            def close(self):
                pass

        orig = zb.socket.socket
        zb.socket.socket = FakeSocket
        try:
            zb.send('/x', {'event': 'baseline', 'agent_name': 'mail9'})
        finally:
            zb.socket.socket = orig
        self.assertEqual(sent, ['1:jt-zimbra-baseline:{"jt_zimbra_baseline":{"agent_name":"mail9","event":"baseline"}}'])

    def test_an_unreadable_list_is_reported_and_not_every_run(self):
        with tempfile.TemporaryDirectory() as wazuh:
            os.makedirs(os.path.join(wazuh, 'var'))
            os.makedirs(os.path.join(wazuh, 'etc', 'lists'))
            sent = []
            orig_inv, orig_send = zb.inventory, zb.send
            zb.inventory = lambda wdb, node: {'009': {'name': 'mail9', 'ip': 'any', 'status': 'active',
                                                     'packages': [{'name': 'zimbra-core', 'version': '10.1.20.GA'}]}}
            zb.send = lambda queue, event, dry=False: sent.append(event)
            try:
                self.assertEqual(zb.main(['--wazuh-path', wazuh]), 1)
                self.assertEqual(zb.main(['--wazuh-path', wazuh]), 1)
                self.assertEqual([e.get('state') for e in sent], ['list_error'])
                self.assertEqual(sent[0]['servers'], 'mail9')
                with open(os.path.join(wazuh, 'etc', 'lists', 'zimbra-webfiles'), 'w') as fh:
                    fh.write('jt-zimbra-release/10.1.20:legit\n/opt/zimbra/lib/ext/x.jar:legit\n')
                self.assertEqual(zb.main(['--wazuh-path', wazuh]), 0)
                self.assertEqual([(e.get('event'), e.get('state') or e.get('status')) for e in sent[1:]],
                                 [('status', 'list_ok'), ('baseline', 'covered')])
            finally:
                zb.inventory, zb.send = orig_inv, orig_send


class Generator(unittest.TestCase):

    def test_generator_parses(self):
        import subprocess
        self.assertEqual(subprocess.run(['sh', '-n', GENERATOR]).returncode, 0)

    def test_generator_and_check_agree_on_the_release_packages(self):
        """The shell script writes the marker the Python check reads; both must
        pick the release from the same packages."""
        with open(GENERATOR, encoding='utf-8') as fh:
            sh = fh.read()
        awk_re = re.search(r"\$1 ~ /(\^zimbra-\([^/]+\)\$)/", sh).group(1)
        self.assertEqual(awk_re, zb.RELEASE_PACKAGES.pattern.replace('(?:', '('))
        self.assertIn('jt-zimbra-release/', sh)
        self.assertTrue(zb.MARKER.match('jt-zimbra-release/10.1.21'))

    def test_generator_keeps_the_list_format(self):
        with open(GENERATOR, encoding='utf-8') as fh:
            sh = fh.read()
        self.assertIn("s/$/:legit/", sh)
        self.assertNotIn('find /opt/zimbra/jetty_base/webapps -type f | ', sh)


class Rules(unittest.TestCase):

    def test_every_status_the_script_sends_has_a_rule(self):
        import xml.etree.ElementTree as ET
        path = os.path.join(PACK, 'rules', 'zz-133300-jt_zimbra_baseline_rules.xml')
        with open(path, encoding='utf-8') as fh:
            root = ET.fromstring('<r>' + fh.read() + '</r>')
        text = ' '.join(f.text for f in root.iter('field'))
        with open(SCRIPT, encoding='utf-8') as fh:
            src = fh.read()
        for state in re.findall(r"'state': '([a-z_]+)'", src):
            self.assertIn('^%s$' % state, text, state)
        for status in ('stale', 'covered'):
            self.assertIn('^%s$' % status, text)
        ids = [r.get('id') for r in root.iter('rule')]
        self.assertTrue(all(133300 <= int(i) <= 133399 for i in ids))
        mailed = {r.get('id') for r in root.iter('rule') if 'alert_by_email' in (r.findtext('options') or '')}
        self.assertEqual(mailed, {'133301', '133304'})


if __name__ == '__main__':
    unittest.main()
