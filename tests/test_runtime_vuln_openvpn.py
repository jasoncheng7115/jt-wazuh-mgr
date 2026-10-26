"""jt-runtime-vuln 1.1: the OpenVPN part of the version checker, offline.

What is pinned down: which packages are OpenVPN (and which are not: OpenVPN 3
is another product), the version forms FreeBSD, Debian, Ubuntu and the
Windows installer use, the two release sources (GitHub releases, where a
release whose notes name a CVE is a security release; the "Supported
versions" wiki page, where only full and old stable support still get
releases), the finding states, the firewall-firmware note, the CVE list in
the event, and that OpenVPN data that cannot be read never stops the Node.js
and Python checks.
"""

import importlib.util
import os
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, 'packs', 'jt-runtime-vuln', 'scripts')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rv = load('jt_runtime_versions_ovpn', os.path.join(SCRIPTS, 'jt-runtime-versions.py'))

DAY = 86400
T0 = 1792728000

GH = [
    {'tag_name': 'v2.7.8', 'body': 'Security: CVE-2026-84790, CVE-2026-88964'},
    {'tag_name': 'v2.6.23', 'body': 'fixes CVE-2026-84732 and CVE-2026-84471'},
    {'tag_name': 'v2.7.7', 'body': 'CVE-2026-84732 CVE-2026-81738'},
    {'tag_name': 'v2.7.6', 'body': 'CVE-2026-63649'},
    {'tag_name': 'v2.7.5', 'body': 'CVE-2026-12996'},
    {'tag_name': 'v2.7.4', 'body': 'DNS fixes only'},
    {'tag_name': 'v2.7_rc1', 'body': 'CVE-2099-1', 'prerelease': True},
    {'tag_name': 'v2.6.22', 'body': 'CVE-2026-63649'},
    {'tag_name': 'v2.6.14', 'body': 'CVE-2025-2704'},
    {'tag_name': 'v2.6.13', 'body': ''},
    {'tag_name': 'v2.5.11', 'body': 'CVE-2024-5594'},
    {'tag_name': 'v2.8.0', 'body': '', 'draft': True},
]
SUPPORT_PAGE = '''<table><tr><th>Version</th><th>First release</th></tr>
<tr><td>git master</td><td>N/A</td><td>Under development</td></tr>
<tr><td>2.7.0 - </td><td>Feb 11, 2026</td><td>-</td><td>Full stable support</td><td>-</td></tr>
<tr><td>2.6.0 - 2.6.22</td><td>Jan 25, 2023</td><td>Aug 5, 2026</td><td>Old stable support</td><td>August 2027</td><td>August 2028</td></tr>
<tr><td>2.5.0 - 2.5.11</td><td>Oct 27, 2020</td><td>July 18, 2024</td><td>unsupported</td><td>-</td><td>July 2025</td></tr>
<tr><td>2.4.0 - 2.4.12</td><td>Dec 26, 2016</td><td>Mar 17, 2022</td><td>unsupported</td></tr></table>'''


def ovpn_releases():
    return rv.openvpn_releases(GH, rv.openvpn_support(SUPPORT_PAGE))


def releases():
    return {'node': {'active': {'24': '24.22.1'}, 'branches': {'24': {'24.22.1': ['security']}}},
            'python': {'active': {'3.12': '3.12.15'}, 'branches': {'3.12': {'3.12.15': ['security']}}},
            'openvpn': ovpn_releases(), 'fetched': T0}


def agent(*packages, kind='server', platform='bsd', name='fw1'):
    return {'081': {'name': name, 'ip': '10.0.0.1', 'status': 'active', 'kind': kind,
                    'platform': platform, 'packages': list(packages)}}


def pkg(name, version, fmt='pkg'):
    return {'name': name, 'version': version, 'format': fmt, 'runtime': 'openvpn'}


class Names(unittest.TestCase):

    def test_which_packages_are_openvpn(self):
        names = rv.RUNTIMES['openvpn']['names']
        for n in ('openvpn', 'openvpn-mbedtls', 'OpenVPN 2.6.14-I001 amd64'):
            self.assertTrue(names.match(n), n)
        for n in ('openvpn3', 'OpenVPN Connect', 'openvpn-systemd-resolved', 'network-manager-openvpn',
                  'pfSense-pkg-openvpn-client-export', 'os-openvpn-legacy', 'easy-rsa'):
            self.assertFalse(names.match(n), n)

    def test_version_forms(self):
        self.assertEqual(rv.vkey('2.7.7_1'), (2, 7, 7))          # FreeBSD port revision
        self.assertEqual(rv.vkey('2.6.14,1'), (2, 6, 14))        # FreeBSD epoch
        self.assertEqual(rv.vkey('2.5.11-1ubuntu1'), (2, 5, 11))
        self.assertEqual(rv.branch_of('openvpn', '2.7.7_1'), '2.7')
        self.assertEqual(rv.package_version({'name': 'OpenVPN 2.6.14-I001 amd64', 'version': '2.6.1401'}),
                         '2.6.14')
        self.assertEqual(rv.classify('2.7.7_1', 'pkg'), 'upstream')
        self.assertEqual(rv.classify('2.6.14,1', 'pkg'), 'upstream')
        self.assertEqual(rv.classify('2.5.11-1ubuntu1', 'deb'), 'distro')
        self.assertEqual(rv.classify('2.6.14-1~bpo12+1', 'deb'), 'distro')


class ReleaseData(unittest.TestCase):

    def test_support_page(self):
        self.assertEqual(rv.openvpn_support(SUPPORT_PAGE),
                         {'2.7': 'full stable support', '2.6': 'old stable support',
                          '2.5': 'unsupported', '2.4': 'unsupported'})

    def test_support_page_without_a_supported_branch_is_refused(self):
        with self.assertRaises(ValueError):
            rv.openvpn_support('<p>Page "Supported Versions" not found.</p>')

    def test_releases(self):
        r = ovpn_releases()
        self.assertEqual(r['active'], {'2.7': '2.7.8', '2.6': '2.6.23'})
        self.assertNotIn('2.8', r['branches'])                   # draft
        self.assertEqual(r['branches']['2.7']['2.7.4'], [])      # notes name no CVE
        self.assertEqual(r['branches']['2.7']['2.7.8'], ['security'])
        self.assertEqual(r['cves']['2.7.8'], ['CVE-2026-84790', 'CVE-2026-88964'])

    def test_assess(self):
        r = ovpn_releases()
        self.assertEqual(rv.assess('2.7.7', '2.7', r)[:2], ('behind_security', '2.7.8'))
        self.assertEqual(rv.assess('2.7.5', '2.7', r)[2], ['2.7.6', '2.7.7', '2.7.8'])
        self.assertEqual(rv.assess('2.6.14', '2.6', r)[0], 'behind_security')
        self.assertEqual(rv.assess('2.7.8', '2.7', r)[0], 'current')
        self.assertEqual(rv.assess('2.5.11', '2.5', r)[0], 'eol')


class Findings(unittest.TestCase):

    def run_once(self, inv, previous, now, rel=None):
        return rv.evaluate(rv.findings(inv), rel or releases(), previous, now)

    def test_firewall_behind_security_names_the_cves_and_the_firmware(self):
        ev, st = self.run_once(agent(pkg('openvpn', '2.7.5')), {}, T0)
        self.assertEqual(len(ev), 1)
        e = ev[0]
        self.assertEqual((e['runtime'], e['status'], e['change'], e['host'], e['latest'], e['branch']),
                         ('openvpn', 'behind_security', 'new', 'server', '2.7.8', '2.7'))
        self.assertEqual(e['cve_count'], 5)
        self.assertIn('CVE-2026-84790', e['cves'])
        self.assertIn('firmware', e['note'])
        self.assertEqual(self.run_once(agent(pkg('openvpn', '2.7.5')), st, T0 + DAY)[0], [])
        self.assertEqual([x['change'] for x in self.run_once(agent(pkg('openvpn', '2.7.5')), st, T0 + 7 * DAY)[0]],
                         ['reminder'])

    def test_linux_server_has_no_firmware_note(self):
        ev, _ = self.run_once(agent(pkg('openvpn', '2.6.14-1', fmt='rpm'), platform='centos'), {}, T0)
        self.assertEqual((ev[0]['status'], ev[0]['note']), ('distro', ''))

    def test_upgrade_is_reported_fixed(self):
        _, st = self.run_once(agent(pkg('openvpn', '2.7.7_1')), {}, T0)
        ev, _ = self.run_once(agent(pkg('openvpn', '2.7.8')), st, T0 + DAY)
        self.assertEqual([(e['change'], e['status']) for e in ev], [('fixed', 'current')])

    def test_end_of_life_branch(self):
        ev, _ = self.run_once(agent(pkg('openvpn', '2.5.11,1')), {}, T0)
        self.assertEqual(ev[0]['status'], 'eol')

    def test_distribution_package_reported_once(self):
        a = agent(pkg('openvpn', '2.5.11-1ubuntu1', fmt='deb'), platform='ubuntu')
        ev, st = self.run_once(a, {}, T0)
        self.assertEqual([e['status'] for e in ev], ['distro_eol'])
        self.assertEqual(self.run_once(a, st, T0 + 30 * DAY)[0], [])

    def test_windows_client_is_a_desktop(self):
        a = agent({'name': 'OpenVPN 2.6.14-I001 amd64', 'version': '2.6.1401', 'format': 'win',
                   'runtime': 'openvpn'}, kind='desktop', platform='windows')
        ev, _ = self.run_once(a, {}, T0)
        self.assertEqual((ev[0]['host'], ev[0]['installed'], ev[0]['status']), ('desktop', '2.6.14', 'behind_security'))

    def test_no_openvpn_release_data_yet_means_no_openvpn_event(self):
        rel = releases()
        del rel['openvpn']
        ev, st = self.run_once(agent(pkg('openvpn', '2.7.5')), {}, T0, rel)
        self.assertEqual((ev, st), ([], {}))


class Fetch(unittest.TestCase):

    SOURCES = {k: k for k in rv.SOURCES}
    NODE = ([{'version': 'v24.22.1', 'security': True}], {'v24': {'start': '2025-05-06', 'end': '2028-04-30'}})
    PY = ({'3.12': {'status': 'security'}}, [{'name': 'Python 3.12.15'}])

    def fake_json(self, fail_openvpn):
        data = {'node_index': self.NODE[0], 'node_schedule': self.NODE[1],
                'python_cycle': self.PY[0], 'python_releases': self.PY[1], 'openvpn_releases': GH}

        def fetch(url):
            if url == 'openvpn_releases' and fail_openvpn:
                raise OSError('rate limited')
            return data[url]
        return fetch

    def test_openvpn_failure_keeps_the_previous_copy_and_node_python_still_run(self):
        old = {'openvpn': {'active': {'2.7': '2.7.7'}, 'branches': {}, 'cves': {}}}
        with mock.patch.object(rv, 'fetch_json', self.fake_json(True)), \
                mock.patch.object(rv, 'fetch_text', lambda url: SUPPORT_PAGE):
            out = rv.fetch_releases(self.SOURCES, '2026-10-26', old)
        self.assertIn('node', out)
        self.assertIn('python', out)
        self.assertEqual(out['openvpn'], old['openvpn'])
        self.assertIn('OpenVPN', out['partial_error'])

    def test_first_run_without_openvpn_data(self):
        with mock.patch.object(rv, 'fetch_json', self.fake_json(True)), \
                mock.patch.object(rv, 'fetch_text', lambda url: SUPPORT_PAGE):
            out = rv.fetch_releases(self.SOURCES, '2026-10-26', {})
        self.assertNotIn('openvpn', out)
        self.assertIn('partial_error', out)

    def test_success(self):
        with mock.patch.object(rv, 'fetch_json', self.fake_json(False)), \
                mock.patch.object(rv, 'fetch_text', lambda url: SUPPORT_PAGE):
            out = rv.fetch_releases(self.SOURCES, '2026-10-26', {})
        self.assertEqual(out['openvpn']['active'], {'2.7': '2.7.8', '2.6': '2.6.23'})
        self.assertNotIn('partial_error', out)


if __name__ == '__main__':
    unittest.main()
