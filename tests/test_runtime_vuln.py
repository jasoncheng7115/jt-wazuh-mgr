"""jt-runtime-vuln 1.0: the Node.js / Python version checker and the KEV list
updater, offline. wazuh-db, the queue and the network are replaced by fakes.

What is pinned down: which packages are the runtimes (and which are not),
upstream builds versus distribution packages (deb and rpm are distribution
packages unless a third-party mark says otherwise: "3.10.12-1~22.04.18"
carries no obvious mark), desktop versus server hosts, the release data
parsers (nodejs.org's security flag, python.org's security-only branches),
the finding states, and the KEV list build and its refusal of a short
catalogue.
"""

import importlib.util
import json
import os
import sys
import tempfile
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


rv = load('jt_runtime_versions', os.path.join(SCRIPTS, 'jt-runtime-versions.py'))
kev = load('jt_kev_update', os.path.join(SCRIPTS, 'jt-kev-update.py'))

DAY = 86400
T0 = 1792728000

NODE_INDEX = [
    {'version': 'v26.12.1', 'security': True}, {'version': 'v26.12.0', 'security': False},
    {'version': 'v24.22.1', 'security': True}, {'version': 'v24.22.0', 'security': False},
    {'version': 'v22.23.4', 'security': True}, {'version': 'v22.23.3', 'security': False},
    {'version': 'v22.22.0', 'security': True}, {'version': 'v20.20.2', 'security': True},
    {'version': 'v0.12.18', 'security': True},
]
NODE_SCHEDULE = {'v20': {'start': '2023-04-18', 'end': '2026-04-30'},
                 'v22': {'start': '2024-04-24', 'end': '2027-04-30'},
                 'v24': {'start': '2025-05-06', 'end': '2028-04-30'},
                 'v26': {'start': '2026-04-22', 'end': '2029-04-30'}}
PY_CYCLE = {'3.15': {'status': 'bugfix'}, '3.14': {'status': 'bugfix'}, '3.13': {'status': 'security'},
            '3.12': {'status': 'security'}, '3.10': {'status': 'end-of-life'}, '3.16': {'status': 'feature'}}
PY_RELEASES = [{'name': 'Python 3.15.1'}, {'name': 'Python 3.15.0'}, {'name': 'Python 3.14.9'},
               {'name': 'Python 3.14.8'}, {'name': 'Python 3.13.17'}, {'name': 'Python 3.13.16'},
               {'name': 'Python 3.12.15'}, {'name': 'Python 3.12.13'}, {'name': 'Python 3.10.22'},
               {'name': 'Python 3.16.0a1'}, {'name': 'Python install manager 26.4'}]


def releases():
    return {'node': rv.node_releases(NODE_INDEX, NODE_SCHEDULE, '2026-10-23'),
            'python': rv.python_releases(PY_CYCLE, PY_RELEASES), 'fetched': T0}


def pkg(name, version, fmt='deb', runtime='node'):
    return {'name': name, 'version': version, 'format': fmt, 'runtime': runtime}


def inv(*packages, kind='server'):
    return {'005': {'name': 'web1', 'ip': '10.0.0.5', 'status': 'active', 'kind': kind,
                    'packages': list(packages)}}


class Packages(unittest.TestCase):

    def test_runtime_names(self):
        node, py = rv.RUNTIMES['node']['names'], rv.RUNTIMES['python']['names']
        for n in ('nodejs', 'node', 'node@22', 'node22', 'Node.js'):
            self.assertTrue(node.match(n), n)
        for n in ('nodejs-doc', 'libnode109', 'node-gyp', 'node-acorn'):
            self.assertFalse(node.match(n), n)
        for n in ('python3.12', 'python3', 'python@3.12', 'python312', 'Python 3.12.10 (64-bit)'):
            self.assertTrue(py.match(n), n)
        for n in ('python3-pip', 'python3.12-venv', 'python3-certifi', 'libpython3.12', 'Python Launcher'):
            self.assertFalse(py.match(n), n)

    def test_upstream_or_distribution(self):
        cases = [('22.23.4-1nodesource1', 'deb', 'upstream'), ('3.11.15-1+jammy1', 'deb', 'upstream'),
                 ('18.19.1+dfsg-6ubuntu5', 'deb', 'distro'), ('3.10.12-1~22.04.18', 'deb', 'distro'),
                 ('3.9.2-3', 'deb', 'distro'), ('3.14.8-1.fc44', 'rpm', 'distro'),
                 ('3.11.13', 'pkg', 'upstream'), ('22.23.4', 'win', 'upstream'), ('20.4.0', 'pkg', 'upstream')]
        for version, fmt, want in cases:
            self.assertEqual(rv.classify(version, fmt), want, version)

    def test_desktop_or_server(self):
        self.assertEqual(rv.host_kind({'os_platform': 'darwin', 'os_name': 'macOS'}), 'desktop')
        self.assertEqual(rv.host_kind({'os_platform': 'windows', 'os_name': 'Microsoft Windows 11 Pro'}), 'desktop')
        self.assertEqual(rv.host_kind({'os_platform': 'windows', 'os_name': 'Microsoft Windows Server 2022'}), 'server')
        self.assertEqual(rv.host_kind({'os_platform': 'ubuntu', 'os_name': 'Ubuntu'}), 'server')

    def test_findings_skip_the_debian_metapackage_and_read_windows_names(self):
        found = rv.findings(inv(pkg('python3', '3.12.3-0ubuntu2.1', runtime='python'),
                                pkg('python3.12', '3.12.3-1ubuntu0.17', runtime='python'),
                                pkg('Python 3.13.16 (64-bit)', '3.13.16150.0', 'win', 'python')))
        self.assertEqual(sorted(found), ['005|python|3.12|distro', '005|python|3.13|upstream'])
        self.assertEqual(found['005|python|3.13|upstream']['installed'], '3.13.16')


class Minimums(unittest.TestCase):

    def test_pip_installed_ca_packages_below_the_minimum(self):
        found = rv.findings(inv(
            {'name': 'certifi', 'version': '2024.8.30', 'format': 'pypi', 'runtime': 'package',
             'location': '/usr/local/lib/python3.8/dist-packages/certifi-2024.8.30.dist-info/METADATA'},
            {'name': 'pip', 'version': '26.0', 'format': 'pypi', 'runtime': 'package', 'location': '/a/pip-26.0.dist-info/M'},
            {'name': 'pip', 'version': '26.2.2', 'format': 'pypi', 'runtime': 'package', 'location': '/b/pip-26.2.2.dist-info/M'}))
        status = {(f['branch'], f['installed']): f['fixed_status'] for f in found.values()}
        self.assertEqual(status, {('certifi', '2024.8.30'): 'below_minimum', ('pip', '26.0'): 'below_minimum',
                                  ('pip', '26.2.2'): 'current'})
        ev, _ = rv.evaluate(found, releases(), {}, T0)
        self.assertEqual(sorted(e['status'] for e in ev), ['below_minimum', 'below_minimum', 'current'])

    def test_versions_with_two_parts(self):
        self.assertLess(rv.pkey('26.0'), rv.pkey('26.2.2'))
        self.assertLess(rv.pkey('2026.7.22'), rv.pkey('2026.10.19'))


class ReleaseData(unittest.TestCase):

    def test_node(self):
        r = rv.node_releases(NODE_INDEX, NODE_SCHEDULE, '2026-10-23')
        self.assertEqual(r['active'], {'22': '22.23.4', '24': '24.22.1', '26': '26.12.1'})
        self.assertNotIn('0', r['branches'])
        self.assertEqual(rv.assess('22.22.0', '22', r), ('behind_security', '22.23.4', ['22.23.4']))
        self.assertEqual(rv.assess('22.23.3', '22', r)[0], 'behind_security')
        self.assertEqual(rv.assess('22.23.4', '22', r)[0], 'current')
        self.assertEqual(rv.assess('20.20.2', '20', r)[0], 'eol')

    def test_python(self):
        r = rv.python_releases(PY_CYCLE, PY_RELEASES)
        self.assertEqual(r['active'], {'3.15': '3.15.1', '3.14': '3.14.9', '3.13': '3.13.17', '3.12': '3.12.15'})
        # security-only branch: every newer release is a security release
        self.assertEqual(rv.assess('3.13.16', '3.13', r)[0], 'behind_security')
        self.assertEqual(rv.assess('3.12.13', '3.12', r)[0], 'behind_security')
        # bugfix branch: behind, not claimed as security
        self.assertEqual(rv.assess('3.14.8', '3.14', r)[0], 'behind')
        self.assertEqual(rv.assess('3.10.22', '3.10', r)[0], 'eol')


class States(unittest.TestCase):

    def run_once(self, packages, previous, now, kind='server'):
        events, state = rv.evaluate(rv.findings(inv(*packages, kind=kind)), releases(), previous, now)
        return events, state

    def test_new_then_quiet_then_weekly(self):
        p = [pkg('nodejs', '22.22.0-1nodesource1')]
        ev, st = self.run_once(p, {}, T0)
        self.assertEqual([(e['status'], e['change'], e['host']) for e in ev], [('behind_security', 'new', 'server')])
        self.assertEqual(self.run_once(p, st, T0 + DAY)[0], [])
        ev, st = self.run_once(p, st, T0 + 7 * DAY)
        self.assertEqual([e['change'] for e in ev], ['reminder'])

    def test_fixed_and_removed(self):
        _, st = self.run_once([pkg('nodejs', '22.22.0-1nodesource1'), pkg('nodejs', '20.20.2-1nodesource1')], {}, T0)
        ev, _ = self.run_once([pkg('nodejs', '22.23.4-1nodesource1')], st, T0 + DAY)
        self.assertEqual(sorted((e['branch'], e['change'], e['status']) for e in ev),
                         [('20', 'fixed', 'removed'), ('22', 'fixed', 'current')])

    def test_distribution_packages_are_reported_once(self):
        p = [pkg('nodejs', '18.19.1+dfsg-6ubuntu5')]
        ev, st = self.run_once(p, {}, T0)
        self.assertEqual([e['status'] for e in ev], ['distro_eol'])
        self.assertEqual(self.run_once(p, st, T0 + 30 * DAY)[0], [])

    def test_events_are_the_managers_own(self):
        sent = []

        class FakeSocket:
            def __init__(self, *a): pass
            def connect(self, path): pass
            def send(self, data): sent.append(data.decode())
            def close(self): pass
        with mock.patch.object(rv.socket, 'socket', FakeSocket):
            rv.send('/q', {'event': 'version', 'agent_name': 'web1'})
        self.assertEqual(sent, ['1:jt-runtime:{"jt_runtime":{"agent_name":"web1","event":"version"}}'])


class Kev(unittest.TestCase):

    CATALOGUE = {'catalogVersion': '2026.10.21', 'vulnerabilities': [
        {'cveID': 'CVE-2024-4577', 'vendorProject': 'PHP Group', 'product': 'PHP', 'dateAdded': '2024-06-12'},
        {'cveID': 'CVE-2019-11043', 'vendorProject': 'PHP', 'product': 'FastCGI: "FPM"', 'dateAdded': '2022-03-25'},
        {'cveID': 'not-a-cve', 'vendorProject': 'x', 'product': 'y', 'dateAdded': ''}]}

    def test_build(self):
        body, count = kev.build(self.CATALOGUE)
        self.assertEqual(count, 2)
        lines = body.splitlines()
        self.assertEqual(lines[0], 'CVE-2019-11043:PHP FastCGI FPM (added 2022-03-25)')
        self.assertTrue(all(l.count(':') == 1 for l in lines))      # a CDB line has one key separator

    def test_a_short_catalogue_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, 'etc', 'lists'))
            os.makedirs(os.path.join(d, 'var'))
            listfile = os.path.join(d, 'etc', 'lists', 'jt-kev')
            with open(listfile, 'w') as fh:
                fh.write('CVE-2000-0001:old\n')
            with open(os.path.join(d, 'var', 'jt-kev.state'), 'w') as fh:
                json.dump({'count': 1700}, fh)
            short = {'vulnerabilities': [{'cveID': 'CVE-2024-%04d' % i} for i in range(1000, 1300)]}
            with mock.patch.object(kev, 'fetch', return_value=(short, 'u', '')), \
                    mock.patch.object(kev, 'send') as sent, mock.patch.object(kev, 'reload_ruleset') as reload:
                rc = kev.main(['--wazuh-path', d, '--force'])
            self.assertEqual(rc, 1)
            self.assertFalse(reload.called)
            with open(listfile) as fh:
                self.assertEqual(fh.read(), 'CVE-2000-0001:old\n')
            self.assertEqual(sent.call_args[0][1]['state'], 'failing')

    def test_a_good_catalogue_is_written_and_reloaded(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, 'etc', 'lists'))
            os.makedirs(os.path.join(d, 'var'))
            full = {'catalogVersion': 'x', 'vulnerabilities': [{'cveID': 'CVE-2024-%04d' % i, 'vendorProject': 'v',
                                                                'product': 'p', 'dateAdded': '2024-01-01'}
                                                               for i in range(1000, 1200)]}
            with mock.patch.object(kev, 'fetch', return_value=(full, 'u', 'Tue')), \
                    mock.patch.object(kev, 'send'), mock.patch.object(kev, 'reload_ruleset', return_value=True) as reload:
                self.assertEqual(kev.main(['--wazuh-path', d]), 0)
                self.assertTrue(reload.called)
                reload.reset_mock()
                self.assertEqual(kev.main(['--wazuh-path', d]), 0)     # within 20 hours: no download
                self.assertFalse(reload.called)
            with open(os.path.join(d, 'etc', 'lists', 'jt-kev')) as fh:
                self.assertEqual(len(fh.read().splitlines()), 200)


if __name__ == '__main__':
    unittest.main()
