"""jt-container-vuln 1.0: the host-side scanner's own logic, offline.

The rules can only alert on what the scanner writes, and whether an image
alerts again tomorrow is decided by the scanner's state, not by analysisd.
So that state machine is what these tests pin down: new, grown,
fix_available, reminder, rebuilt and same for images; new, same, reminder
and recovered for failures. Also: counting unique CVEs, KEV marking, the
kernel-header exclusion, the bounded output file, credential scrubbing, and
the docker/Trivy command lines (no Docker socket and no network for the
scanning container). Docker and the network are replaced by fakes; nothing
here runs a container or opens a connection. Everything is written inside
temporary directories.
"""

import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
import urllib.error

sys.dont_write_bytecode = True      # no __pycache__ inside the shipped pack

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'packs', 'jt-container-vuln', 'agent', 'jt-container-vuln.py')

_spec = importlib.util.spec_from_file_location('jt_container_vuln', SCRIPT)
cv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cv)

DAY = 86400.0
T0 = 1792300000.0      # 2026-10-17


def vuln(cve, pkg, sev, fixed='', installed='1.0', score=None, title='t'):
    v = {'VulnerabilityID': cve, 'PkgName': pkg, 'InstalledVersion': installed,
         'FixedVersion': fixed, 'Severity': sev, 'Title': title}
    if score is not None:
        v['CVSS'] = {'nvd': {'V3Score': score}}
    return v


def report(*vulns, os_family='debian', os_name='13.7', typ='debian'):
    return {'SchemaVersion': 2, 'Metadata': {'OS': {'Family': os_family, 'Name': os_name}},
            'Results': [{'Target': 'x', 'Class': 'os-pkgs', 'Type': typ, 'Vulnerabilities': list(vulns)}]}


KEV = {'CVE-2024-3094': {'dateAdded': '2024-04-01', 'knownRansomwareCampaignUse': 'Unknown'},
       'CVE-2023-4863': {'dateAdded': '2023-09-13', 'knownRansomwareCampaignUse': 'Known'}}


def kev_document(n=600, extra=()):
    items = [{'cveID': 'CVE-2020-%05d' % i, 'dateAdded': '2021-11-03',
              'knownRansomwareCampaignUse': 'Unknown'} for i in range(n)]
    items += [{'cveID': c, 'dateAdded': '2024-01-01', 'knownRansomwareCampaignUse': 'Known'} for c in extra]
    return json.dumps({'catalogVersion': '2026.10.16', 'count': len(items),
                       'vulnerabilities': items}).encode()


class Summarize(unittest.TestCase):

    def test_a_cve_in_two_packages_counts_once_at_its_highest_severity(self):
        r = report(vuln('CVE-2026-1', 'pcre2', 'HIGH', fixed='2'),
                   vuln('CVE-2026-1', 'pcre2-syntax', 'CRITICAL'),
                   vuln('CVE-2026-2', 'curl', 'HIGH'))
        s = cv.summarize(r, {})
        self.assertEqual(s['counts']['critical'], 1)
        self.assertEqual(s['counts']['high'], 1)
        self.assertEqual(s['fixable']['critical'], 1, 'fixable when any finding has a fix')
        self.assertEqual(s['critical_ids'], ['CVE-2026-1'])
        self.assertEqual(s['top'][0]['more_packages'], 1)

    def test_kev_matches_any_severity_and_comes_first(self):
        r = report(vuln('CVE-2026-9', 'libx', 'CRITICAL', fixed='2', score=9.8),
                   vuln('CVE-2023-4863', 'libwebp7', 'MEDIUM'),
                   vuln('CVE-2024-3094', 'xz-utils', 'LOW'))
        s = cv.summarize(r, KEV)
        self.assertEqual(s['kev_ids'], ['CVE-2023-4863', 'CVE-2024-3094'])
        self.assertEqual(s['kev_ransomware'], ['CVE-2023-4863'])
        self.assertEqual([t['id'] for t in s['top']][:2], ['CVE-2023-4863', 'CVE-2024-3094'])
        self.assertTrue(s['top'][0]['kev'])

    def test_kernel_headers_are_left_out(self):
        r = report(vuln('CVE-2026-43185', 'linux-libc-dev', 'CRITICAL'),
                   vuln('CVE-2026-43186', 'linux-headers-6.1.0-26-common', 'HIGH'),
                   vuln('CVE-2026-6653', 'libxml2', 'CRITICAL'))
        s = cv.summarize(r, {}, ignore=cv.DEFAULTS['IGNORE_PACKAGES'])
        self.assertEqual(s['critical_ids'], ['CVE-2026-6653'])
        self.assertEqual(s['counts']['high'], 0)
        self.assertEqual(s['ignored'], 2)
        self.assertEqual(cv.summarize(r, {})['counts']['critical'], 2, 'only when asked')

    def test_ids_that_are_not_advisory_ids_are_dropped_and_text_is_bounded(self):
        r = report(vuln('<script>', 'x', 'CRITICAL'),
                   vuln('CVE-2026-3', 'y\x1b[31m', 'HIGH', title='T' * 500))
        s = cv.summarize(r, {})
        self.assertEqual(s['total'], 1)
        self.assertNotIn('\x1b', s['top'][0]['pkg'])
        self.assertLessEqual(len(s['top'][0]['title']), 100)

    def test_the_line_stays_small_and_starts_with_msg(self):
        many = [vuln('CVE-2026-%d' % i, 'pkg%d' % i, 'CRITICAL', fixed='9', title='x' * 300)
                for i in range(2000)]
        s = cv.summarize(report(*many), {}, top_n=10)
        change, new = cv.image_change(cv.fresh_state(), 'sha256:' + 'a' * 64, ['img:1'],
                                      set(s['critical_ids']), set(s['fixable_critical_ids']),
                                      set(s['kev_ids']), T0, 7)
        rec = cv.image_line({'ref': 'img:1', 'id': 'sha256:' + 'a' * 64, 'containers': ['c%d' % i for i in range(50)]},
                            s, change, new, {})
        line = json.dumps({'container_vuln': rec}, separators=(',', ':'))
        self.assertLess(len(line), 8192, 'Wazuh events are cut at 64 KB; keep far below')
        self.assertTrue(line.startswith('{"container_vuln":{"msg":"img:1: 2000 critical'))
        self.assertEqual(len(rec['top']), 10)
        self.assertTrue(rec['new'].endswith(',+1990'))
        self.assertTrue(rec['containers'].endswith(',+40'))


class ImageChange(unittest.TestCase):
    """The rules alert on change in (new, grown, fix_available, reminder)."""

    ID1, ID2 = 'sha256:' + '1' * 64, 'sha256:' + '2' * 64

    def setUp(self):
        self.state = cv.fresh_state()

    def step(self, crit, fixable=(), kev=(), ts=T0, image=None, refs=('app:1',)):
        return cv.image_change(self.state, image or self.ID1, list(refs), set(crit), set(fixable),
                               set(kev), ts, 7)

    def test_first_scan_is_new_then_same_every_day(self):
        self.assertEqual(self.step(['CVE-2026-1']), ('new', ['CVE-2026-1']))
        for day in range(1, 7):
            self.assertEqual(self.step(['CVE-2026-1'], ts=T0 + day * DAY)[0], 'same')

    def test_a_new_critical_is_grown_and_names_only_the_new_one(self):
        self.step(['CVE-2026-1'])
        self.assertEqual(self.step(['CVE-2026-1', 'CVE-2026-2'], ts=T0 + DAY), ('grown', ['CVE-2026-2']))
        self.assertEqual(self.step(['CVE-2026-1', 'CVE-2026-2'], ts=T0 + 2 * DAY)[0], 'same')

    def test_a_kev_listing_of_a_known_cve_is_grown(self):
        self.step(['CVE-2026-1'])
        self.assertEqual(self.step(['CVE-2026-1'], kev=['CVE-2026-1'], ts=T0 + DAY), ('grown', ['CVE-2026-1']))

    def test_a_cve_that_disappears_and_comes_back_is_not_new_again(self):
        self.step(['CVE-2026-1', 'CVE-2026-2'])
        self.assertEqual(self.step(['CVE-2026-1'], ts=T0 + DAY)[0], 'same')
        self.assertEqual(self.step(['CVE-2026-1', 'CVE-2026-2'], ts=T0 + 2 * DAY)[0], 'same')

    def test_reminder_after_seven_days_only_when_something_can_be_done(self):
        self.step(['CVE-2026-1'], fixable=['CVE-2026-1'])
        self.assertEqual(self.step(['CVE-2026-1'], fixable=['CVE-2026-1'], ts=T0 + 6.9 * DAY)[0], 'same')
        self.assertEqual(self.step(['CVE-2026-1'], fixable=['CVE-2026-1'], ts=T0 + 7 * DAY)[0], 'reminder')
        self.assertEqual(self.step(['CVE-2026-1'], fixable=['CVE-2026-1'], ts=T0 + 8 * DAY)[0], 'same')
        self.assertEqual(self.step(['CVE-2026-1'], fixable=['CVE-2026-1'], ts=T0 + 14 * DAY)[0], 'reminder')

    def test_an_unfixable_critical_is_not_repeated_weekly_but_its_fix_is_reported(self):
        self.step(['CVE-2026-1'])
        self.assertEqual(self.step(['CVE-2026-1'], ts=T0 + 30 * DAY)[0], 'same')
        self.assertEqual(self.step(['CVE-2026-1'], fixable=['CVE-2026-1'], ts=T0 + 31 * DAY),
                         ('fix_available', ['CVE-2026-1']))
        self.assertEqual(self.step(['CVE-2026-1'], fixable=['CVE-2026-1'], ts=T0 + 32 * DAY)[0], 'same')

    def test_a_kev_cve_is_reminded_even_without_a_fix(self):
        self.step([], kev=['CVE-2024-3094'])
        self.assertEqual(self.step([], kev=['CVE-2024-3094'], ts=T0 + 7 * DAY)[0], 'reminder')

    def test_a_rebuild_of_the_same_tag_with_nothing_new_is_rebuilt(self):
        self.step(['CVE-2026-1'])
        self.assertEqual(self.step(['CVE-2026-1'], image=self.ID2, ts=T0 + DAY), ('rebuilt', []))
        self.assertEqual(self.step(['CVE-2026-1'], image=self.ID2, ts=T0 + 2 * DAY)[0], 'same')

    def test_a_rebuild_that_brings_a_new_critical_is_grown(self):
        self.step(['CVE-2026-1'])
        self.assertEqual(self.step(['CVE-2026-1', 'CVE-2026-5'], image=self.ID2, ts=T0 + DAY),
                         ('grown', ['CVE-2026-5']))

    def test_a_rebuild_inherits_the_reminder_clock(self):
        self.step(['CVE-2026-1'], fixable=['CVE-2026-1'])
        self.assertEqual(self.step(['CVE-2026-1'], fixable=['CVE-2026-1'], image=self.ID2,
                                   ts=T0 + 8 * DAY)[0], 'reminder')

    def test_another_image_with_the_same_cves_is_new(self):
        self.step(['CVE-2026-1'])
        self.assertEqual(self.step(['CVE-2026-1'], image=self.ID2, refs=('other:2',), ts=T0 + DAY)[0], 'new')

    def test_a_clean_image_is_new_once_and_never_reminded(self):
        self.assertEqual(self.step([]), ('new', []))
        self.assertEqual(self.step([], ts=T0 + 30 * DAY)[0], 'same')

    def test_state_survives_a_save_and_load_and_old_entries_are_pruned(self):
        self.step(['CVE-2026-1'])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'state.json')
            cv.save_state(path, self.state)
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o600')
            again = cv.load_state(path)
            self.assertEqual(again['images'][self.ID1]['reported'], ['CVE-2026-1'])
            cv.prune_state(again, T0 + 31 * DAY)
            self.assertEqual(again['images'], {})
            with open(path, 'w') as fh:
                fh.write('{broken')
            self.assertEqual(cv.load_state(path)['images'], {})


class StatusChange(unittest.TestCase):

    def test_failure_lifecycle(self):
        st = cv.fresh_state()
        self.assertEqual(cv.status_change(st, 'none', T0, 3), 'ok')
        self.assertEqual(cv.status_change(st, 'db_stale', T0 + DAY, 3), 'new')
        self.assertEqual(cv.status_change(st, 'db_stale', T0 + 2 * DAY, 3), 'same')
        self.assertEqual(cv.status_change(st, 'db_stale', T0 + 4 * DAY, 3), 'reminder')
        self.assertEqual(cv.status_change(st, 'db_stale', T0 + 5 * DAY, 3), 'same')
        self.assertEqual(cv.status_change(st, 'docker_unreachable', T0 + 6 * DAY, 3), 'new')
        self.assertEqual(cv.status_change(st, 'none', T0 + 7 * DAY, 3), 'recovered')
        self.assertEqual(cv.status_change(st, 'none', T0 + 8 * DAY, 3), 'ok')


class Output(unittest.TestCase):

    def test_the_file_is_rotated_once_it_is_too_big(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'out.json')
            for i in range(40):
                cv.append_lines(path, [{'msg': 'x' * 400, 'type': 'status', 'n': i}], 4096)
            self.assertLessEqual(os.path.getsize(path), 4096 + 600)
            self.assertLessEqual(os.path.getsize(path + '.1'), 4096 + 600)
            self.assertEqual(sorted(os.listdir(d)), ['out.json', 'out.json.1'])
            with open(path) as fh:
                last = json.loads(fh.read().splitlines()[-1])
            self.assertEqual(last['container_vuln']['n'], 39)

    def test_scrub_removes_credentials_and_keeps_one_line(self):
        text = ('pulling\nError: Get "https://bob:s3cret@registry.example.com/v2/": '
                'Authorization: Bearer abc.def password=hunter2 token=xyz')
        out = cv.scrub(text)
        for secret in ('s3cret', 'abc.def', 'hunter2', 'xyz', 'bob:'):
            self.assertNotIn(secret, out)
        self.assertNotIn('\n', out)
        self.assertNotIn('pulling', out)

    def test_config_parsing(self):
        conf = cv.parse_config('# c\nCPUS="0.5"\nexport MEMORY=2g\nUNKNOWN=1\nJAVA_DB=off\n')
        self.assertEqual((conf['CPUS'], conf['MEMORY'], conf['JAVA_DB']), ('0.5', '2g', 'off'))
        self.assertNotIn('UNKNOWN', conf)
        self.assertTrue(cv.pinned(cv.DEFAULTS['TRIVY_IMAGE']))
        self.assertFalse(cv.pinned('aquasec/trivy:0.75.0'))
        self.assertFalse(cv.pinned('aquasec/trivy:latest@sha256:abc'))


class Resp(object):
    def __init__(self, body, headers=None):
        self.body, self.headers = body, headers or {}

    def read(self, n=-1):
        return self.body


class Kev(unittest.TestCase):

    def conf(self, **kw):
        c = dict(cv.DEFAULTS)
        c.update(kw)
        return c

    def test_download_marks_and_keeps_the_last_good_copy(self):
        with tempfile.TemporaryDirectory() as d:
            calls = []

            def ok(url, timeout, proxy, headers):
                calls.append(url)
                return Resp(kev_document(extra=['CVE-2024-3094']), {'Last-Modified': 'Fri, 16 Oct 2026'})
            kev, info = cv.update_kev(self.conf(), d, T0, ok)
            self.assertIn('CVE-2024-3094', kev)
            self.assertEqual((info['age_days'], info['error']), (0.0, ''))
            # within 20 hours: no request at all
            cv.update_kev(self.conf(), d, T0 + 3600, ok)
            self.assertEqual(len(calls), 1)

            def down(url, timeout, proxy, headers):
                raise urllib.error.URLError('timed out')
            kev, info = cv.update_kev(self.conf(), d, T0 + 2 * DAY, down)
            self.assertIn('CVE-2024-3094', kev, 'last good copy still used')
            self.assertEqual(info['age_days'], 2.0)
            self.assertIn('timed out', info['error'])
            kev, info = cv.update_kev(self.conf(), d, T0 + 8 * DAY, down)
            self.assertGreater(info['age_days'], 7)

    def test_a_bad_document_never_replaces_the_good_one(self):
        with tempfile.TemporaryDirectory() as d:
            cv.update_kev(self.conf(), d, T0, lambda *a: Resp(kev_document()))

            def tiny(url, timeout, proxy, headers):
                return Resp(json.dumps({'vulnerabilities': [{'cveID': 'CVE-2026-1'}]}).encode())
            kev, info = cv.update_kev(self.conf(), d, T0 + DAY, tiny)
            self.assertEqual(len(kev), 600)
            self.assertTrue(info['error'])

    def test_fallback_source_and_not_modified(self):
        with tempfile.TemporaryDirectory() as d:
            seen = []

            def first_fails(url, timeout, proxy, headers):
                seen.append((url, dict(headers)))
                if 'cisa.gov' in url:
                    raise urllib.error.URLError('refused')
                return Resp(kev_document(), {'Last-Modified': 'Fri, 16 Oct 2026 17:15:48 GMT'})
            kev, info = cv.update_kev(self.conf(), d, T0, first_fails)
            self.assertEqual(len(kev), 600)
            self.assertEqual(info['error'], '')
            self.assertIn('githubusercontent', seen[-1][0])

            def not_modified(url, timeout, proxy, headers):
                seen.append((url, dict(headers)))
                if 'cisa.gov' in url:
                    raise urllib.error.URLError('refused')
                raise urllib.error.HTTPError(url, 304, 'Not Modified', {}, None)
            kev, info = cv.update_kev(self.conf(), d, T0 + DAY, not_modified)
            self.assertEqual(info['age_days'], 0.0)
            self.assertEqual(seen[-1][1].get('If-Modified-Since'), 'Fri, 16 Oct 2026 17:15:48 GMT')


class FakeDocker(object):
    """Answers the docker commands the scanner runs, and records them."""

    TRIVY_REPORT = report(vuln('CVE-2026-6653', 'libxml2', 'CRITICAL'),
                          vuln('CVE-2024-3094', 'xz-utils', 'HIGH', fixed='5.6.1+really5.4.5-1'),
                          vuln('CVE-2026-43185', 'linux-libc-dev', 'CRITICAL'))

    def __init__(self, tmp, java_first=False, docker_down=False, trivy_present=True, db_ok=True):
        self.tmp = tmp
        self.calls = []
        self.java_first = java_first
        self.docker_down = docker_down
        self.trivy_present = trivy_present
        self.db_ok = db_ok
        self.containers = {'c1' * 32: ('/web1', 'nginx:stable', 'sha256:' + 'a' * 64),
                           'c2' * 32: ('/web2', 'nginx:stable', 'sha256:' + 'a' * 64),
                           'c3' * 32: ('/db', 'postgres:17', 'sha256:' + 'b' * 64)}

    @staticmethod
    def mount(args, target):
        for i, a in enumerate(args):
            if a == '-v' and args[i + 1].split(':')[1] == target:
                return args[i + 1].split(':')[0]
        return None

    def run(self, args, timeout, stdout_path=None):
        self.calls.append(list(args))
        if args[:2] == ['docker', 'version']:
            if self.docker_down:
                return 1, '', 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock.'
            return 0, '29.1.3\n', ''
        if args[:2] == ['docker', 'ps']:
            return 0, '\n'.join(self.containers) + '\n', ''
        if args[:2] == ['docker', 'inspect']:
            out = [json.dumps({'name': n, 'image_ref': r, 'image': i})
                   for cid, (n, r, i) in self.containers.items() if cid in args]
            return 0, '\n'.join(out) + '\n', ''
        if args[:3] == ['docker', 'image', 'inspect']:
            ref = args[-1]
            if '--format' not in args:
                return (0, '[]', '') if self.trivy_present else (1, '', 'No such image')
            if 'org.opencontainers.image.version' in args[4]:
                return 0, '0.75.0\n', ''
            return 0, json.dumps({'id': ref if ref.startswith('sha256:') else 'sha256:' + 'a' * 64,
                                  'tags': ['nginx:stable'], 'digests': ['nginx@sha256:' + 'e' * 64],
                                  'size': 1000}) + '\n', ''
        if args[:2] == ['docker', 'pull']:
            return 1, '', 'Error response from daemon: Get "https://u:pw@registry.example.com/v2/": no such host'
        if args[:2] == ['docker', 'save']:
            with open(args[3], 'wb') as fh:
                fh.write(b'tar')
            return 0, '', ''
        if args[:2] == ['docker', 'rm']:
            return 0, '', ''
        if args[:2] == ['docker', 'run']:
            cache = self.mount(args, '/cache')
            if '--download-db-only' in args:
                if not self.db_ok:
                    return 1, '', 'FATAL failed to download artifact from any source'
                os.makedirs(os.path.join(cache, 'db'), exist_ok=True)
                with open(os.path.join(cache, 'db', 'metadata.json'), 'w') as fh:
                    json.dump({'UpdatedAt': '2026-10-17T00:00:00.123456789Z'}, fh)
                return 0, '', ''
            if '--download-java-db-only' in args:
                os.makedirs(os.path.join(cache, 'java-db'), exist_ok=True)
                with open(os.path.join(cache, 'java-db', 'metadata.json'), 'w') as fh:
                    json.dump({'UpdatedAt': '2026-10-17T00:00:00Z'}, fh)
                self.java_first = False
                return 0, '', ''
            if '--input' in args:
                if self.java_first:
                    return 1, '', ("FATAL Fatal error run error: ... Unable to initialize the Java DB: Java DB "
                                   "update failed: '--skip-java-db-update' cannot be specified on the first run")
                out = args[args.index('--output') + 1]
                host_tmp = self.mount(args, '/tmp')
                with open(os.path.join(host_tmp, os.path.basename(out)), 'w') as fh:
                    json.dump(self.TRIVY_REPORT, fh)
                return 0, '', ''
        raise AssertionError('unexpected command %r' % args)


class EndToEnd(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        d = self.dir.name
        self.out = os.path.join(d, 'out.json')
        self.conf = os.path.join(d, 'c.conf')
        with open(self.conf, 'w') as fh:
            fh.write('CACHE_DIR=%s/cache\nSTATE_DIR=%s/state\nOUTPUT=%s\n' % (d, d, self.out))
        self.kev = lambda url, t, p, h: Resp(kev_document(extra=['CVE-2024-3094']))

    def tearDown(self):
        self.dir.cleanup()

    def run_once(self, fake, ts, extra=()):
        code = cv.main(['--config', self.conf] + list(extra), runner=fake, clock=lambda: ts,
                       fetcher=self.kev)
        with open(self.out) as fh:
            lines = [json.loads(l)['container_vuln'] for l in fh.read().splitlines()]
        return code, lines

    def test_one_line_per_image_then_a_status_line(self):
        fake = FakeDocker(self.dir.name)
        code, lines = self.run_once(fake, T0 + DAY / 2)
        self.assertEqual(code, 0)
        self.assertEqual([l['type'] for l in lines], ['image', 'image', 'status'])
        nginx = [l for l in lines if l.get('image') == 'nginx:stable'][0]
        self.assertEqual(nginx['containers'], 'web1,web2', 'two containers of one image: one line')
        self.assertEqual((nginx['critical'], nginx['high'], nginx['kev_count']), (1, 1, 1))
        self.assertEqual(nginx['kev'], 'CVE-2024-3094')
        self.assertEqual(nginx['ignored_kernel_headers'], 1)
        self.assertEqual(nginx['change'], 'new')
        self.assertEqual(lines[-1]['status'], 'ok')
        self.assertEqual(lines[-1]['scanner'], 'trivy 0.75.0')
        self.assertEqual(list(lines[0])[:2], ['msg', 'type'])

    def test_the_scanning_container_gets_no_socket_no_network_and_no_privileges(self):
        fake = FakeDocker(self.dir.name)
        self.run_once(fake, T0 + DAY / 2)
        runs = [c for c in fake.calls if c[:2] == ['docker', 'run']]
        self.assertTrue(runs)
        for c in runs:
            joined = ' '.join(c)
            self.assertNotIn('docker.sock', joined)
            self.assertNotIn('--privileged', c)
            for flag in ('--cap-drop', '--read-only', '--pids-limit', '--memory', '--cpus'):
                self.assertIn(flag, c)
            self.assertIn(cv.DEFAULTS['TRIVY_IMAGE'], c)
        scans = [c for c in runs if '--input' in c]
        for c in scans:
            self.assertEqual(c[c.index('--network') + 1], 'none')
            self.assertIn('vuln', c[c.index('--scanners') + 1])
            self.assertNotIn('secret', c[c.index('--scanners') + 1])
            self.assertTrue(any(v.endswith(':/cache:ro') for v in c), 'database read-only while scanning')
        inspect = [c for c in fake.calls if c[:2] == ['docker', 'inspect']][0]
        self.assertNotIn('Env', inspect[3], 'container environment (secrets) is never requested')

    def test_a_second_run_the_same_day_skips_and_the_next_day_is_same(self):
        fake = FakeDocker(self.dir.name)
        self.run_once(fake, T0 + DAY / 2)
        _, lines = self.run_once(fake, T0 + DAY / 2 + 3600)
        self.assertEqual(lines[-1]['skipped_recent'], 2)
        self.assertEqual(len(lines), 4, 'only a status line was added')
        _, lines = self.run_once(fake, T0 + 1.5 * DAY)
        self.assertEqual([l['change'] for l in lines[-3:-1]], ['same', 'same'])

    def test_java_db_is_fetched_only_when_an_image_needs_it(self):
        fake = FakeDocker(self.dir.name, java_first=True)
        code, lines = self.run_once(fake, T0 + DAY / 2)
        self.assertEqual(code, 0, lines[-1])
        java = [c for c in fake.calls if '--download-java-db-only' in c]
        self.assertEqual(len(java), 1)
        self.assertEqual(lines[-1]['scanned'], 2)

    def test_docker_down_is_a_status_with_a_reason(self):
        fake = FakeDocker(self.dir.name, docker_down=True)
        code, lines = self.run_once(fake, T0)
        self.assertEqual(code, 1)
        self.assertEqual((lines[-1]['problem'], lines[-1]['change']), ('docker_unreachable', 'new'))
        _, lines = self.run_once(fake, T0 + DAY)
        self.assertEqual(lines[-1]['change'], 'same')

    def test_a_scanner_that_cannot_be_pulled_is_reported_without_credentials(self):
        fake = FakeDocker(self.dir.name, trivy_present=False)
        _, lines = self.run_once(fake, T0)
        self.assertEqual(lines[-1]['problem'], 'scanner_unavailable')
        self.assertNotIn('pw@', lines[-1]['error'])
        self.assertNotIn('pw@', lines[-1]['msg'])

    def test_an_unpinned_scanner_image_is_refused(self):
        with open(self.conf, 'a') as fh:
            fh.write('TRIVY_IMAGE=aquasec/trivy:latest\n')
        fake = FakeDocker(self.dir.name)
        _, lines = self.run_once(fake, T0)
        self.assertEqual(lines[-1]['problem'], 'scanner_unavailable')
        self.assertFalse([c for c in fake.calls if c[:2] in (['docker', 'run'], ['docker', 'pull'])])

    def test_no_database_means_no_scan(self):
        fake = FakeDocker(self.dir.name, db_ok=False)
        _, lines = self.run_once(fake, T0)
        self.assertEqual(lines[-1]['problem'], 'db_missing')
        self.assertFalse([c for c in fake.calls if '--input' in c])

    def test_temporary_files_are_removed(self):
        fake = FakeDocker(self.dir.name)
        self.run_once(fake, T0 + DAY / 2)
        self.assertEqual(os.listdir(os.path.join(self.dir.name, 'cache', 'tmp')), [])


class Packaging(unittest.TestCase):

    def test_the_script_runs_on_the_python_of_the_oldest_supported_host(self):
        # Ubuntu 22.04 ships 3.10, UCS 5.2 and Debian 12 3.11: no newer syntax
        with io.open(SCRIPT, encoding='utf-8') as fh:
            body = fh.read()
        self.assertNotRegex(body, r'\(\s*\w+\s*:=|^\s*match \w+:\s*$|removeprefix|removesuffix')
        self.assertIn('af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa', body)

    def test_the_rules_accept_only_the_scanners_file(self):
        path = os.path.join(ROOT, 'packs', 'jt-container-vuln', 'rules', 'zz-132800-jt_container_vuln_rules.xml')
        with io.open(path, encoding='utf-8') as fh:
            body = fh.read()
        self.assertRegex(body, r'<location type="pcre2">jt-container-vuln\\\.json\$</location>')
        conf = os.path.join(ROOT, 'packs', 'jt-container-vuln', 'agent', 'agent.conf')
        with io.open(conf, encoding='utf-8') as fh:
            self.assertIn('<location>/var/log/jt-container-vuln.json</location>', fh.read())
        self.assertEqual(cv.DEFAULTS['OUTPUT'], '/var/log/jt-container-vuln.json')


if __name__ == '__main__':
    unittest.main()
