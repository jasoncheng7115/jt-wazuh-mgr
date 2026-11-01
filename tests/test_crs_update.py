"""jt-modsecurity 1.1: agent/jt-crs-update.py, the Core Rule Set updater.

It runs daily as root on a web server and swaps the rules nginx loads, so the
checks are about what must not happen: a release that is unsigned, signed by
another key or holds paths outside its directory being applied; a release that
nginx rejects staying in place; a new major version or a brand-new release
being applied automatically; the same notice every day. gpg is real (a
throwaway key stands in for the CRS release key); GitHub, nginx and syslog are
stand-ins.
"""

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

sys.dont_write_bytecode = True      # no __pycache__ inside the shipped pack

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'packs', 'jt-modsecurity', 'agent', 'jt-crs-update.py')
KEY = os.path.join(ROOT, 'packs', 'jt-modsecurity', 'agent', 'crs-signing-key.asc')
DAY = 86400


def load():
    spec = importlib.util.spec_from_file_location('jt_crs_update', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def crs_tree(base, version):
    rules = os.path.join(base, 'rules')
    os.makedirs(rules)
    with open(os.path.join(rules, 'REQUEST-901-INITIALIZATION.conf'), 'w') as fh:
        # the comment is in the real REQUEST-901 and was once read as the version
        fh.write('# - Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/); OWASP_CRS/3.1.0.\n')
        fh.write('SecRule &TX:crs_setup_version "@eq 0" "id:901001,ver:\'OWASP_CRS/%s\'"\n' % version)
    with open(os.path.join(base, 'crs-setup.conf.example'), 'w') as fh:
        fh.write('# example\n')


def tarball(path, version, extra=None):
    """A minimal-release tarball; extra = list of (TarInfo, bytes) added after."""
    with tempfile.TemporaryDirectory() as tmp:
        top = os.path.join(tmp, 'coreruleset-%s' % version)
        crs_tree(top, version)
        with tarfile.open(path, 'w:gz') as tf:
            tf.add(top, arcname='coreruleset-%s' % version)
            for info, data in extra or []:
                tf.addfile(info, io.BytesIO(data) if data is not None else None)


@unittest.skipUnless(shutil.which('gpg'), 'gpg is not installed')
class TestCrsUpdate(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.gnupg = tempfile.mkdtemp()
        os.chmod(cls.gnupg, 0o700)
        g = ['gpg', '--homedir', cls.gnupg, '--batch', '--quiet', '--pinentry-mode', 'loopback', '--passphrase', '']
        subprocess.run(g + ['--quick-gen-key', 'Test Release <t@example.com>', 'ed25519', 'sign', '1d'],
                       check=True, capture_output=True)
        out = subprocess.run(['gpg', '--homedir', cls.gnupg, '--with-colons', '--list-keys'],
                             check=True, capture_output=True, text=True).stdout
        cls.fpr = next(l.split(':')[9] for l in out.splitlines() if l.startswith('fpr'))
        cls.key = os.path.join(cls.gnupg, 'pub.asc')
        with open(cls.key, 'wb') as fh:
            fh.write(subprocess.run(['gpg', '--homedir', cls.gnupg, '--armor', '--export', cls.fpr],
                                    check=True, capture_output=True).stdout)
        cls.g = g

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.gnupg, ignore_errors=True)

    def sign(self, path):
        subprocess.run(self.g + ['--yes', '--armor', '--detach-sign', '-o', path + '.asc', path],
                       check=True, capture_output=True)

    def setUp(self):
        self.m = load()
        self.m.PINNED_FPR = self.fpr
        self.tmp = tempfile.mkdtemp()
        self.modsec = os.path.join(self.tmp, 'modsec')
        os.makedirs(self.modsec)
        self.crs = os.path.join(self.modsec, 'crs')
        crs_tree(self.crs + '-4.30.0', '4.30.0')
        os.symlink('crs-4.30.0', self.crs)
        self.logged = []
        self.m.log = lambda level, msg, quiet=False: self.logged.append((level, ' '.join(str(msg).split()), quiet))
        self.nginx_ok, self.reload_bad, self.files = True, [], {}
        self.m.nginx_test = lambda: (self.nginx_ok, 'nginx: [emerg] test failure' if not self.nginx_ok else '')
        self.m.reload_and_check = lambda conf: list(self.reload_bad)
        self.m.fetch = self.fake_fetch
        self.m.apt_pending = lambda: []
        self.conf = dict(self.m.DEFAULTS, CRS_DIR=self.crs, KEY=self.key,
                         STATE=os.path.join(self.tmp, 'state', 'state.json'))
        self.now = time.time()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake_fetch(self, url, limit, accept=None):
        if url == self.m.API:
            return json.dumps(self.api).encode()
        if url not in self.files:
            raise RuntimeError('404 %s' % url)
        with open(self.files[url], 'rb') as fh:
            return fh.read()

    def release(self, version, age_days, signed=True, extra=None, by=None):
        name = 'coreruleset-%s-minimal.tar.gz' % version
        path = os.path.join(self.tmp, name)
        tarball(path, version, extra)
        if signed:
            self.sign(path)
        url = 'https://example.invalid/%s' % name
        self.files[url] = path
        self.files[url + '.asc'] = (by or path) + '.asc'
        published = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self.now - age_days * DAY))
        return {'tag_name': 'v' + version, 'draft': False, 'prerelease': False, 'published_at': published,
                'assets': [{'name': name, 'browser_download_url': url},
                           {'name': name + '.asc', 'browser_download_url': url + '.asc'}]}

    def in_use(self):
        return os.path.basename(os.path.realpath(self.crs))

    def levels(self, level):
        return [m for l, m, q in self.logged if l == level and not q]

    # -- choosing ---------------------------------------------------------

    def test_a_release_older_than_the_wait_is_applied(self):
        self.api = [self.release('4.31.0', 8)]
        self.assertEqual(self.m.run(self.conf, 'apply'), 0)
        self.assertEqual(self.in_use(), 'crs-4.31.0')
        self.assertIn('updated CRS 4.30.0 -> 4.31.0', self.levels('INFO'))
        self.assertTrue(os.path.isdir(self.crs + '-4.30.0'), 'the previous version is kept for rollback')

    def test_a_new_release_waits_and_an_older_eligible_one_is_taken(self):
        self.api = [self.release('4.31.0', 2)]
        self.m.run(self.conf, 'apply')
        self.assertEqual(self.in_use(), 'crs-4.30.0')
        self.assertTrue(any('it will be applied after 7 days' in m for m in self.levels('INFO')))
        self.logged.clear()
        self.api = [self.release('4.32.0', 1), self.release('4.31.0', 9)]
        self.m.run(self.conf, 'apply')
        self.assertEqual(self.in_use(), 'crs-4.31.0')

    def test_a_new_major_version_is_only_reported_once_a_week(self):
        self.api = [self.release('5.0.0', 30)]
        self.m.run(self.conf, 'apply')
        self.assertEqual(self.in_use(), 'crs-4.30.0')
        self.assertEqual(len([m for m in self.levels('NOTICE') if m.startswith('CRS 5.0.0 (new major')]), 1)
        self.m.run(self.conf, 'apply')
        self.assertEqual(len(self.levels('NOTICE')), 1, 'the same notice again the next day')

    def test_prereleases_and_older_lines_are_ignored(self):
        r = self.release('4.31.0', 30)
        r['prerelease'] = True
        self.api = [r, self.release('4.25.9', 30)]
        self.m.run(self.conf, 'apply')
        self.assertEqual(self.in_use(), 'crs-4.30.0')

    def test_check_mode_changes_nothing_and_logs_nothing(self):
        self.api = [self.release('4.31.0', 30)]
        self.m.run(self.conf, 'check')
        self.assertEqual(self.in_use(), 'crs-4.30.0')
        self.assertEqual([x for x in self.logged if not x[2]], [])
        self.assertFalse(os.path.exists(self.conf['STATE']))

    # -- what must never be applied ----------------------------------------

    def test_an_unsigned_release_is_refused(self):
        self.api = [self.release('4.31.0', 30, signed=False)]
        self.files[self.api[0]['assets'][1]['browser_download_url']] = KEY   # some unrelated .asc
        self.m.run(self.conf, 'apply')
        self.assertEqual(self.in_use(), 'crs-4.30.0')
        self.assertTrue(any(m.startswith('signature check failed') for m in self.levels('ERROR')))
        self.assertFalse(os.path.exists(self.crs + '-4.31.0'))

    def test_a_release_signed_by_another_key_is_refused(self):
        self.api = [self.release('4.31.0', 30)]
        self.m.PINNED_FPR = '36006F0E0BA167832158821138EEACA1AB8A6E72'   # the real CRS key, not ours
        self.conf['KEY'] = KEY
        self.m.run(self.conf, 'apply')
        self.assertEqual(self.in_use(), 'crs-4.30.0')
        self.assertTrue(any(m.startswith('signature check failed') for m in self.levels('ERROR')))

    def test_a_tampered_tarball_is_refused(self):
        self.api = [self.release('4.31.0', 30)]
        with open(self.files[self.api[0]['assets'][0]['browser_download_url']], 'ab') as fh:
            fh.write(b'x')
        self.m.run(self.conf, 'apply')
        self.assertEqual(self.in_use(), 'crs-4.30.0')

    def test_paths_outside_the_release_directory_are_refused(self):
        for name, kind in (('../evil.conf', tarfile.REGTYPE), ('/etc/evil.conf', tarfile.REGTYPE),
                           ('coreruleset-4.31.0/rules/link.conf', tarfile.SYMTYPE),
                           ('other/rules/x.conf', tarfile.REGTYPE)):
            info = tarfile.TarInfo(name)
            info.type = kind
            data = None
            if kind == tarfile.SYMTYPE:
                info.linkname = '/etc/shadow'
            else:
                data = b'SecRule ...\n'
                info.size = len(data)
            self.logged.clear()
            self.api = [self.release('4.31.0', 30, extra=[(info, data)])]
            self.m.run(self.conf, 'apply')
            self.assertEqual(self.in_use(), 'crs-4.30.0', name)
            self.assertTrue(any('could not be unpacked' in m for m in self.levels('ERROR')), name)
            self.assertFalse(os.path.exists(os.path.join(self.tmp, 'evil.conf')))

    def test_a_tarball_holding_another_version_is_refused(self):
        self.api = [self.release('4.31.0', 30)]
        path = self.files[self.api[0]['assets'][0]['browser_download_url']]
        with tempfile.TemporaryDirectory() as t:
            top = os.path.join(t, 'coreruleset-4.31.0')
            crs_tree(top, '4.29.0')
            with tarfile.open(path, 'w:gz') as tf:
                tf.add(top, arcname='coreruleset-4.31.0')
        self.sign(path)
        self.m.run(self.conf, 'apply')
        self.assertEqual(self.in_use(), 'crs-4.30.0')

    # -- nginx refusing ------------------------------------------------------

    def test_nginx_t_failure_puts_the_previous_version_back(self):
        self.api = [self.release('4.31.0', 30)]
        self.nginx_ok = False
        self.assertEqual(self.m.run(self.conf, 'apply'), 1)
        self.assertEqual(self.in_use(), 'crs-4.30.0')
        self.assertTrue(any(m.startswith('nginx rejected CRS 4.31.0') and m.endswith('rolled back to 4.30.0')
                            for m in self.levels('ERROR')))

    def test_a_failed_reload_puts_the_previous_version_back(self):
        self.api = [self.release('4.31.0', 30)]
        self.reload_bad = ['2026/11/01 04:37:01 [emerg] 1#1: something']
        self.m.run(self.conf, 'apply')
        self.assertEqual(self.in_use(), 'crs-4.30.0')
        self.assertTrue(any(m.startswith('nginx failed to reload with CRS 4.31.0') for m in self.levels('ERROR')))

    # -- staleness, rollback, setup, pruning ----------------------------------

    def test_a_long_run_of_failed_checks_becomes_its_own_error(self):
        self.m.fetch = lambda *a, **k: (_ for _ in ()).throw(OSError('network unreachable'))
        os.makedirs(os.path.dirname(self.conf['STATE']))
        with open(self.conf['STATE'], 'w') as fh:
            json.dump({'last_check_ok': self.now - 3 * DAY}, fh)
        self.m.run(self.conf, 'apply')
        self.assertEqual([m for m in self.levels('ERROR') if 'no successful' in m], [])
        with open(self.conf['STATE'], 'w') as fh:
            json.dump({'last_check_ok': self.now - 15 * DAY}, fh)
        self.m.run(self.conf, 'apply')
        self.assertTrue(any(m.startswith('no successful update check for 15 days') for m in self.levels('ERROR')))

    def test_rollback_and_pruning(self):
        self.conf['KEEP'] = '2'
        for v, age in (('4.31.0', 30), ('4.32.0', 20), ('4.33.0', 10)):
            self.api = [self.release(v, age)]
            self.m.run(self.conf, 'apply')
        self.assertEqual(self.in_use(), 'crs-4.33.0')
        self.assertEqual(sorted(os.path.basename(p) for p in self.m.versions_on_disk(self.crs).values()),
                         ['crs-4.32.0', 'crs-4.33.0'])
        self.assertEqual(self.m.do_rollback(self.conf), 0)
        self.assertEqual(self.in_use(), 'crs-4.32.0')
        self.assertIn('rolled back CRS 4.33.0 -> 4.32.0 (operator)', self.levels('INFO'))

    def test_setup_turns_a_directory_into_a_versioned_symlink(self):
        os.unlink(self.crs)
        os.rename(self.crs + '-4.30.0', self.crs)
        self.assertEqual(self.m.do_setup(self.conf), 0)
        self.assertTrue(os.path.islink(self.crs))
        self.assertEqual(self.in_use(), 'crs-4.30.0')
        self.nginx_ok = False
        os.unlink(self.crs)
        os.rename(self.crs + '-4.30.0', self.crs)
        self.assertEqual(self.m.do_setup(self.conf), 1)
        self.assertTrue(os.path.isdir(self.crs) and not os.path.islink(self.crs), 'restored as it was')

    def test_messages_are_single_lines(self):
        m = load()
        seen = []
        m.subprocess = type('S', (), {'run': staticmethod(lambda args, **k: seen.append(args)),
                                      'SubprocessError': Exception})
        m.log('ERROR', 'a\nINFO updated CRS 1.0.0 -> 9.9.9')
        self.assertEqual(seen[0][-1], 'ERROR a INFO updated CRS 1.0.0 -> 9.9.9')

    def test_the_shipped_key_is_the_crs_release_key(self):
        out = subprocess.run(['gpg', '--show-keys', '--with-colons', KEY], capture_output=True, text=True).stdout
        self.assertIn('fpr:::::::::36006F0E0BA167832158821138EEACA1AB8A6E72:', out)
        self.assertEqual(load().PINNED_FPR, '36006F0E0BA167832158821138EEACA1AB8A6E72')


if __name__ == '__main__':
    unittest.main()
