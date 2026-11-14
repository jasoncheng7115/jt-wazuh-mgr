"""jt-fail2ban 1.4: jt-waf-block, the fail2ban action that blocks an address at the reverse
proxy through jt-waf-mgr's temporary IP block API. No network: the API call is replaced."""

import importlib.util
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'packs', 'jt-fail2ban', 'agent', 'jt-waf-block.py')

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('jt_waf_block', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestWafBlock(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.answer = (201, {'id': 1})
        self.logs = []
        self.saved = (mod.settings, mod.call, mod.log)
        mod.settings = lambda: {'url': 'https://waf.example.org/api/v1', 'token_file': '/x',
                                'ca_file': '', 'timeout': '5'}
        mod.call = lambda conf, method, path, body=None: (self.calls.append((method, path, body)), self.answer)[1]
        mod.log = lambda level, text: self.logs.append(text)

    def tearDown(self):
        mod.settings, mod.call, mod.log = self.saved

    def test_ban_posts_one_address_with_ttl_and_source(self):
        rc = mod.main(['ban', '93.184.216.34', '--source', 'mail2/zimbra-webmail', '--ttl', '86400',
                       '--reason', 'zimbra-webmail: 4 failures'])
        self.assertEqual(rc, 0)
        self.assertEqual(self.calls, [('POST', '/blocks', {'ip': '93.184.216.34', 'ttl': 86400,
                                                           'source': 'mail2/zimbra-webmail',
                                                           'reason': 'zimbra-webmail: 4 failures'})])
        self.assertTrue(self.logs[-1].startswith('INFO ban 93.184.216.34 source=mail2/zimbra-webmail: done'))

    def test_private_and_bad_input_never_reach_the_api(self):
        # documentation ranges (203.0.113.0/24, 2001:db8::/32) are not public either
        for ip in ('10.0.5.20', '10.0.0.1', '127.0.0.1', '::1', 'fe80::1', '100.64.0.1', '203.0.113.7'):
            with self.subTest(ip=ip):
                self.assertEqual(mod.main(['ban', ip, '--source', 'mail2/x']), 0)
        self.assertEqual(mod.main(['ban', 'not-an-ip', '--source', 'mail2/x']), 2)
        self.assertEqual(mod.main(['ban', '93.184.216.34', '--source', 'mail2/x;rm -rf /']), 2)
        self.assertEqual(mod.main(['ban', '93.184.216.34']), 2)
        self.assertEqual(self.calls, [])

    def test_ttl_is_clamped_and_permanent_is_the_maximum(self):
        for ttl, want in ((5, 60), (10 ** 9, 7 * 86400), (-1, 7 * 86400), (3600, 3600)):
            self.calls.clear()
            mod.main(['ban', '93.184.216.34', '--source', 'm/j', '--ttl', str(ttl)])
            self.assertEqual(self.calls[0][2]['ttl'], want)

    def test_failures_exit_non_zero_and_are_logged(self):
        self.answer = (409, {'error': {'code': 'blocks_off'}})
        self.assertEqual(mod.main(['ban', '93.184.216.34', '--source', 'm/j']), 1)
        self.assertIn('HTTP 409 blocks_off', self.logs[-1])
        self.assertTrue(self.logs[-1].startswith('ERROR ban 93.184.216.34 source=m/j:'))

        def boom(*a, **k):
            raise OSError('refused')
        mod.call = boom
        self.assertEqual(mod.main(['ban', '93.184.216.34', '--source', 'm/j']), 1)
        self.assertIn('unreachable', self.logs[-1])

    def test_unban_deletes_only_this_source(self):
        self.answer = (200, {'removed': 1})
        self.assertEqual(mod.main(['unban', '2606:4700::1111', '--source', 'mail2/zimbra-webmail']), 0)
        self.assertEqual(self.calls[0][:2], ('DELETE', '/blocks/2606%3A4700%3A%3A1111?source=mail2%2Fzimbra-webmail'))
        self.answer = (404, {})
        self.assertEqual(mod.main(['unban', '93.184.216.34', '--source', 'm/j']), 0, 'already gone is fine')


class TestTokenFile(unittest.TestCase):
    def test_token_file_must_be_private_regular_and_root_owned(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'token')
            with open(p, 'w') as fh:
                fh.write('jwm_abc\n')
            os.chmod(p, 0o600)
            if os.getuid() == 0:
                self.assertEqual(mod.token(p), 'jwm_abc')
            os.chmod(p, 0o644)
            with self.assertRaises(SystemExit):
                mod.token(p)
            link = os.path.join(d, 'link')
            os.symlink(p, link)
            with self.assertRaises(SystemExit):
                mod.token(link)


if __name__ == '__main__':
    unittest.main()
