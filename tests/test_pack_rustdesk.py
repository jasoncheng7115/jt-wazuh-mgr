"""jt-rustdesk: the home-country list builder (packs/jt-rustdesk/scripts/jt-rustdesk-geo.py).

The list decides whether a RustDesk client registering from a public address is
"home" (level 3) or "abroad" (level 7), so a wrong or emptied list turns every
client into an alert, or hides the ones that matter.
"""

import importlib.util
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'packs', 'jt-rustdesk', 'scripts', 'jt-rustdesk-geo.py')

sys.dont_write_bytecode = True     # no __pycache__ inside packs/ (packs/INDEX lists every file)
spec = importlib.util.spec_from_file_location('jt_rustdesk_geo', SCRIPT)
geo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(geo)

DELEGATED = '\n'.join([
    '2|apnic|20261105|99999|19830613|20261104|+1000',
    'apnic|*|ipv4|*|9999|summary',
    'apnic|TW|ipv4|1.34.0.0|65536|20000101|allocated',      # a /16
    'apnic|TW|ipv4|61.218.0.0|131072|20000101|allocated',   # a /15: two /16 keys
    'apnic|TW|ipv4|203.69.10.0|256|20000101|assigned',      # a /24
    'apnic|TW|ipv4|202.39.8.128|128|20000101|assigned',     # a /25: written as its /24
    'apnic|JP|ipv4|1.0.16.0|4096|20000101|allocated',       # another country
    'apnic|TW|ipv4|192.0.2.0|256|20000101|reserved',        # not allocated or assigned
    'apnic|TW|ipv6|2001:b000::|20|20000101|allocated',      # IPv6: not in the list
    'apnic|TW|asn|3462|1|20000101|allocated',
]) + '\n'


TREES = []


def tearDownModule():
    for d in TREES:
        shutil.rmtree(d, ignore_errors=True)


def tree():
    d = tempfile.mkdtemp(prefix='jtrd-')
    TREES.append(d)
    for sub in ('etc/lists', 'etc/jt-packs', 'var', 'queue/sockets'):
        os.makedirs(os.path.join(d, sub))
    return d


class TestKeys(unittest.TestCase):
    def test_octet_boundary_expansion(self):
        k = lambda n: geo.cdb_keys(ipaddress.ip_network(n))
        self.assertEqual(k('1.34.0.0/16'), ['1.34.'])
        self.assertEqual(k('61.218.0.0/15'), ['61.218.', '61.219.'])
        self.assertEqual(k('203.69.10.0/24'), ['203.69.10.'])
        self.assertEqual(k('202.39.8.128/25'), ['202.39.8.'])
        self.assertEqual(k('10.0.0.0/8'), ['10.'])
        self.assertEqual(len(k('8.0.0.0/6')), 4)

    def test_build_keeps_only_the_chosen_countries(self):
        body, count = geo.build(DELEGATED, ['TW'])
        keys = [line.split(':')[0] for line in body.splitlines()]
        self.assertEqual(keys, ['1.34.', '61.218.', '61.219.', '202.39.8.', '203.69.10.'])
        self.assertEqual(count, 5)
        self.assertTrue(all(line.endswith(':home') for line in body.splitlines()))
        self.assertNotIn('192.0.2.', body)      # reserved, not allocated
        self.assertNotIn('1.0.', body)          # Japan

    def test_a_longer_prefix_under_a_shorter_one_is_dropped(self):
        text = DELEGATED + 'apnic|TW|ipv4|1.34.5.0|256|20000101|assigned\n'
        body, _ = geo.build(text, ['TW'])
        self.assertNotIn('1.34.5.', body)

    def test_countries_setting(self):
        d = tree()
        path = os.path.join(d, 'etc/jt-packs/jt-rustdesk.conf')
        self.assertEqual(geo.read_countries(path), ['TW'])            # no file: Taiwan
        with open(path, 'w') as fh:
            fh.write('# home countries\ncountries = jp, TW tw, xyz, 12\n')
        self.assertEqual(geo.read_countries(path), ['JP', 'TW'])


class TestRun(unittest.TestCase):
    def setUp(self):
        self.d = tree()
        self.events, self.reloads = [], []
        self.saved = (geo.fetch, geo.send, geo.reload_ruleset)
        geo.send = lambda wazuh, event: self.events.append(event)
        geo.reload_ruleset = lambda wazuh: self.reloads.append(wazuh) or True
        self.list = os.path.join(self.d, 'etc/lists/jt-rustdesk-home')

    def tearDown(self):
        geo.fetch, geo.send, geo.reload_ruleset = self.saved

    def run_geo(self, *args, text=DELEGATED):
        geo.fetch = lambda url: text
        return geo.main(['--wazuh-path', self.d, '--force'] + list(args))

    def test_writes_the_list_and_reloads_once(self):
        self.assertEqual(self.run_geo(), 0)
        with open(self.list) as fh:
            self.assertIn('1.34.:home', fh.read())
        self.assertEqual(len(self.reloads), 1)
        self.assertEqual(self.run_geo(), 0)          # same content: no second reload
        self.assertEqual(len(self.reloads), 1)

    def test_check_writes_nothing(self):
        self.assertEqual(self.run_geo('--check'), 0)
        self.assertFalse(os.path.exists(self.list))
        self.assertEqual(self.reloads, [])

    def test_a_list_that_shrank_by_half_is_refused(self):
        big = DELEGATED + ''.join('apnic|TW|ipv4|%d.0.0.0|16777216|20000101|allocated\n' % n
                                  for n in range(100, 140))
        self.assertEqual(self.run_geo(text=big), 0)
        with open(self.list) as fh:
            before = fh.read()
        self.assertEqual(self.run_geo(text=DELEGATED), 1)
        with open(self.list) as fh:
            self.assertEqual(fh.read(), before, 'the last good list stays')
        self.assertEqual(self.events[-1]['state'], 'failing')

    def test_a_failed_download_alerts_once_and_recovers(self):
        def broken(url):
            raise OSError('network unreachable')
        geo.fetch = broken
        self.assertEqual(geo.main(['--wazuh-path', self.d, '--force']), 1)
        self.assertEqual(geo.main(['--wazuh-path', self.d, '--force']), 1)
        self.assertEqual([e['state'] for e in self.events], ['failing'])
        self.assertEqual(self.run_geo(), 0)
        self.assertEqual(self.events[-1]['state'], 'recovered')

    def test_worker_reloads_only_when_the_synced_list_changed(self):
        self.assertEqual(geo.main(['--wazuh-path', self.d, '--reload-if-changed']), 0)   # no list yet
        self.assertEqual(self.reloads, [])
        with open(self.list, 'w') as fh:
            fh.write('1.34.:home\n')
        geo.main(['--wazuh-path', self.d, '--reload-if-changed'])
        geo.main(['--wazuh-path', self.d, '--reload-if-changed'])
        self.assertEqual(len(self.reloads), 1)

    def test_events_are_json_under_one_key(self):
        sent = []

        class Sock(object):
            def connect(self, path):
                sent.append(path)

            def send(self, data):
                sent.append(data)

            def close(self):
                pass
        real = geo.socket.socket
        geo.socket.socket = lambda *a: Sock()
        try:
            self.saved[1](self.d, {'state': 'failing', 'detail': 'x'})
        finally:
            geo.socket.socket = real
        self.assertTrue(sent[0].endswith('queue/sockets/queue'))
        prefix, payload = sent[1].decode().split(':', 2)[1:]
        self.assertEqual(prefix, 'jt-rustdesk-geo')
        self.assertEqual(json.loads(payload), {'jt_rustdesk_geo': {'detail': 'x', 'state': 'failing'}})


if __name__ == '__main__':
    unittest.main()
