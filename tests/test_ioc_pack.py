"""jt-ioc 1.5: the threat-IP updater and the Windows rule chain, offline.

The updater is loaded like jt-malware-hash's (no __pycache__ inside the shipped
pack). wazuh-logtest cannot replay eventchannel events (CLAUDE.md pitfall 14), so
the Sysmon/logon rules are checked by walking the rule tree with decoded values.
Written by the jt-ioc subagent in Round 3 (2026-10-11).
"""
import importlib.util
import io
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_updater():
    path = os.path.join(ROOT, 'packs', 'jt-ioc', 'scripts', 'update-threat-ip-list.py')
    spec = importlib.util.spec_from_file_location('ioc_updater', path)
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


mod = _load_updater()
N = ipaddress.ip_network


class TestIocUpdater(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(self.tmp))
        mod._QUEUE = None

    def write(self, name, body):
        p = os.path.join(self.tmp, name)
        with open(p, 'w') as fh:
            fh.write(body)
        return p

    def test_tiers(self):
        feeds = {'blocklist_de': {N('198.51.100.10/32'), N('198.51.100.20/32')}, 'cins': {N('198.51.100.20/32')},
                 'tor_exit': {N('198.51.100.30/32')}, 'spamhaus_drop': {N('203.0.113.0/24')},
                 'net_ua': {N('198.51.100.30/32')}}
        main, high, st = mod.build_lists(feeds, {}, exclusions=[], scanners=[])
        self.assertIn('198.51.100.10', main); self.assertNotIn('198.51.100.10', high)
        self.assertIn('198.51.100.20', high)                      # two votes
        self.assertIn('203.0.113.', high)                         # curated network as a prefix key
        self.assertNotIn('198.51.100.30', high)                   # Tor + one vote = one vote
        self.assertIn('::ffff:198.51.100.20', high)               # mapped form
        tor_only = mod.build_lists({'tor_exit': {N('198.51.100.40/32')}}, {}, [], [])
        self.assertNotIn('198.51.100.40', tor_only[1])

    def test_scanners_and_exclusions_are_removed(self):
        feeds = {'blocklist_de': {N('198.51.100.10/32'), N('198.51.100.11/32'), N('198.51.0.0/16')},
                 'cins': {N('198.51.100.10/32')}}
        main, high, st = mod.build_lists(feeds, {'mapped_v6_keys': 'no'}, exclusions=[N('198.51.100.11/32')],
                                         scanners=[N('198.51.100.10/32')])
        self.assertNotIn('198.51.100.10', main)                   # scanner, even with two votes
        self.assertNotIn('198.51.100.11', main)                   # excluded
        self.assertNotIn('198.51.', main)                         # network overlapping an exclusion
        self.assertFalse(any(k.startswith('::ffff:') for k in main))

    def test_cdb_keys(self):
        self.assertEqual(mod.cdb_keys(N('203.0.113.0/24')), ['203.0.113.'])
        self.assertEqual(len(mod.cdb_keys(N('203.0.112.0/23'))), 2)
        self.assertEqual(mod.cdb_keys(N('203.0.113.4/31')), ['203.0.113.4', '203.0.113.5'])
        self.assertEqual(mod.cdb_keys(N('10.0.0.0/8')), ['10.'])
        self.assertIsNone(mod.cdb_keys(N('0.0.0.0/0')))

    def test_parsers(self):
        p = self.write('ua.csv', 'IP;BAN_DATE;UNBAN_DATE;REASON\n198.51.100.1;%d;0;"x"\n198.51.100.2;%d;0;"y"\n'
                       % (1791600000, 1791600000 - 40 * 86400))
        self.assertEqual(mod.parse_net_ua(p, 30, now=1791600000 + 3600), {N('198.51.100.1/32')})
        self.assertEqual(len(mod.parse_net_ua(p, 0, now=1791600000)), 2)
        p = self.write('drop.json', '{"cidr":"203.0.113.0/24","sblid":"SBL1","rir":"arin"}\n'
                       '{"type":"metadata","timestamp":1,"size":2,"records":1}\n')
        self.assertEqual(mod.parse_spamhaus(p), {N('203.0.113.0/24')})
        p = self.write('tf.csv', '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware",'
                       '"malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised"\n'
                       '"2026-10-11 09:05:03", "1", "198.51.100.5:7777", "ip:port", "botnet_cc", "x", "None", "X", "", "100", "False"\n'
                       '"2026-10-11 09:05:03", "2", "198.51.100.6:443", "ip:port", "botnet_cc", "x", "None", "X", "", "50", "False"\n')
        self.assertEqual(mod.parse_threatfox(p, 75), {N('198.51.100.5/32')})
        p = self.write('plain.txt', '# c\n198.51.100.7\n198.51.100.8 # x\n2001:db8::1\n<html>\n198.51.100.0/30,foo\n')
        self.assertEqual(mod.parse_plain(p), {N('198.51.100.7/32'), N('198.51.100.8/32'), N('198.51.100.0/30')})
        p = self.write('ds.txt', '#\n198.51.100.0\t198.51.100.255\t24\t1234\tX\tUS\tx@example.com\n')
        self.assertEqual(mod.parse_dshield(p), {N('198.51.100.0/24')})

    def test_render_never_empty_and_no_comments(self):
        self.assertTrue(mod.render({}).startswith(mod.PLACEHOLDER + ':'))
        body = mod.render({'198.51.100.1': {'cins', 'blocklist_de'}})
        self.assertEqual(body, '"198.51.100.1":blocklist_de,cins\n')
        with open(os.path.join(ROOT, 'packs', 'jt-ioc', 'lists', 'jason_tools_threat_ip')) as fh:
            shipped = fh.read()
        self.assertFalse(shipped.startswith('#'))
        self.assertEqual(mod.count_keys(os.path.join(ROOT, 'packs', 'jt-ioc', 'lists', 'jason_tools_threat_ip')), 0)

    def test_write_list_does_not_use_the_compiler_temp_name(self):
        lists = os.path.join(self.tmp, 'lists'); os.makedirs(lists)
        work = os.path.join(self.tmp, 'work'); os.makedirs(work)
        path = os.path.join(lists, 'jason_tools_threat_ip')
        seen = []
        real = os.replace
        def spy(a, b):
            seen.append(a); return real(a, b)
        mod.os.replace = spy
        try:
            mod.write_list(path, '"198.51.100.1":x\n', work)
        finally:
            mod.os.replace = real
        self.assertTrue(all(not s.endswith(path + '.tmp') for s in seen), seen)
        self.assertEqual(open(path).read(), '"198.51.100.1":x\n')

    def test_broken_feed_keeps_previous_copy(self):
        work = self.tmp
        self.write('cins.txt', '\n'.join('198.51.100.%d' % i for i in range(1, 101)) + '\n')
        state = {'feeds': {'cins': {'fetched': 0, 'count': 100}}}
        def fake_fetch(urls, dest, headers, **kw):
            with open(dest, 'w') as fh:
                fh.write('198.51.100.1\n')               # 1 against 100
            return 13
        real = mod.fetch
        mod.fetch = fake_fetch
        try:
            nets, fails = mod.update_feeds(work, ['cins'], {}, state)
            self.assertEqual(len(nets['cins']), 100)        # previous copy used
            self.assertEqual(fails[0][0], 'feed')
            for _ in range(2):
                nets, fails = mod.update_feeds(work, ['cins'], {}, state, force=True)
            self.assertEqual(len(nets['cins']), 1)          # accepted after three in a row
        finally:
            mod.fetch = real

    def test_html_answer_is_rejected(self):
        p = os.path.join(self.tmp, 'x')
        class R:
            def __init__(s): s.d = [b'<!DOCTYPE html><html>blocked</html>', b'']
            def read(s, n): return s.d.pop(0)
            def __enter__(s): return s
            def __exit__(s, *a): pass
        real = mod.urllib.request.urlopen
        mod.urllib.request.urlopen = lambda *a, **k: R()
        try:
            with self.assertRaises(ValueError):
                mod._download('https://example.com/x', p, {}, 5)
        finally:
            mod.urllib.request.urlopen = real
        self.assertFalse(os.path.exists(p))

    def test_failure_reaches_the_queue_in_the_shape_906090_reads(self):
        path = os.path.join(self.tmp, 'q')
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); srv.bind(path)
        mod._QUEUE = path; mod._SECRET = 'sekrit'
        try:
            mod.report_failure('refused', 'abuse.ch refused (key sekrit)')
            msg = srv.recv(4096).decode()
        finally:
            mod._QUEUE = None; mod._SECRET = None; srv.close()
        self.assertTrue(msg.startswith('1:jt-ioc:jt-ioc: ERROR refused: '), msg)
        self.assertNotIn('sekrit', msg)

    def test_stale_and_placeholder(self):
        p = self.write('jason_tools_threat_ip', mod.PLACEHOLDER + ':jt-ioc\n')
        self.assertTrue(mod.check_stale(p, {}))
        p = self.write('jason_tools_threat_ip', '"198.51.100.1":x\n')
        self.assertFalse(mod.check_stale(p, {}))
        os.utime(p, (0, 0))
        self.assertTrue(mod.check_stale(p, {'stale_hours': '48'}))

    def test_cli_flags_used_by_existing_cron_lines(self):
        with io.open(os.path.join(ROOT, 'packs', 'jt-ioc', 'scripts', 'update-threat-ip-list.py'), encoding='utf-8') as fh:
            src = fh.read()
        for flag in ('--wazuh-path', '--reload-if-stale', '--force', '--dry-run', '--no-reload'):
            self.assertIn("'%s'" % flag, src)

    def test_default_feeds_avoid_commercial_restrictions(self):
        on = mod.enabled_feeds({})
        for name in ('threatfox', 'feodo', 'dshield', 'matthewroberts'):
            self.assertNotIn(name, on)
        self.assertNotIn('darklist_de', mod.FEEDS)
        self.assertIn('threatfox', mod.enabled_feeds({'threatfox': 'yes'}))
        self.assertNotIn('cins', mod.enabled_feeds({'cins': 'no'}))


RULES = os.path.join(ROOT, 'packs', 'jt-ioc', 'rules', 'zz-906050-jason_tools_ioc_late.xml')
LOW, HIGH = '198.51.100.10', '198.51.100.20'
LISTS = {'etc/lists/jason_tools_threat_ip': {LOW, HIGH}, 'etc/lists/jason_tools_threat_ip_high': {HIGH}}

class TestIocWindowsRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with io.open(RULES, encoding='utf-8') as fh:
            root = ET.fromstring('<r>' + fh.read() + '</r>')
        cls.rules = {}
        for r in root.iter('rule'):
            cls.rules[r.get('id')] = {
                'level': int(r.get('level')),
                'fields': [(f.get('name').split('.')[-1], f.text, f.get('type')) for f in r.findall('field')],
                'lists': [(l.get('field').split('.')[-1], l.text.strip()) for l in r.findall('list')],
                'parents': [s.strip() for el in r.findall('if_sid') for s in el.text.split(',')],
                'groups': [el.text.strip() for el in r.findall('if_group')]}

    def matches(self, rid, ev):
        r = self.rules[rid]
        for key, pat, typ in r['fields']:
            if ev.get(key) is None or not re.search(pat, ev[key]):
                return False
        for key, lst in r['lists']:
            if ev.get(key) not in LISTS[lst]:
                return False
        return True

    def finals(self, parent, ev, group=None):
        out = []
        for rid, r in self.rules.items():
            if (parent in r['parents'] or (group and group in r['groups'])) and self.matches(rid, ev):
                out += self.finals(rid, ev) or [rid]
        return sorted(set(out))

    def test_sysmon_event3(self):
        out = lambda ip, proto='tcp', port='443': {'initiated': 'true', 'protocol': proto, 'destinationIp': ip,
                                                   'destinationPort': port, 'sourceIp': '10.0.0.5', 'image': 'x.exe'}
        inb = lambda ip: {'initiated': 'false', 'protocol': 'tcp', 'sourceIp': ip, 'destinationIp': '10.0.0.5',
                          'destinationPort': '3389', 'image': 'svchost.exe'}
        cases = [
            ('61605', out(LOW), ['906032']), ('61605', out(HIGH), ['906033']), ('61605', out('192.0.2.1'), []),
            ('92101', out(HIGH), ['906033']),                     # PowerShell over TCP (level 0 sibling first)
            ('92108', out(HIGH, port='3389'), ['906033']),        # outbound RDP
            ('92108', inb(LOW), ['906031']), ('92108', inb(HIGH), ['906034']),
            ('61605', out(LOW, 'udp', '40000'), ['906036']), ('61605', out(HIGH, 'udp', '40000'), ['906037']),
            ('61605', out(HIGH, 'udp', '53'), ['906035']), ('61605', out(HIGH, 'tcp', '53'), ['906035']),
            ('61605', out(HIGH, 'udp', '5353'), ['906037']),      # only port 53 is DNS
        ]
        for parent, ev, want in cases:
            with self.subTest(parent=parent, ev=ev):
                self.assertEqual(self.finals(parent, ev), want)

    def test_windows_logon(self):
        ev = lambda ip: {'ipAddress': ip, 'targetUserName': 'alice'}
        for ip, want in ((LOW, ['906051']), (HIGH, ['906053']), ('192.0.2.1', [])):
            with self.subTest(ip=ip):
                self.assertEqual(self.finals('92651', ev(ip), group='authentication_success'), want)

    def test_every_high_rule_is_a_leaf_under_its_low_rule(self):
        # a node without the high list declared drops only these rules (warning 7616)
        for rid, r in self.rules.items():
            if any(l == 'etc/lists/jason_tools_threat_ip_high' for _, l in r['lists']):
                with self.subTest(rule=rid):
                    self.assertEqual(len(r['parents']), 1)
                    self.assertFalse(any(rid in o['parents'] for o in self.rules.values()))
                    self.assertGreater(r['level'], self.rules[r['parents'][0]]['level'])


if __name__ == "__main__":
    unittest.main()
