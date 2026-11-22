"""jt-yara: the agent scripts (statically, and end to end in a container when docker, a
YARA-X binary and the Debian image are at hand) and what the manager side expects of them."""

import json
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, 'packs', 'jt-yara', 'agent')
YR = os.environ.get('JT_TEST_YR', '/usr/local/bin/yr')
IMAGE = 'python:3.12-slim-bookworm'


def read(name):
    return open(os.path.join(AGENT, name), encoding='utf-8').read()


class TestYaraAgentScripts(unittest.TestCase):
    def test_shell_syntax(self):
        for name in ('jt-yara.sh', 'jt-yara-quarantine.sh', 'jt-yara-status.sh', 'jt-yara-install.sh'):
            r = subprocess.run(['bash', '-n', os.path.join(AGENT, name)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, name + r.stderr)

    def test_scan_and_quarantine_share_one_scope(self):
        # the quarantine refuses what the scanner would not scan, so the two must agree
        pat = re.compile(r"^SCAN_PATHS='([^']+)'$", re.M)
        scan, quar = pat.search(read('jt-yara.sh')).group(1), pat.search(read('jt-yara-quarantine.sh')).group(1)
        self.assertEqual(scan, quar)
        fn = re.compile(r'^in_scope\(\) \{.*?^\}$', re.M | re.S)
        self.assertEqual(fn.search(read('jt-yara.sh')).group(0), fn.search(read('jt-yara-quarantine.sh')).group(0))

    def test_no_site_paths_in_the_pack(self):
        # a site's own web roots go in scan-paths.local (install --scan-path), not in the pack
        for name in ('jt-yara.sh', 'jt-yara-quarantine.sh'):
            self.assertNotRegex(read(name), r'/var/\((?:amviz|it)|/var/it/')

    def test_the_marker_is_the_same_everywhere(self):
        marker = re.search(r'\$m = "([^"]+)"', read('jt-test.yar')).group(1)
        self.assertIn(marker, read('jt-yara-status.sh'))
        self.assertIn(marker, read('jt-yara-install.sh'))
        self.assertIn('JT_Wazuh_YARA_Test', read('jt-test.yar'))

    def test_status_line_matches_the_decoder(self):
        dec = open(os.path.join(ROOT, 'packs', 'jt-yara', 'decoders', 'jt-yara_decoders.xml'), encoding='utf-8').read()
        regex = re.search(r'<decoder name="jt-yara-status">.*?<regex type="pcre2">(.*?)</regex>', dec, re.S).group(1)
        line = ('wazuh-yara: STATUS - state=broken yr=- rules=- rules_name=- rules_age=- scans=0 errors=3 hits=0 '
                'quarantine=no problem=yr missing at /usr/local/bin/yr; self-test: x')
        self.assertTrue(re.match(regex, line))
        # every key the status script writes, in the order the decoder reads them
        echo = re.search(r'echo "wazuh-yara: STATUS - (.*?)" >> "\$LOG"', read('jt-yara-status.sh')).group(1)
        keys = re.findall(r'(\w+)=\$', echo)
        self.assertEqual(keys, ['state', 'yr', 'rules', 'rules_name', 'rules_age', 'scans', 'errors', 'hits',
                                'quarantine', 'problem'])

    def test_group_delivers_every_agent_file(self):
        m = json.load(open(os.path.join(ROOT, 'packs', 'jt-yara', 'manifest.json'), encoding='utf-8'))
        files = set(m['agent_group']['files'])
        self.assertEqual(files, {f for f in os.listdir(AGENT) if f != 'agent.conf'})

    @unittest.skipUnless(shutil.which('docker') and os.path.isfile(YR), 'needs docker and a YARA-X binary')
    def test_end_to_end_in_a_container(self):
        if subprocess.run(['docker', 'image', 'inspect', IMAGE], capture_output=True).returncode:
            self.skipTest('image %s not present (not downloaded by the tests)' % IMAGE)
        r = subprocess.run(['docker', 'run', '--rm', '-v', AGENT + ':/pack:ro', '-v', YR + ':/yr:ro',
                            '-v', os.path.join(ROOT, 'tests', 'yara', 'agent-e2e.sh') + ':/e2e.sh:ro',
                            IMAGE, 'bash', '/e2e.sh'], capture_output=True, text=True, timeout=600)
        out = r.stdout + r.stderr
        self.assertIn('ALL PASS', out, out[-3000:])
        self.assertNotIn('FAIL ', out, out[-3000:])


import importlib.util  # noqa: E402
import sys  # noqa: E402
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    'jt_yara_inventory', os.path.join(ROOT, 'packs', 'jt-yara', 'scripts', 'jt-yara-inventory.py'))
inv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inv)


def alert(name, ts, state='ok', level='STATUS'):
    return json.dumps({'timestamp': ts + '.123+0800', 'rule': {'level': 3, 'id': '133430'},
                       'agent': {'id': '012', 'name': name, 'ip': 'any'},
                       'data': {'yara': {'level': level, 'state': state, 'yr': '1.22.1'}}}).encode() + b'\n'


class TestYaraInventory(unittest.TestCase):
    def test_reads_status_lines_only(self):
        seen = {}
        inv.note_line(alert('web1', '2026-11-22T04:17:00'), seen)
        inv.note_line(alert('web1', '2026-11-21T04:17:00'), seen)          # older: ignored
        inv.note_line(alert('web2', '2026-11-22T04:17:00', level='INFO'), seen)   # a match, not a status
        inv.note_line(alert('web3', '2026-11-22T05:00:00', state='broken'), seen)
        self.assertEqual(sorted(seen), ['web1', 'web3'])
        self.assertEqual(seen['web3']['state'], 'broken')
        self.assertEqual(seen['web1']['ts'], int(__import__('time').mktime((2026, 11, 22, 4, 17, 0, 0, 0, -1))))

    def test_judge(self):
        now = 10 ** 9
        day = 86400
        agents = [{'id': '001', 'name': 'web1', 'node': 'n1', 'status': 'active', 'groups': ['default', 'yara']},
                  {'id': '002', 'name': 'mail2', 'node': 'n1', 'status': 'active', 'groups': ['default']},
                  {'id': '003', 'name': 'dev9', 'node': 'n1', 'status': 'active', 'groups': ['default']},
                  {'id': '004', 'name': 'web2', 'node': 'n1', 'status': 'disconnected', 'groups': ['yara']},
                  {'id': '005', 'name': 'web3', 'node': 'n2', 'status': 'active', 'groups': ['yara']},
                  {'id': '006', 'name': 'web4', 'node': 'n1', 'status': 'active', 'groups': ['yara']}]
        conf = {'expected': {'mail2'}, 'silent_hours': 36}
        seen = {'web1': {'ts': now - 2 * day, 'state': 'ok'}, 'dev9': {'ts': now - 3600, 'state': 'ok'},
                'web4': {'ts': now - 3600, 'state': 'ok'}}
        f = inv.judge(agents, 'n1', conf, seen, since=now - 3 * day, now=now)
        self.assertEqual(f['web1']['event'], 'silent')
        self.assertEqual(f['web1']['hours'], 48)
        self.assertEqual(f['mail2']['event'], 'missing')            # listed, never reported
        self.assertEqual(f['mail2']['why'], 'listed in jt-yara.conf')
        self.assertEqual(f['dev9']['event'], 'unexpected')
        self.assertNotIn('web2', f)                                   # disconnected: not judged
        self.assertNotIn('web3', f)                                   # another node's agent
        self.assertNotIn('web4', f)                                   # reports in time
        # the check has not watched long enough to call a host missing
        f = inv.judge(agents, 'n1', conf, seen, since=now - 3600, now=now)
        self.assertNotIn('mail2', f)

    def test_evaluate_reminds_and_reports_back(self):
        now = 10 ** 9
        found = {'web1': {'event': 'silent', 'agent_name': 'web1', 'hours': 40}}
        ev, st = inv.evaluate(found, {}, now)
        self.assertEqual([e['change'] for e in ev], ['new'])
        ev, st2 = inv.evaluate(found, st, now + 3600)
        self.assertEqual(ev, [])                                      # once a day, not every hour
        ev, _ = inv.evaluate(found, st, now + 86400)
        self.assertEqual([e['change'] for e in ev], ['reminder'])
        ev, _ = inv.evaluate({}, st, now + 7200)
        self.assertEqual([(e['event'], e['was']) for e in ev], [('back', 'silent')])


if __name__ == '__main__':
    unittest.main()
