"""jt-file-access: structure the sandbox cases cannot show (offline)."""

import json
import os
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACK = os.path.join(ROOT, 'packs', 'jt-file-access')
RULES = os.path.join(PACK, 'rules', 'zz-133800-jt_file_access_rules.xml')


def rules():
    text = open(RULES, encoding='utf-8').read()
    root = ET.fromstring('<root>' + re.sub(r'<!--.*?-->', '', text, flags=re.S) + '</root>')
    return {r.get('id'): r for r in root.iter('rule')}


def field(rule, name):
    for f in rule.findall('field'):
        if f.get('name') == name:
            return f.text
    return None


class TestFileAccessPack(unittest.TestCase):
    def test_level_zero_rules_touch_only_this_packs_events(self):
        # a broad level 0 rule under a built-in parent hides built-in alerts (trap 13):
        # Linux ones need this pack's audit keys, Windows ones event 4663, which no
        # built-in rule handles
        for rid, r in rules().items():
            if r.get('level') != '0':
                continue
            sids = (r.findtext('if_sid') or '').split(',')
            if '80700' in sids:
                self.assertEqual(field(r, 'audit.key'), '^jt_file_read$|^jt_file_write$', rid)
            elif '60103' in sids:
                self.assertEqual(field(r, 'win.system.eventID'), '^4663$', rid)
            else:
                self.fail('level 0 rule %s under an unexpected parent %s' % (rid, sids))

    def test_system_accounts_on_alerting_builtins_go_back_to_the_builtin_level(self):
        # 4656 failures (built-in 60104, level 5) and 4907 (60112, level 8) are not silenced
        rs = rules()
        self.assertEqual(rs['133837'].get('level'), '5')
        self.assertEqual(rs['133837'].findtext('if_sid'), '133832')
        self.assertEqual(rs['133842'].get('level'), '8')
        self.assertEqual(rs['133842'].findtext('if_sid'), '133841')

    def test_linux_rules_also_hang_off_the_python_sibling(self):
        # built-in 92600 (python, level 0) sits next to 80700's children (trap 18)
        for rid in ('133800', '133801', '133802', '133810'):
            self.assertEqual(rules()[rid].findtext('if_sid'), '80700,92600', rid)

    def test_access_mask_patterns(self):
        rs = rules()
        pat = {rid: re.compile(field(rs[rid], 'win.eventdata.accessMask')) for rid in ('133820', '133821', '133822', '133823')}
        def hits(mask):
            return {rid for rid, p in pat.items() if p.search(mask)}
        self.assertEqual(hits('0x1'), {'133820'})
        self.assertEqual(hits('0x6'), {'133821'})
        self.assertEqual(hits('0x2'), {'133821'})
        self.assertEqual(hits('0x10000'), {'133822'})
        self.assertEqual(hits('0x40000'), {'133823'})
        self.assertEqual(hits('0x80000'), {'133823'})
        self.assertEqual(hits('0x50000'), {'133822', '133823'})   # level 8 is tried first
        self.assertEqual(hits('0x20000'), set())                  # READ_CONTROL alone
        self.assertEqual(hits('0x80'), set())                     # ReadAttributes alone
        self.assertEqual(hits('0x100'), set())                    # WriteAttributes alone
        self.assertEqual(hits('0X1'), {'133820'})

    def test_auditd_template_uses_the_keys_the_rules_read(self):
        text = open(os.path.join(PACK, 'agent', 'jt-file-access.rules'), encoding='utf-8').read()
        lines = [l for l in text.splitlines() if l.startswith('-w ')]
        self.assertTrue(lines)
        keys = {re.search(r'-k (\S+)', l).group(1) for l in lines}
        self.assertEqual(keys, {'jt_file_read', 'jt_file_write'})
        perms = {re.search(r'-k (\S+)', l).group(1): re.search(r'-p (\S+)', l).group(1) for l in lines}
        self.assertEqual(perms, {'jt_file_read': 'r', 'jt_file_write': 'wa'})

    def test_powershell_script_is_ascii_with_crlf(self):
        # Windows PowerShell 5.1 reads a file without BOM as ANSI
        data = open(os.path.join(PACK, 'agent', 'jt-file-access-sacl.ps1'), 'rb').read()
        data.decode('ascii')
        self.assertNotIn(b'\n', data.replace(b'\r\n', b''))
        self.assertIn(b'0CCE921D-69AE-11D9-BED3-505054503030', data)   # File System, by GUID
        self.assertIn(b"'S-1-1-0'", data)                             # Everyone, by SID

    def test_quiet_lists_are_site_data(self):
        m = json.load(open(os.path.join(PACK, 'manifest.json'), encoding='utf-8'))
        lists = {f['name']: f for f in m['files'] if f['type'] == 'list'}
        self.assertEqual(set(lists), {'jt-file-access-quiet', 'jt-file-access-quiet-accounts'})
        for f in lists.values():
            self.assertTrue(f.get('keep') and f.get('declare'), f['name'])

    def test_time_rules_and_the_cases_agree(self):
        # pack_sandbox's clock_expect uses 20:00-07:00 and weekends
        rs = rules()
        for rid in ('133805', '133827'):
            self.assertEqual(rs[rid].findtext('time'), '8 pm - 7 am', rid)
        for rid in ('133806', '133828'):
            self.assertEqual(rs[rid].findtext('weekday'), 'weekends', rid)
        cases = json.load(open(os.path.join(ROOT, 'tests', 'pack_cases', 'jt-file-access.json'), encoding='utf-8'))
        clocked = [c for c in cases['cases'] + cases['sequences'] if c.get('expect_by_clock')]
        self.assertGreaterEqual(len(clocked), 6)
        for c in clocked:
            self.assertEqual(str(c['expect_rule']), str(c['expect_by_clock']['day'][0]))


if __name__ == '__main__':
    unittest.main()
