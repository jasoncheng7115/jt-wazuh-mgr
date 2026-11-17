"""tools/pack_gate.py: when the upgrade and the cluster master may take the
fresh scenario's replay instead of their own (offline, nothing is started)."""

import importlib.util
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
_spec = importlib.util.spec_from_file_location('pack_gate', os.path.join(ROOT, 'tools', 'pack_gate.py'))
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

CONF = ('<ossec_config>\n  <!-- <ruleset>commented</ruleset> -->\n  <ruleset>\n    <rule_dir>ruleset/rules</rule_dir>\n'
        '    <list>etc/lists/a</list>\n    <list>etc/lists/b</list>\n  </ruleset>\n'
        '  <log_alert_level>1</log_alert_level>\n</ossec_config>\n')


class FakeRun:
    def __init__(self, stdout):
        self.stdout = stdout


def fake_dexec(files, conf):
    def dexec(name, *cmd, **kw):
        if cmd[0] == 'cat':
            return FakeRun(conf)
        return FakeRun(''.join('%s  %s\n' % (md5, path) for path, md5 in sorted(files.items())))
    return dexec


class TestReuse(unittest.TestCase):
    def setUp(self):
        self.saved_ref = gate.REF
        gate.REF = gate.Reference()
        self.owners = {'rules/zz-1-a.xml': 'jt-a', 'rules/zz-2-b.xml': 'jt-b', 'lists/b': 'jt-b'}
        self.base = {'rules/zz-1-a.xml': '11', 'rules/zz-2-b.xml': '22', 'lists/b': '33',
                     'rules/local_rules.xml': '44'}

    def tearDown(self):
        gate.REF = self.saved_ref

    def plan(self, files, conf=CONF):
        with mock.patch.object(gate, 'dexec', fake_dexec(self.base, CONF)):
            gate.REF.fp = gate.ruleset_fingerprint('ref')
        gate.REF.fp_ready.set()
        with mock.patch.object(gate, 'dexec', fake_dexec(files, conf)), \
                mock.patch.object(gate, 'pack_of_files', lambda only: self.owners):
            return gate.reuse_plan('other', set(), '4.14.10', '4.14.10')

    def test_identical_ruleset_reuses_everything(self):
        self.assertEqual(self.plan(dict(self.base)), ('reuse', []))

    def test_list_order_and_comments_do_not_matter(self):
        conf = CONF.replace('<list>etc/lists/a</list>\n    <list>etc/lists/b</list>',
                            '<list>etc/lists/b</list>\n    <list>etc/lists/a</list>').replace(
            '<!-- <ruleset>commented</ruleset> -->', '<!-- other -->')
        self.assertEqual(self.plan(dict(self.base), conf), ('reuse', []))

    def test_a_pack_file_that_differs_is_replayed(self):
        files = dict(self.base, **{'lists/b': '99'})
        self.assertEqual(self.plan(files), ('reuse', ['jt-b']))

    def test_a_missing_or_extra_pack_file_is_replayed(self):
        files = dict(self.base)
        del files['rules/zz-1-a.xml']
        self.assertEqual(self.plan(files), ('reuse', ['jt-a']))

    def test_other_differences_replay_everything(self):
        self.assertEqual(self.plan(dict(self.base, **{'rules/local_rules.xml': '00'}))[0], 'full')
        self.assertEqual(self.plan(dict(self.base), CONF.replace('<list>etc/lists/a</list>', ''))[0], 'full')
        self.assertEqual(self.plan(dict(self.base), CONF.replace('>1<', '>3<'))[0], 'full')

    def test_other_versions_and_a_missing_reference_replay_everything(self):
        self.assertEqual(gate.reuse_plan('x', set(), '4.13.1', '4.14.10')[0], 'full')
        gate.REF.give_up()
        with mock.patch.object(gate, 'dexec', fake_dexec(self.base, CONF)):
            self.assertEqual(gate.reuse_plan('x', set(), '4.14.10', '4.14.10')[0], 'full')

    def test_replay_by_plan_merges_the_reference_and_its_own(self):
        gate.REF.replay = {'jt-a': {'passed': 5, 'total': 5, 'failures': []},
                           'jt-b': {'passed': 1, 'total': 2, 'failures': [{'i': 2}]},
                           '_sessions': {'passed': 0, 'total': 0, 'failures': []}}
        gate.REF.replay_ready.set()
        calls = []

        def fake_replay(name, only, **kw):
            calls.append(sorted(only))
            return {'jt-b': {'passed': 2, 'total': 2, 'failures': []}, '_sessions': {}}
        with mock.patch.object(gate, 'replay', fake_replay), mock.patch.object(gate, 'say', lambda m: None):
            result, how = gate.replay_by_plan('x', set(), ('reuse', ['jt-b']))
            self.assertEqual(calls, [['jt-b']])
            self.assertEqual(result['jt-b']['passed'], 2)
            self.assertEqual(result['jt-a']['passed'], 5)
            self.assertIn('reused', how)
            result, how = gate.replay_by_plan('x', {'jt-a'}, ('full', 'why'))
            self.assertEqual(calls[-1], ['jt-a'])
            self.assertIn('full', how)

    def test_a_failed_reference_replay_means_a_full_replay(self):
        gate.REF.give_up()          # the fresh scenario died: no replay to take
        with mock.patch.object(gate, 'replay', lambda name, only, **kw: {'own': True}):
            result, how = gate.replay_by_plan('x', set(), ('reuse', []))
        self.assertEqual(result, {'own': True})
        self.assertIn('failed', how)


if __name__ == '__main__':
    unittest.main()
