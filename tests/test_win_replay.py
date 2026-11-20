"""tools/win_replay.py and the "win" cases of pack_sandbox: the event XML they build (offline)."""

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location('win_replay', os.path.join(ROOT, 'tools', 'win_replay.py'))
wr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wr)
import pack_sandbox as sb    # noqa: E402

WIN = {"system": {"providerName": "Microsoft-Windows-Security-Auditing",
                  "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "eventID": "4663",
                  "keywords": "0x8020000000000000", "eventRecordID": "1", "channel": "Security",
                  "computer": "win-test", "message": "\"An attempt was made to access an object.\""},
       "eventdata": {"subjectUserName": "o'neil", "objectName": "C:\\\\Data\\\\a&b <x>.docx",
                     "accessMask": "0x1"}}


def functions(src):
    """The imports, constants and functions of an in-container script, without running it."""
    keep, block = [], False
    for line in src.splitlines():
        if line.startswith(('import ', 'from ', 'SUCCESS', 'def ')):
            block = line.startswith('def ')
            keep.append(line)
        elif block and (line.startswith((' ', '\t')) or not line.strip()):
            keep.append(line)
        else:
            block = False
    ns = {}
    exec(compile('\n'.join(keep), '<replay>', 'exec'), ns)
    return ns


class TestWinReplay(unittest.TestCase):
    def test_replay_xml_uses_single_quotes_and_halves_backslashes(self):
        f = functions(wr.REPLAY)
        x = f['xml'](WIN, 7000000001)
        self.assertNotIn('"', x.split('<EventData>')[0])      # analysisd rejects double quotes
        root = ET.fromstring(x)
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        data = {d.get('Name'): d.text for d in root.findall('.//e:Data', ns)}
        self.assertEqual(data['ObjectName'], 'C:\\Data\\a&b <x>.docx')     # one backslash, as Windows writes it
        self.assertEqual(data['SubjectUserName'], "o'neil")
        self.assertEqual(root.find('.//e:EventRecordID', ns).text, '7000000001')

    def test_sandbox_xml_is_valid_too(self):
        f = functions(sb.WIN_EVENT)
        x = f['xml']({"event_id": "4656", "failure": True,
                      "data": {"ObjectName": "C:\\Data\\a&b.docx", "SubjectUserName": "o'neil"}}, 5)
        root = ET.fromstring(x)
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        self.assertEqual(root.find('.//e:Keywords', ns).text, '0x8010000000000000')   # audit failure
        self.assertEqual({d.get('Name'): d.text for d in root.findall('.//e:Data', ns)}['ObjectName'],
                         'C:\\Data\\a&b.docx')

    def test_reads_alerts_archives_json_and_archives_log(self):
        alert = {"timestamp": "2026-11-20T10:00:00", "rule": {"id": "92154", "level": 4},
                 "data": {"win": WIN}}
        archive_json = {"timestamp": "2026-11-20T10:00:01", "data": {"win": WIN}}
        archive_log = '2026 Nov 20 10:00:02 (win10) any->EventChannel ' + json.dumps({"win": WIN})
        linux = {"rule": {"id": "5715", "level": 3}, "data": {"srcip": "192.0.2.1"}}
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as fh:
            for o in (alert, archive_json, linux):
                fh.write(json.dumps(o) + '\n')
            fh.write(archive_log + '\n')
            path = fh.name
        try:
            ev = wr.read_events([path])
        finally:
            os.unlink(path)
        self.assertEqual([e[1] for e in ev], [['92154', 4], None, None])

    def test_clock_expect(self):
        case = {"expect_rule": "1", "expect_level": 3,
                "expect_by_clock": {"day": ["1", 3], "offhours": ["2", 7], "weekend": ["3", 7]}}
        self.assertEqual(sb.clock_expect(case, 10, 3)['expect_rule'], '1')
        self.assertEqual(sb.clock_expect(case, 20, 3)['expect_rule'], '2')
        self.assertEqual(sb.clock_expect(case, 6, 3)['expect_rule'], '2')
        self.assertEqual(sb.clock_expect(case, 7, 3)['expect_rule'], '1')
        self.assertEqual(sb.clock_expect(case, 12, 6)['expect_rule'], '3')
        self.assertEqual(sb.clock_expect(case, 23, 7)['expect_rule'], '2')   # off hours first, as in the rules


if __name__ == '__main__':
    unittest.main()
