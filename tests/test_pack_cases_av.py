"""Case files must not carry attack text that antivirus scanners quarantine (offline).

A user downloading the repository on Windows had tests/pack_cases/jt-docker.json
quarantined as PotentialRisk.PUA/BAT.BitCoinMin for a miner command line in a
test log line. Such lines go in "log_b64" (pack_sandbox.decode_case)."""

import base64
import glob
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
sys.dont_write_bytecode = True
import pack_sandbox as sb    # noqa: E402

BAIT = re.compile('|'.join(base64.b64decode(p).decode() for p in (   # base64 so this file is not a bait too
    'eG1yaWcgLW8=',
    'c3RyYXR1bVwrdGNwOi8v',
    'LS1kb25hdGUtbGV2ZWw=',
    'YmFzaCAtaSA+JiAvZGV2L3RjcA==',
    'dnNzYWRtaW4oXC5leGUpPyBkZWxldGUgc2hhZG93cw==',
    'c2VrdXJsc2E6Og==',
    'aW52b2tlLW1pbWlrYXR6',
    'WDVPIVAlQEFQ',
)), re.I)


class TestNoAntivirusBait(unittest.TestCase):
    def test_case_files_hold_no_plain_attack_text(self):
        for path in sorted(glob.glob(os.path.join(ROOT, 'tests', 'pack_cases', '*.json'))):
            text = open(path, encoding='utf-8').read()
            m = BAIT.search(text)
            self.assertIsNone(m, '%s: "%s" in plain text, store the line as log_b64'
                              % (os.path.basename(path), m and m.group(0)))

    def test_encoded_lines_decode_and_still_carry_the_attack(self):
        found = 0
        for path in glob.glob(os.path.join(ROOT, 'tests', 'pack_cases', '*.json')):
            data = json.load(open(path, encoding='utf-8'))
            for case in data['cases'] + data.get('sequences', []):
                if 'log_b64' in case:
                    found += 1
                    self.assertTrue(BAIT.search(sb.decode_case(case)['log']), path)
        self.assertGreaterEqual(found, 4)


if __name__ == '__main__':
    unittest.main()
