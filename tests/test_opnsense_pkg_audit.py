"""jt-opnsense 1.2.2: the agent folds pkg audit into one line for rule 131578.

The command in agent/agent.conf pipes `pkg-static audit -F` through awk
(logcollector runs commands with popen(), so through /bin/sh). These tests run
that awk program, taken verbatim from the shipped file, on output in the shape
freebsd/pkg src/audit.c prints, and check the line the decoder expects.
"""
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_CONF = os.path.join(ROOT, 'packs', 'jt-opnsense', 'agent', 'agent.conf')
DECODERS = os.path.join(ROOT, 'packs', 'jt-opnsense', 'decoders', 'jt-opnsense_decoders.xml')

REPORT = """vulnxml file up-to-date
openvpn-2.7.7 is vulnerable:
  OpenVPN -- multiple vulnerabilities
  CVE: CVE-2026-84790
  CVE: CVE-2026-88964
  WWW: https://vuxml.FreeBSD.org/freebsd/00000000-0000-0000-0000-000000000001.html

openssl35-3.5.9 is vulnerable:
  OpenSSL -- Multiple vulnerabilities
  CVE: CVE-2026-11111
  WWW: https://vuxml.FreeBSD.org/freebsd/00000000-0000-0000-0000-000000000002.html

  OpenSSL -- Denial of service
  CVE: CVE-2026-22222
  CVE: CVE-2026-11111
  WWW: https://vuxml.FreeBSD.org/freebsd/00000000-0000-0000-0000-000000000003.html

openssl-3.0.15,1 is vulnerable:
  OpenSSL -- issue without a CVE
  WWW: https://vuxml.FreeBSD.org/freebsd/00000000-0000-0000-0000-000000000004.html

4 problem(s) in 3 package(s) found.
"""


def _command():
    with open(AGENT_CONF, encoding='utf-8') as fh:
        text = re.sub(r'<!--.*?-->', '', fh.read(), flags=re.S)
    m = re.search(r'<command>(/usr/local/sbin/pkg-static audit[^<]*)</command>', text)
    return m.group(1)


@unittest.skipUnless(shutil.which('awk'), 'needs awk')
class TestPkgAuditCommand(unittest.TestCase):

    def run_awk(self, report):
        cmd = _command()
        self.assertIn(' | /usr/bin/awk ', cmd)
        program = cmd.split(' | /usr/bin/awk ', 1)[1]
        # The shell strips the single quotes around the program.
        self.assertTrue(program.startswith("'") and program.endswith("'"))
        out = subprocess.run(['awk', program[1:-1]], input=report, capture_output=True,
                             text=True, check=True).stdout
        return out

    def test_command_has_no_xml_entities_or_redirection(self):
        # os_xml does not decode entities (trap 25): "&gt;" would reach the shell.
        cmd = _command()
        self.assertNotIn('&', cmd)
        self.assertNotIn('<', cmd)

    def test_report_folds_into_one_line_with_packages_and_unique_cves(self):
        self.assertEqual(self.run_awk(REPORT),
                         '4 problem(s) in 3 package(s) found. Vulnerable: openvpn-2.7.7; '
                         'openssl35-3.5.9; openssl-3.0.15,1. CVEs: 4.\n')

    def test_clean_report(self):
        self.assertEqual(self.run_awk('vulnxml file up-to-date\n0 problem(s) in 0 package(s) found.\n'),
                         '0 problem(s) in 0 package(s) found. Vulnerable: none. CVEs: 0.\n')

    def test_pkg_1x_wording(self):
        out = self.run_awk('py311-x-1.0 is vulnerable:\n  desc\n\n1 problem(s) in 1 installed package(s) found.\n')
        self.assertEqual(out, '1 problem(s) in 1 installed package(s) found. Vulnerable: py311-x-1.0. CVEs: 0.\n')

    def test_no_summary_means_no_event(self):
        # pkg could not run or fetch: nothing is sent, as with the plain command.
        self.assertEqual(self.run_awk('pkg: cannot fetch vulnxml file\n'), '')

    def test_decoder_regex_reads_both_forms(self):
        with open(DECODERS, encoding='utf-8') as fh:
            text = fh.read()
        rx = re.search(r'<decoder name="jt-opnsense-pkg-audit">.*?<regex type="pcre2">([^<]+)</regex>',
                       text, re.S).group(1)
        new = re.search(rx, "ossec: output: 'jt-opnsense-pkg-audit': " + self.run_awk(REPORT).strip())
        self.assertEqual(new.groups(), ('4', '3', 'openvpn-2.7.7; openssl35-3.5.9; openssl-3.0.15,1', '4'))
        old = re.search(rx, "ossec: output: 'jt-opnsense-pkg-audit': 3 problem(s) in 2 package(s) found.")
        self.assertEqual(old.groups()[:2], ('3', '2'))


if __name__ == '__main__':
    unittest.main()
