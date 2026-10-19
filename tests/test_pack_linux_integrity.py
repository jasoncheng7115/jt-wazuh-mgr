"""Invariants of the shipped agent group configurations that file integrity
rules depend on (offline: reads packs/ only).

Two things are easy to break and silent when broken:
- a diff (report_changes) of /etc/shadow, /etc/gshadow or /etc/security/opasswd
  copies password hashes into every alert and into the archives;
- an agent group that lists a directory another group also lists replaces that
  group's options on the agent (a path configured twice keeps only the last
  entry, measured on 4.14.7), so jt-linux-integrity must list files, not the
  directories a site's own group monitors.
"""
import glob
import os
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKS = os.path.join(ROOT, 'packs')
SECRET_FILES = ('/etc/shadow', '/etc/gshadow', '/etc/security/opasswd')


def _agent_confs():
    for path in sorted(glob.glob(os.path.join(PACKS, '*', 'agent', 'agent.conf'))):
        with open(path, encoding='utf-8') as fh:
            text = fh.read()
        yield path, ET.fromstring('<r>' + re.sub(r'<\?xml[^>]*\?>', '', text) + '</r>')


def _entries(root):
    for el in root.iter('directories'):
        for p in (el.text or '').split(','):
            if p.strip():
                yield p.strip(), el.attrib


def _covers(entry, target):
    """True when a <directories> entry (wildcards allowed) monitors target."""
    rx = re.escape(entry.rstrip('/')).replace(r'\*', '[^/]*').replace(r'\?', '[^/]')
    return re.fullmatch(rx + '(?:/.*)?', target) is not None


class TestAgentGroupDiffs(unittest.TestCase):

    def test_password_databases_never_get_a_diff_without_nodiff(self):
        for path, root in _agent_confs():
            nodiff = [(n.text or '').strip() for n in root.iter('nodiff') if n.get('type') != 'sregex']
            nodiff_re = [(n.text or '').strip() for n in root.iter('nodiff') if n.get('type') == 'sregex']
            for entry, attrs in _entries(root):
                if attrs.get('report_changes') != 'yes':
                    continue
                for secret in SECRET_FILES:
                    if not _covers(entry, secret):
                        continue
                    protected = secret in nodiff or any(
                        re.search(alt.replace('.', r'\.'), secret)
                        for rx in nodiff_re for alt in rx.split('|'))
                    with self.subTest(conf=os.path.relpath(path, ROOT), entry=entry, file=secret):
                        self.assertTrue(protected, 'report_changes would diff %s' % secret)

    def test_linux_integrity_lists_the_password_databases_without_diff(self):
        path = os.path.join(PACKS, 'jt-linux-integrity', 'agent', 'agent.conf')
        root = dict(_agent_confs())[path]
        seen = {}
        for entry, attrs in _entries(root):
            seen[entry] = attrs
        for secret in ('/etc/shadow', '/etc/gshadow'):
            self.assertIn(secret, seen)
            self.assertNotEqual(seen[secret].get('report_changes'), 'yes')
        nodiff = {(n.text or '').strip() for n in root.iter('nodiff')}
        for secret in SECRET_FILES:
            self.assertIn(secret, nodiff)


class TestAgentGroupPaths(unittest.TestCase):

    def test_linux_integrity_never_lists_a_directory_a_site_group_owns(self):
        """/etc, /root/.ssh, /home and similar broad directories belong to a site's
        own groups; listing one here would replace their options on the agent."""
        path = os.path.join(PACKS, 'jt-linux-integrity', 'agent', 'agent.conf')
        root = dict(_agent_confs())[path]
        broad = {'/', '/etc', '/root', '/root/.ssh', '/home', '/var', '/var/spool', '/usr', '/usr/lib',
                 '/lib', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/boot', '/tmp', '/var/tmp'}
        for entry, _ in _entries(root):
            with self.subTest(entry=entry):
                self.assertNotIn(entry.rstrip('/') or '/', broad)
                self.assertNotIn('restrict', _)

    def test_paths_shared_with_another_pack_group_carry_the_same_options(self):
        """A host in two pack groups gets whichever entry the agent reads last."""
        confs = dict(_agent_confs())
        mine_path = os.path.join(PACKS, 'jt-linux-integrity', 'agent', 'agent.conf')
        mine = {e: a for e, a in _entries(confs[mine_path])}
        for path, root in confs.items():
            if path == mine_path:
                continue
            for entry, attrs in _entries(root):
                if entry in mine:
                    with self.subTest(conf=os.path.relpath(path, ROOT), entry=entry):
                        self.assertEqual(dict(attrs), dict(mine[entry]))


if __name__ == '__main__':
    unittest.main()
