"""jt-portable-detect Windows rules, checked against decoded eventchannel values.

wazuh-logtest cannot replay an eventchannel event on 4.14 (it decodes it as plain
JSON), so these rule chains are checked here, offline. Values are shaped exactly as
analysisd decodes them: two backslashes per path separator, as in the existing
test_windows_portable_rules_against_decoded_eventchannel_values.

Unlike that test, this one models analysisd's sibling order (4.14.7 rules_list.c):
children of a rule are tried level 0 first, then by level from high to low, and on a
tie in load order, built-in files first. The first child that matches wins and the
event continues below it; siblings are not tried again. That order is what made the
built-in 92032 (parent "cmd /C", level 3) take root-folder executions away from
906177 when 906177 was level 3, and what made 906180 (level 0) hide jt-malware-hash
100116. The built-in siblings modelled below are copied, condition for condition,
from the 4.14.7 ruleset files named next to them (only the ones that matter here).

Standard library only, no network, nothing outside the repository is read.
"""
import io
import os
import re
import sys
import unittest
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.join(os.path.dirname(HERE), 'packs', 'jt-portable-detect')
RULES = os.path.join(PACK, 'rules', 'zz-906100-jt_portable_rules.xml')

B = '\\\\'          # one path separator as analysisd decodes an eventchannel value
MALWARE = {'SHA256=BADBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADB'}


def p(*parts):
    return B.join(parts)


def U(*parts):
    return p('C:', 'Users', 'user', *parts)


SYS32 = p('C:', 'Windows', 'System32')


def ev(**kw):
    out = {}
    for k, v in kw.items():
        if k in ('eventID', 'providerName', 'channel', 'message', 'severityValue'):
            out['win.system.' + k] = v
        else:
            out['win.eventdata.' + k] = v
    return out


def _load_list(name):
    path = os.path.join(PACK, 'lists', name)
    keys = set()
    with io.open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith('"'):
                keys.add(line[1:line.index('"', 1)])
            else:
                keys.add(line.split(':', 1)[0])
    return keys


LISTS = {
    'etc/lists/jt-approved-portable': _load_list('jt-approved-portable'),
    'etc/lists/jt-approved-portable-hash': _load_list('jt-approved-portable-hash'),
    'etc/lists/malware_hash': MALWARE,
}


class Rule(object):
    def __init__(self, rid, level, parents, conds, lists=(), order=0, frequency=False):
        self.id, self.level, self.parents = rid, level, parents
        self.conds, self.lists, self.order, self.frequency = conds, list(lists), order, frequency

    def matches(self, e):
        if self.frequency:
            return False
        for field, rx, flags in self.conds:
            v = e.get(field)
            if v is None or not re.search(rx, v, flags):
                return False
        for field, lookup, name in self.lists:
            hit = e.get(field) in LISTS[name]
            if (lookup == 'match_key') != hit:
                return False
        return True


def _builtin(rid, level, parents, conds, order):
    return Rule(rid, level, parents, [(f, rx, 0) for f, rx in conds], order=order)


# Built-in 4.14.7 rules that are siblings of this pack's rules, in load order.
_I = re.I
BUILTIN = [
    # 0595-win-sysmon_rules.xml (children of 61600 by event ID)
    _builtin('61603', 0, ['61600'], [('win.system.eventID', r'^1$')], 100),
    _builtin('61613', 0, ['61600'], [('win.system.eventID', r'^11$')], 101),
    _builtin('61617', 0, ['61600'], [('win.system.eventID', r'^15$')], 102),
    _builtin('61650', 0, ['61600'], [('win.system.eventID', r'^22$')], 103),
    # 0800-sysmon_id_1.xml (if_group sysmon_event1 = children of 61603)
    _builtin('92000', 4, ['61603'], [('win.eventdata.parentImage', r'(?i)\\(c|w)script\.exe')], 200),
    _builtin('92025', 0, ['61603'], [('win.eventdata.originalFileName', r'(?i)reg.EXE')], 201),
    _builtin('92028', 0, ['61603'], [('win.eventdata.commandLine', r'(?i)\.(bat|cmd|lnk|pif|vbs|vbe|js|wsh|ps1)'),
                                    ('win.eventdata.originalFileName', r'(?i)powershell\.exe$')], 202),
    _builtin('92031', 3, ['61603'], [('win.eventdata.originalFileName', r'(?i)(net\.EXE|net1\.EXE)')], 203),
    _builtin('92032', 3, ['92031', '61603'], [('win.eventdata.parentImage', r'(?i)cmd\.EXE'),
                                             ('win.eventdata.parentCommandLine', r'(?i)\s\/C\s')], 204),
    _builtin('92042', 0, ['61603'], [('win.eventdata.originalFileName', r'(?i)netsh.EXE')], 205),
    _builtin('92068', 3, ['61603'], [('win.eventdata.parentCommandLine', r'(?i)PSEXESVC\.exe')], 206),
    _builtin('92069', 0, ['61603'], [('win.eventdata.parentImage', r'(?i)WmiPrvSE\.exe')], 207),
    # 0830-sysmon_id_11.xml (if_group sysmon_event_11 = children of 61613)
    _builtin('92213', 15, ['61613'], [('win.eventdata.targetFilename',
             r'(?i)[c-z]:\\\\(Users)\\\\.+\\\\AppData\\\\Local\\\\Temp\\\\.+\.(exe|com|dll|vbs|js|bat|cmd|pif|wsh|ps1|msi|vbe)')], 300),
    _builtin('92217', 6, ['61613'], [('win.eventdata.targetFilename',
             r'(?i)[c-z]:\\\\Windows\\\\.+\.(exe|com|dll|vbs|js|bat|cmd|pif|wsh|ps1|lnk|msi|vbe)$')], 301),
    _builtin('92218', 6, ['92217'], [('win.eventdata.image', r'^System$')], 302),
    _builtin('92219', 6, ['92217'], [('win.eventdata.image', r'(?i)svchost\.exe'),
                                    ('win.eventdata.targetFilename', r'(?i)[c-z]:\\\\Windows\\\\.+\.dll$')], 303),
    _builtin('92225', 6, ['61613'], [('win.eventdata.targetFilename',
             r'(?i)\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\StartUp.+\.(exe|com|dll|vbs|js|bat|cmd|pif|wsh|ps1|lnk|msi|vbe)')], 304),
    # 0575-win-base_rules.xml / 0955-WEF-baseline_rules.xml (AppLocker)
    _builtin('67012', 3, ['60010'], [('win.system.providerName', 'Microsoft-Windows-AppLocker'),
                                    ('win.system.eventID', '8003')], 400),
    _builtin('67013', 3, ['60011'], [('win.system.providerName', 'Microsoft-Windows-AppLocker'),
                                    ('win.system.eventID', '8004')], 401),
    # jt-malware-hash 1.6 (jasontools-malware-rule.xml loads before zz-906100-...)
    Rule('100112', 14, ['61603', '92025', '92028', '92042', '92069'], [],
         [('win.eventdata.hashes', 'match_key', 'etc/lists/malware_hash')], order=500),
    Rule('100116', 14, ['61600'], [('win.system.eventID', r'^29$', 0)],
         [('win.eventdata.hashes', 'match_key', 'etc/lists/malware_hash')], order=501),
]


def _load_pack():
    with io.open(RULES, encoding='utf-8') as fh:
        root = ET.fromstring('<r>' + fh.read() + '</r>')
    out = []
    for i, r in enumerate(root.iter('rule')):
        conds = []
        for f in r.findall('field'):
            rx = f.text
            if f.get('type') != 'pcre2':
                rx = rx.replace('\\.', '.')     # OS_Regex here only uses ^ $ and \.
            conds.append((f.get('name'), rx, 0))
        lists = [(l.get('field'), l.get('lookup'), l.text.strip()) for l in r.findall('list')]
        parents = [s.strip() for el in r.findall('if_sid') for s in el.text.split(',')]
        out.append(Rule(r.get('id'), int(r.get('level')), parents, conds, lists,
                        order=1000 + i, frequency=r.get('frequency') is not None))
    return out


PACK_RULES = _load_pack()


def _ordered_children(rules, parent):
    kids = [r for r in rules if parent in r.parents]
    return sorted(kids, key=lambda r: (0 if r.level == 0 else 1, -r.level, r.order))


def final_rule(parent, e, rules=None):
    """The rule analysisd reports for event e entering at parent (None: stays at parent)."""
    rules = rules if rules is not None else BUILTIN + PACK_RULES
    current = None
    node = parent
    while True:
        nxt = None
        for r in _ordered_children(rules, node):
            if r.matches(e):
                nxt = r
                break
        if nxt is None:
            return current
        current = nxt.id
        node = nxt.id


def by_id(rid):
    return [r for r in PACK_RULES if r.id == rid][0]


def field(rid, name):
    return [rx for f, rx, _ in by_id(rid).conds if f == name][0]


class TestSiblingOrder(unittest.TestCase):

    def test_root_folder_tools_started_by_cmd_psexec_or_a_script_host_still_escalate(self):
        cmd = p('C:', 'Windows', 'System32', 'cmd.exe')
        cases = [
            ('cmd /C', ev(image=p('C:', 'Tools', 'ngrok.exe'), parentImage=cmd,
                         parentCommandLine='cmd.exe /C C:\\\\Tools\\\\ngrok.exe tcp 3389'), '906176'),
            ('PsExec', ev(image=p('C:', 'Tools', 'ad.exe'), product='AnyDesk', parentImage='x',
                          parentCommandLine='C:\\\\Windows\\\\PSEXESVC.exe'), '906175'),
            ('wscript', ev(image=p('C:', 'Tools', 'todesk.exe'), product='ToDesk',
                           parentImage=p('C:', 'Windows', 'System32', 'wscript.exe')), '906179'),
            ('cmd /C, plain tool', ev(image=p('C:', 'Tools', 'tool.exe'), parentImage=cmd,
                                     parentCommandLine='cmd.exe /C C:\\\\Tools\\\\tool.exe'), '906177'),
        ]
        for name, e, want in cases:
            with self.subTest(launch=name):
                self.assertEqual(final_rule('61603', e), want)

    def test_at_level_3_the_builtin_cmd_rule_took_the_event(self):
        # documents the 3.4.1 bug the level change fixes
        old = [Rule(r.id, 3 if r.id == '906177' else r.level, r.parents, r.conds, r.lists, r.order, r.frequency)
               for r in PACK_RULES]
        e = ev(image=p('C:', 'Tools', 'ngrok.exe'), parentImage=p('C:', 'Windows', 'System32', 'cmd.exe'),
               parentCommandLine='cmd.exe /C C:\\\\Tools\\\\ngrok.exe tcp 3389')
        self.assertEqual(final_rule('61603', e, BUILTIN + old), '92032')

    def test_known_malware_hashes_reach_jt_malware_hash_first(self):
        bad = next(iter(MALWARE))
        self.assertEqual(final_rule('61600', ev(eventID='29', image='explorer.exe', hashes=bad,
                                                targetFilename=U('Downloads', 'x.pdf'))), '100116')
        self.assertEqual(final_rule('61600', ev(eventID='29', image='explorer.exe', hashes='SHA256=00',
                                                targetFilename=U('Downloads', 'x.pdf'))), '906183')
        self.assertEqual(final_rule('61603', ev(image=U('Downloads', 'x.exe'), parentImage='x', hashes=bad)), '100112')
        self.assertEqual(final_rule('61603', ev(image=U('Downloads', 'x.exe'), parentImage='WmiPrvSE.exe',
                                                hashes=bad)), '100112')

    def test_no_pack_child_lowers_an_alerting_pack_parent(self):
        """A child of a lower level replaces its parent's alert. Exclusions (level 0), the
        approval list and the WiX copy (906173) do that on purpose; nothing else may."""
        allowed = {'906140', '906141', '906142', '906173'}
        levels = {r.id: r.level for r in PACK_RULES}
        for r in PACK_RULES:
            if r.level == 0 or r.id in allowed or r.frequency:
                continue
            for parent in r.parents:
                if parent in levels and levels[parent] >= 3:
                    with self.subTest(rule=r.id, parent=parent):
                        self.assertGreaterEqual(r.level, levels[parent])


class TestNewWindowsRules(unittest.TestCase):

    def check(self, cases):
        for parent, e, want in cases:
            with self.subTest(parent=parent, event=e):
                self.assertEqual(final_rule(parent, e), want)

    def test_remote_access_tools_by_lolrmm_file_name(self):
        self.check([
            ('61603', ev(image=U('Downloads', 'ToDesk.exe'), parentImage='x'), '906179'),
            ('61603', ev(image=U('AppData', 'Local', 'Temp', 'x1', 'SunloginClient_15.exe'), parentImage='x'), '906179'),
            ('61603', ev(image=p('C:', 'ProgramData', 'NinjaRMMAgent', 'NinjaRMMAgent.exe'), parentImage='x'), '906105'),
            ('61603', ev(image=p('C:', 'ProgramData', 'JWrapper-Remote Access', 'SimpleGatewayService.exe'),
                         parentImage='x'), '906105'),
            ('61603', ev(image=p('C:', 'ProgramData', 'x', 'SimpleGatewayService.exe'), parentImage='x'), '906179'),
            ('61603', ev(image=p('C:', 'Program Files', 'ToDesk', 'ToDesk.exe'), parentImage='x'), None),
            ('61603', ev(image=U('Downloads', 'report.exe'), parentImage='x'), '906100'),
            ('61603', ev(image=U('Downloads', 'a.exe'), parentImage='x', product='Alpemix'), '906175'),
        ])

    def test_renamed_tunnels_by_command_line(self):
        pub = p('C:', 'Users', 'Public', 'svc.exe')
        self.check([
            ('61603', ev(image=pub, parentImage='x', commandLine='\\"' + pub + '\\" tcp 3389'), '906152'),
            ('61603', ev(image=pub, parentImage='x', commandLine=pub + ' tunnel run --token eyJhIjoi'), '906152'),
            ('61603', ev(image=pub, parentImage='x', commandLine=pub + ' tunnel --url http://localhost:3389'), '906152'),
            ('61603', ev(image=pub, parentImage='x', commandLine=pub + ' client 203.0.113.5:443 R:socks'), '906152'),
            ('61603', ev(image=pub, parentImage='x', commandLine=pub + ' -c frpc.toml'), '906152'),
            ('61603', ev(image=pub, parentImage='x', commandLine=pub + ' -R 4444:127.0.0.1:3389 203.0.113.5'), '906152'),
            ('61603', ev(image=U('Downloads', 'ngrok.exe'), parentImage='x', commandLine='ngrok.exe tcp 3389'), '906176'),
            ('61603', ev(image=U('Downloads', 'devtunnel.exe'), parentImage='x', commandLine='devtunnel host'), '906176'),
            ('61603', ev(image=pub, parentImage='x', commandLine=pub + ' --help'), '906100'),
            ('61603', ev(image=pub, parentImage='x', commandLine=pub + ' --port 8080'), '906100'),
            ('61603', ev(image=p('C:', 'Program Files', 'cloudflared', 'cloudflared.exe'), parentImage='x',
                         commandLine='cloudflared.exe tunnel run --token x'), None),
        ])

    def test_tunnelling_service_dns(self):
        self.check([
            ('61600', ev(eventID='22', queryName='api.trycloudflare.com', image=U('Downloads', 'x.exe')), '906153'),
            ('61600', ev(eventID='22', queryName='connect.us.ngrok-agent.com',
                         image=U('AppData', 'Roaming', 'Upd', 'svc.exe')), '906153'),
            ('61600', ev(eventID='22', queryName='usw2-data.rel.tunnels.api.visualstudio.com',
                         image=U('Downloads', 'code.exe')), '906153'),
            ('61600', ev(eventID='22', queryName='region1.v2.argotunnel.com',
                         image=p('C:', 'Program Files (x86)', 'cloudflared', 'cloudflared.exe')), '61650'),
            ('61600', ev(eventID='22', queryName='global.rel.tunnels.api.visualstudio.com',
                         image=U('AppData', 'Local', 'Programs', 'Microsoft VS Code', 'Code.exe')), '61650'),
            ('61600', ev(eventID='22', queryName='ngrok.com', image=U('Downloads', 'x.exe')), '61650'),
            ('61600', ev(eventID='22', queryName='api.rustdesk.com',
                         image=p('C:', 'Program Files', 'RustDesk', 'RustDesk.exe')), '61650'),
        ])

    def test_dual_use_tools(self):
        self.check([
            ('61603', ev(image=p('C:', 'ProgramData', 'r.exe'), parentImage='x', description='Rsync for cloud storage'), '906154'),
            ('61603', ev(image=U('Downloads', 'ipscan.exe'), parentImage='x', description='Advanced IP Scanner'), '906154'),
            ('61603', ev(image=U('Music', 'n.exe'), parentImage='x', description='Application for scanning networks'), '906154'),
            ('61603', ev(image=p('C:', 'Users', 'Public', 'a.exe'), parentImage='x', originalFileName='AdFind.exe'), '906155'),
            ('61603', ev(image=U('Downloads', 'npp.exe'), parentImage='x', description='Notepad++',
                         originalFileName='Notepad++.exe'), '906140'),
            # a level 12 location is not lowered by the level 10 tool rules
            ('61603', ev(image=p('C:', 'Windows', 'Tasks', 'r.exe'), parentImage='x',
                         description='Rsync for cloud storage'), '906174'),
            ('61603', ev(image=p('C:', 'Program Files', 'rclone', 'rclone.exe'), parentImage='x',
                         description='Rsync for cloud storage'), None),
        ])

    def test_double_extension_outlook_and_never_program_folders(self):
        outlook = U('AppData', 'Local', 'Microsoft', 'Windows', 'INetCache', 'Content.Outlook', 'AB12CD34', 'inv.exe')
        self.check([
            ('61603', ev(image=U('Downloads', 'invoice.pdf.exe'), parentImage='x'), '906156'),
            ('61603', ev(image=U('Desktop', 'photo.jpg      .exe'), parentImage='x'), '906156'),
            ('61603', ev(image=U('Downloads', 'setup-2.1.0.exe'), parentImage='x'), '906100'),
            ('61603', ev(image=outlook, parentImage='OUTLOOK.EXE'), '906157'),
            ('61603', ev(image=U('AppData', 'Local', 'Microsoft', 'Teams', 'current', 'Teams.exe'), parentImage='x'), None),
            ('61603', ev(image=p('C:', 'PerfLogs', 'x.exe'), parentImage='x'), '906158'),
            ('61603', ev(image=p('C:', 'Windows', 'Fonts', 'svc.exe'), parentImage='x'), '906158'),
            ('61603', ev(image=p('C:', 'Windows', 'IME', 'IMETC', 'x.exe'), parentImage='x'), None),
            ('61603', ev(image=p('C:', 'PerfLogsX', 'a.exe'), parentImage='x'), '906177'),
            ('61603', ev(image=p('C:', 'RECYCLER.BIN', 'x.exe'), parentImage='x'), '906178'),
            ('61603', ev(image=p('C:', 'Windows', 'Fonts', 'ngrok.exe'), parentImage='x'), '906176'),
        ])

    def test_archive_extraction_abuse(self):
        winrar = p('C:', 'Program Files', 'WinRAR', 'WinRAR.exe')
        startup = U('AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'x.lnk')
        cve = ('C:\\\\WINDOWS\\\\system32\\\\cmd.exe /c \\"\\"' +
               U('AppData', 'Local', 'Temp', 'Rar$DIa6720.18397', 'poc.png .cmd') + '\\" \\"')
        self.check([
            ('61613', ev(image=winrar, targetFilename=startup), '906159'),
            ('61613', ev(image=p('C:', 'Program Files', '7-Zip', '7zG.exe'),
                         targetFilename=p('C:', 'ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs',
                                          'StartUp', 'x.exe')), '906159'),
            ('61613', ev(image=p('C:', 'Windows', 'explorer.exe'), targetFilename=startup), None),
            ('61613', ev(image=winrar, targetFilename=U('Downloads', 'x.exe')), '906124'),
            ('61603', ev(image=p('C:', 'Windows', 'System32', 'cmd.exe'), parentImage=winrar, commandLine=cve), '906185'),
            ('61603', ev(image=p('C:', 'Windows', 'System32', 'notepad.exe'), parentImage=winrar,
                         commandLine='notepad.exe ' + U('AppData', 'Local', 'Temp', 'Rar$DIa1.2', 'readme.txt')), None),
            ('61603', ev(image=U('AppData', 'Local', 'Temp', 'Rar$DIa12.345', 't.exe'), parentImage=winrar), '906170'),
            ('61603', ev(image=U('AppData', 'Local', 'Temp', 'Rar$EXa12.345', 't.exe'), parentImage=winrar), '906170'),
            ('61603', ev(image=U('AppData', 'Local', 'Temp', 'Rarity', 't.exe'), parentImage='x'), '906102'),
        ])

    def test_executable_content_in_windows_user_writable_folders(self):
        ps = p('C:', 'WINDOWS', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
        self.check([
            ('61600', ev(eventID='29', image=ps, targetFilename=p('C:', 'Windows', 'Tasks', 'x.exe')), '906184'),
            ('61600', ev(eventID='29', image=ps, targetFilename=p('C:', 'Windows', 'System32', 'spool', 'drivers',
                                                                 'color', 'x.dll')), '906184'),
            ('61600', ev(eventID='29', image=ps, targetFilename=p('C:', 'Windows', 'Tasks', 'x.dat')), '906183'),
            ('61600', ev(eventID='29', image=p(SYS32, 'OpenSSH', 'sftp-server.exe'),
                         targetFilename=p('C:', 'Windows', 'Tasks', 'x.exe')), '906181'),
            ('61600', ev(eventID='29', image=ps, targetFilename=p('C:', 'Windows', 'Temp', 'x.exe')), '906180'),
        ])

    def test_defender_attack_surface_reduction(self):
        self.check([
            ('62101', ev(eventID='1121', iD='01443614-CD74-433A-B99E-2ECDC07BFC25', path=U('Downloads', 'x.exe')), '906186'),
            ('62100', ev(eventID='1122', iD='B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4', path='E:\\\\x.exe'), '906187'),
            ('62101', ev(eventID='1121', iD='{c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb}', path=U('Downloads', 'cmd.exe')), '906186'),
            # credential theft from LSASS: a different question, not this pack's
            ('62101', ev(eventID='1121', iD='9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2', path=SYS32), None),
            ('62101', ev(eventID='1116', iD='01443614-CD74-433A-B99E-2ECDC07BFC25'), None),
        ])

    def test_applocker_scripts_and_installers(self):
        prov = 'Microsoft-Windows-AppLocker'
        self.check([
            ('60010', ev(providerName=prov, eventID='8006'), '906112'),
            ('60011', ev(providerName=prov, eventID='8007'), '906113'),
            ('60010', ev(providerName=prov, eventID='8003'), '906110'),
            ('60010', ev(providerName='SomeApp', eventID='8006'), None),
        ])

    def test_builtin_92217_operating_system_shapes(self):
        svchost = p('C:', 'WINDOWS', 'system32', 'svchost.exe')
        msiexec = p('C:', 'Windows', 'system32', 'msiexec.exe')
        wu = p('C:', 'Windows', 'SoftwareDistribution', 'Download', 'Install')
        self.check([
            ('92217', ev(image=svchost, targetFilename=p(wu, 'AM_Delta_Patch_1.459.645.0.exe')), '906136'),
            ('92217', ev(image=svchost, targetFilename=p(wu, 'AM_Delta.exe')), '906136'),
            ('92217', ev(image=U('Downloads', 'x.exe'), targetFilename=p(wu, 'AM_Delta.exe')), None),
            ('92217', ev(image=msiexec, targetFilename=p('C:', 'Windows', 'Installer', '2af1d.msi')), '906137'),
            ('92217', ev(image=msiexec, targetFilename=p('C:', 'Windows', 'Installer', 'x.exe')), None),
        ])

    def test_download_marks_for_newer_payload_types(self):
        for ext in ('one', 'appinstaller', 'rdp', 'chm', 'xll', 'library-ms'):
            e = ev(targetFilename=U('Downloads', 'f.' + ext) + ':Zone.Identifier', contents='[ZoneTransfer]  ZoneId=3')
            with self.subTest(ext=ext):
                self.assertEqual(final_rule('61617', e), '906122')
        e = ev(targetFilename=U('Downloads', 'f.txt') + ':Zone.Identifier', contents='[ZoneTransfer]  ZoneId=3')
        self.assertIsNone(final_rule('61617', e))


class TestPatternsKeptInStep(unittest.TestCase):

    def test_archive_directories_are_the_same_in_906102_and_906170(self):
        a = re.search(r'\(\?!\\\\\|\((.*)\)\\\\\)$', field('906102', 'win.eventdata.image')).group(1)
        b = re.search(r'Temp\\\\\+\((.*)\)\\\\\+$', field('906170', 'win.eventdata.image')).group(1)
        self.assertEqual(a, b)

    def test_906152_excludes_exactly_the_names_906176_matches(self):
        names_176 = re.search(r'\\\\\+\((.*?)\)\\\.exe\$', field('906176', 'win.eventdata.image')).group(1)
        names_152 = re.search(r'\\\\\+\((.*?)\)\\\.exe\$', field('906152', 'win.eventdata.image')).group(1)
        self.assertEqual(names_176, names_152)

    def test_location_rule_children_share_one_parent_list(self):
        loc12 = by_id('906175').parents
        for rid in ('906176', '906179', '906152', '906156'):
            with self.subTest(rule=rid):
                self.assertEqual(by_id(rid).parents, loc12)
        loc10 = by_id('906154').parents
        self.assertEqual(by_id('906155').parents, loc10)
        levels = {r.id: r.level for r in PACK_RULES}
        self.assertEqual(sorted(x for x in loc12 if x not in loc10 and levels.get(x, 0) < 12), [])


if __name__ == '__main__':
    unittest.main()
