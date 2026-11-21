#!/usr/bin/env python3
"""Test a rule pack in a throwaway Wazuh manager container, never on a real one.

    tools/pack_sandbox.py up <pack-id>        start jtsbx-<pack-id> (wazuh/wazuh-manager)
    tools/pack_sandbox.py install <pack-id>   copy the pack in, declare its lists, check, restart
    tools/pack_sandbox.py test <pack-id>      run tests/pack_cases/<pack-id>.json through logtest
    tools/pack_sandbox.py down <pack-id>      remove the container
    tools/pack_sandbox.py slim <pack-id>      shrink a container started before `up` did it

A pack is tested on a live manager until now, and one syntax error there is
one restart away from a manager that does not come back. The container gives
every pack its own analysisd, so several can be developed side by side.

Case file format, tests/pack_cases/<pack-id>.json:
    {"pack": "<id>", "sandbox_lists": {"<list>": "key:value\n"},
     "cases": [{"log": "...", "location": "/var/log/x.log",
      "expect_rule": "131201", "expect_level": 5, "repeat": 1, "note": "..."}],
     "sequences": [{"before": ["line", ...], "log": "...", ...}],
     "sandbox_packs": ["jt-zimbra", ...]}   (other packs installed first)
expect_in_description (optional) lists substrings the rendered rule
description must contain, to check decoded fields that reach the alert.
with_all_packs (optional, {"expect_rule", "expect_level", "why"}) is the
result when every pack is installed (tools/pack_gate.py); ignored here.
min_wazuh (optional, "4.14") is the oldest manager a case applies to, for a
case that names a built-in rule or field older rulesets lack; pack_gate.py
skips it on older managers. on_older (optional, {"wazuh_below": "4.14",
"expect_rule", "expect_level"}) is the result an older manager gives instead,
for instance a compatibility twin of a rule; pack_gate.py judges by it there.
"log_b64" (optional) replaces "log" with the line in base64, for attack text
that antivirus scanners would quarantine the case file for (also in "before").
expect_fields (optional, {"field": "value" or null}) checks logtest's decoded fields; null
means the field must not be decoded.
expect_rule "none" means no rule above level 0 may match. repeat sends the
line that many times in one logtest session (for frequency rules) and judges
the last event; "before" lines (or a "log" holding several lines) run first
in the same session. A "before" entry may also be {"log": "...", "location":
"..."}, for correlations across hosts or files (wazuh-logtest -l gives one
location to a whole session, so such cases go through the logtest socket).

File integrity rules cannot be replayed by wazuh-logtest (syscheck events never
pass the decoders). A case with "fim" instead of "log" is sent as a syscheck
event to analysisd's own queue and judged by the alert it produces:
    {"fim": {"path": "/etc/pam.d/sudo", "type": "added|modified|deleted",
             "sha256": "...", "changed": ["size", "sha256"], "diff": "...",
             "process": "/usr/bin/vim", "perm": "rw-r--r--", "size": 120, "tags": "x"},
     "expect_rule": "100938", "expect_level": 13}
The sandbox logs alerts from level 1, so a quiet level-1/2 rule can be named;
"none" means no alert at all (the event ended at level 0 or matched nothing).
"before" lines of a fim case go into the same live analysisd first (for a
correlation such as "updater started, then the binary changed").

Windows eventchannel events cannot be replayed by wazuh-logtest either (it
decodes them as plain JSON). A case with "win" is sent the way an agent sends
it: queue type f, the event as XML, decoded by analysisd's own
windows_eventchannel decoder (one backslash in the XML becomes two in
win.eventdata, as on a real agent):
    {"win": {"event_id": "4663", "channel": "Security",
             "provider": "Microsoft-Windows-Security-Auditing",
             "failure": false, "data": {"SubjectUserName": "alice", ...}},
     "repeat": 1, "isolate": false, "expect_rule": "133820", "expect_level": 3}
"before" entries are merged over "win" and sent first; "agent": ["001", "win-a"]
in a spec makes it that agent's event (for <different_location />). analysisd
is live, so frequency counters and ignore windows outlast a case: "isolate":
true appends a random suffix to SubjectUserName and moves a 10.x IpAddress to a
random 10.x.y network for that run. "expect_any": true accepts the expected rule
from any event of the sequence (analysisd's threads do not keep the order, so
which event of a cross-host frequency sequence fires can shift).

expect_by_clock ({"day": [rule, level], "offhours": [...], "weekend": [...]})
is for rules with <time> / <weekday>: the expectation is chosen from the
manager container's clock (off hours 20:00-07:00 before weekends).
"""

import json
import os
import random
import re
import subprocess
import sys
import time

IMAGE = os.environ.get('JT_SANDBOX_IMAGE', 'wazuh/wazuh-manager:4.14.7')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OSSEC = '/var/ossec'


def run(cmd, data=None, check=True):
    r = subprocess.run(cmd, input=data, capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit('command failed: %s' % ' '.join(cmd))
    return r


def name_of(pack):
    if not re.match(r'^[a-z0-9][a-z0-9._-]{0,63}$', pack):
        raise SystemExit('invalid pack id')
    return 'jtsbx-' + pack


def wait_ready(name, seconds=180):
    end = time.time() + seconds
    while time.time() < end:
        r = run(['docker', 'exec', name, OSSEC + '/bin/wazuh-control', 'status'], check=False)
        if 'wazuh-analysisd is running' in r.stdout:
            break
        time.sleep(3)
    else:
        raise SystemExit('analysisd did not start in %s' % name)
    # "running" comes before logtest answers: the first cases after a restart
    # used to come back as "no match".
    while time.time() < end:
        r = run(['docker', 'exec', '-i', name, OSSEC + '/bin/wazuh-logtest'],
                data='jt sandbox readiness probe\n', check=False)
        if 'Phase 1: Completed pre-decoding' in r.stdout + r.stderr:
            return
        time.sleep(2)
    raise SystemExit('logtest did not answer in %s' % name)


def slim(name):
    """Switch off what rule tests never use and that fills the disk.

    On first start the manager image unpacks its vulnerability feed (a 3 GB
    tar plus the database built from it) and queues events for an indexer it
    does not have: 9 to 14 GB per container. Ten sandboxes side by side filled
    the root disk of a shared machine. Analysis, decoders, rules and logtest do
    not depend on either.
    """
    conf = run(['docker', 'exec', name, 'cat', OSSEC + '/etc/ossec.conf']).stdout
    for block in ('vulnerability-detection', 'indexer'):
        # Confined to the block: once it already says "no", an unconfined .*?
        # ran on to the next <enabled>yes in the file and switched logtest off.
        conf = re.sub(r'(<%s>(?:(?!</%s>).)*?<enabled>)yes(</enabled>)' % (block, block),
                      r'\1no\2', conf, count=1, flags=re.S)
    run(['docker', 'exec', '-i', name, 'sh', '-c', 'cat > %s/etc/ossec.conf' % OSSEC], data=conf)
    run(['docker', 'exec', name, 'sh', '-c',
         'rm -rf %s/tmp/vd_* %s/queue/vd/* %s/queue/indexer/*' % (OSSEC, OSSEC, OSSEC)], check=False)
    run(['docker', 'exec', name, OSSEC + '/bin/wazuh-control', 'restart'])
    wait_ready(name)


def up(pack):
    name = name_of(pack)
    run(['docker', 'rm', '-f', name], check=False)
    run(['docker', 'run', '-d', '--name', name, IMAGE])
    wait_ready(name)
    slim(name)
    print('%s is running' % name)


def copy_pack(name, pack, lists):
    """Copy one pack's rule, decoder and list files into the container."""
    pdir = os.path.join(ROOT, 'packs', pack)
    with open(os.path.join(pdir, 'manifest.json'), encoding='utf-8') as fh:
        manifest = json.load(fh)
    for entry in manifest.get('files', []):
        sub = {'rule': 'rules', 'list': 'lists'}.get(entry['type'], 'decoders')
        dest = OSSEC + '/' + entry['dest']
        run(['docker', 'cp', os.path.join(pdir, sub, entry['name']), '%s:%s' % (name, dest)])
        run(['docker', 'exec', name, 'chown', 'wazuh:wazuh', dest])
        if entry['type'] == 'list' and entry.get('declare'):
            lists.append(entry['dest'])
    return manifest


def install(pack):
    name = name_of(pack)
    lists = []
    # A pack that correlates other packs' events (jt-account-guard) names them in
    # its case file as "sandbox_packs"; they go in first, the pack itself last.
    cases_path = os.path.join(ROOT, 'tests', 'pack_cases', pack + '.json')
    partners = []
    if os.path.isfile(cases_path):
        with open(cases_path, encoding='utf-8') as fh:
            partners = json.load(fh).get('sandbox_packs') or []
    for other in partners:
        if other != pack:
            name_of(other)          # validates the id
            copy_pack(name, other, lists)
    manifest = copy_pack(name, pack, lists)
    conf = run(['docker', 'exec', name, 'cat', OSSEC + '/etc/ossec.conf']).stdout
    # fim cases are judged from alerts.json; log quiet levels too (logtest is unaffected)
    conf = re.sub(r'<log_alert_level>\d+</log_alert_level>', '<log_alert_level>1</log_alert_level>', conf, count=1)
    for rel in lists:
        tag = '<list>%s</list>' % rel
        if tag not in conf:
            conf = conf.replace('</ruleset>', '  %s\n  </ruleset>' % tag, 1)
    run(['docker', 'exec', '-i', name, 'sh', '-c', 'cat > %s/etc/ossec.conf' % OSSEC], data=conf)
    # Entries a case file wants in a list for the test only (a site's allowlist).
    if os.path.isfile(cases_path):
        with open(cases_path, encoding='utf-8') as fh:
            extra = json.load(fh).get('sandbox_lists') or {}
        for list_name, body in extra.items():
            if not re.match(r'^[A-Za-z0-9._-]+$', list_name):
                raise SystemExit('invalid list name in sandbox_lists')
            run(['docker', 'exec', '-i', name, 'sh', '-c',
                 'cat >> %s/etc/lists/%s' % (OSSEC, list_name)], data=body)
    check = run(['docker', 'exec', name, OSSEC + '/bin/wazuh-analysisd', '-t'], check=False)
    # Warnings fail too: a clean manager prints none, and the ones a pack causes
    # mean part of it is ignored (an if_matched_sid with a list of IDs drops the
    # whole rule with nothing but a warning).
    bad = [l for l in (check.stdout + check.stderr).splitlines()
           if re.search(r'ERROR|CRITICAL|WARNING', l)]
    if check.returncode != 0 or bad:
        print('\n'.join(bad) or check.stderr)
        raise SystemExit('ruleset check failed')
    run(['docker', 'exec', name, OSSEC + '/bin/wazuh-control', 'restart'])
    wait_ready(name)
    print('installed %s %s%s (%d lists declared), ruleset check passed'
          % (pack, manifest.get('version', ''),
             ' with ' + ', '.join(partners) if partners else '', len(lists)))


def logtest(name, lines, location=None):
    cmd = ['docker', 'exec', '-i', name, OSSEC + '/bin/wazuh-logtest']
    if location:
        cmd += ['-l', location]
    r = run(cmd, data='\n'.join(lines) + '\n', check=False)
    out = r.stdout + r.stderr          # wazuh-logtest prints its results on stderr
    events = out.split('**Phase 1: Completed pre-decoding.')[1:]
    results = []
    for ev in events:
        phase3 = ev.split('**Phase 3: Completed filtering (rules).')
        if len(phase3) < 2:
            results.append(('none', 0, '', phase3[0]))
            continue
        rid = re.search(r"\tid: '(\d+)'", phase3[1])
        lvl = re.search(r"\tlevel: '(\d+)'", phase3[1])
        desc = re.search(r"\tdescription: '(.*)'", phase3[1])
        results.append((rid.group(1) if rid else 'none', int(lvl.group(1)) if lvl else 0,
                        desc.group(1) if desc else '', phase3[0]))
    return results


# Runs inside the container with the manager's own Python: one logtest
# session over the socket, each event with its own location.
SOCKET_LOGTEST = r'''
import json, socket, struct, sys
def req(msg):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('/var/ossec/queue/sockets/logtest')
    data = json.dumps(msg).encode()
    s.sendall(struct.pack('<I', len(data)) + data)
    size = struct.unpack('<I', s.recv(4))[0]
    buf = b''
    while len(buf) < size:
        buf += s.recv(size - len(buf))
    s.close()
    return json.loads(buf)
token = None
for line in sys.stdin:
    ev = json.loads(line)
    p = {'event': ev['log'], 'log_format': 'syslog', 'location': ev['location']}
    if token:
        p['token'] = token
    d = req({'version': 1, 'origin': {'name': 'jt-sandbox', 'module': 'jt-sandbox'},
             'command': 'log_processing', 'parameters': p}).get('data', {})
    token = d.get('token', token)
    rule = (d.get('output') or {}).get('rule') or {}
    print(json.dumps([str(rule.get('id', 'none')), int(rule.get('level', 0) or 0),
                      rule.get('description', '')]))
'''


def logtest_located(name, events):
    """events: [(location, line), ...] in one session; returns the results per event."""
    data = ''.join(json.dumps({'log': line, 'location': loc}) + '\n' for loc, line in events)
    r = run(['docker', 'exec', '-i', name, OSSEC + '/framework/python/bin/python3', '-c',
             SOCKET_LOGTEST], data=data, check=False)
    results = []
    for line in r.stdout.splitlines():
        try:
            results.append(tuple(json.loads(line)))
        except ValueError:
            pass
    if not results:
        sys.stderr.write(r.stderr[-500:])
    return results


# Runs inside the container: one syscheck event into analysisd's queue, then the
# alert for that path (or nothing) from alerts.json.
FIM_EVENT = r'''
import json, socket, sys, time
spec, wait = json.loads(sys.argv[1]), float(sys.argv[2])
path, kind = spec["path"], spec.get("type", "added")
alerts = "/var/ossec/logs/alerts/alerts.json"
with open(alerts) as fh:
    start = fh.seek(0, 2)
attrs = {"type": "file", "size": spec.get("size", 120), "perm": spec.get("perm", "rw-r--r--"),
         "uid": "0", "gid": "0", "user_name": "root", "group_name": "root", "inode": 4242,
         "mtime": int(time.time()), "hash_md5": "1" * 32, "hash_sha1": "2" * 40,
         "hash_sha256": spec.get("sha256", "3" * 64), "checksum": "4" * 40}
data = {"path": path, "version": 2.0, "mode": spec.get("mode", "realtime"), "type": kind,
        "timestamp": int(time.time()), "attributes": attrs}
if kind == "modified":
    changed = spec.get("changed") or ["size", "md5", "sha1", "sha256"]
    old = dict(attrs)
    for c in changed:
        if c == "size": old["size"] = attrs["size"] + 1
        elif c in ("md5", "sha1", "sha256"): old["hash_" + c] = "0" * len(attrs["hash_" + c])
        elif c == "mtime": old["mtime"] = attrs["mtime"] - 86400
        elif c == "permission": old["perm"] = "rwxrwxrwx"
        elif c in ("uid", "gid", "inode"): old[c] = "1" if c != "inode" else 4241
    data["old_attributes"], data["changed_attributes"] = old, changed
if spec.get("diff"):
    data["content_changes"] = spec["diff"]
if spec.get("tags"):
    data["tags"] = spec["tags"]          # <directories tags="..."> on the agent; rules see it as "tag"
if spec.get("process"):
    data["audit"] = {"user_id": "0", "user_name": "root", "process_name": spec["process"],
                     "process_id": 4242, "ppid": 1, "effective_uid": "0", "effective_name": "root",
                     "group_id": "0", "group_name": "root", "audit_uid": "1000", "audit_name": "admin1",
                     "parent_name": "/usr/bin/bash", "parent_cwd": "/root", "cwd": "/root"}
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.connect("/var/ossec/queue/sockets/queue")
# log lines that must be in analysisd's correlation memory first ("1:" = a
# log line, as logcollector sends it); logtest sessions never reach it
for ev in spec.get("before") or []:
    if isinstance(ev, str):
        ev = {"log": ev}
    s.send(("1:%s:%s" % (ev.get("location") or "jt-sandbox", ev["log"])).encode())
    time.sleep(0.3)
if spec.get("before"):
    time.sleep(1)
s.send(("8:syscheck:" + json.dumps({"type": "event", "data": data})).encode())
end = time.time() + wait
while time.time() < end:
    time.sleep(0.5)
    with open(alerts) as fh:
        fh.seek(start)
        for line in fh:
            try:
                a = json.loads(line)
            except ValueError:
                continue
            if (a.get("syscheck") or {}).get("path") == path:
                r = a.get("rule", {})
                print(json.dumps([str(r.get("id")), int(r.get("level", 0)), r.get("description", "")]))
                sys.exit(0)
print(json.dumps(["none", 0, ""]))
'''


def fim_case(name, spec, expect_alert):
    # an expected alert gets time under load; a quiet one only needs to stay quiet
    wait = '15' if expect_alert else '4'
    r = run(['docker', 'exec', name, OSSEC + '/framework/python/bin/python3', '-c', FIM_EVENT,
             json.dumps(spec), wait], check=False)
    try:
        return [tuple(json.loads(r.stdout.strip().splitlines()[-1]))]
    except (ValueError, IndexError):
        sys.stderr.write(r.stderr[-500:])
        return []


# Runs inside the container: Windows eventchannel events into analysisd's queue, then the
# alert for the last one (or nothing). wazuh-logtest cannot replay these (it decodes them as
# plain JSON); the agent sends the event's XML with queue type 'f', and analysisd's own
# windows_eventchannel decoder builds win.system / win.eventdata from it, as in production
# (one backslash in the XML becomes two in win.eventdata, the same as on a real agent).
WIN_EVENT = r'''
import json, socket, sys, time, random
from xml.sax.saxutils import escape
specs, wait = json.loads(sys.argv[1]), float(sys.argv[2])
alerts = "/var/ossec/logs/alerts/alerts.json"
with open(alerts) as fh:
    start = fh.seek(0, 2)
SUCCESS, FAILURE = "0x8020000000000000", "0x8010000000000000"
def xml(spec, rid):
    data = "".join("<Data Name='%s'>%s</Data>" % (k, escape(str(v))) for k, v in (spec.get("data") or {}).items())
    kw = spec.get("keywords") or (FAILURE if spec.get("failure") else SUCCESS)
    if spec.get("sysmon"):     # Sysmon/Operational: no audit keywords, Level 4 (information)
        spec = dict({"provider": "Microsoft-Windows-Sysmon", "guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
                     "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "version": "5",
                     "task": spec.get("event_id", "1")}, **spec)
        kw = spec.get("keywords") or "0x8000000000000000"
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<Provider Name='%s' Guid='%s'/><EventID>%s</EventID><Version>%s</Version>"
            "<Level>%s</Level><Task>%s</Task><Opcode>0</Opcode><Keywords>%s</Keywords>"
            "<TimeCreated SystemTime='2026-11-21T00:00:00.0000000Z'/><EventRecordID>%d</EventRecordID><Correlation/>"
            "<Execution ProcessID='4' ThreadID='8'/><Channel>%s</Channel><Computer>%s</Computer><Security/></System>"
            "<EventData>%s</EventData></Event>") % (
        escape(spec.get("provider", "Microsoft-Windows-Security-Auditing")),
        escape(spec.get("guid", "{54849625-5478-4994-a5ba-3e3b0328c30d}")), spec.get("event_id", "4663"),
        spec.get("version", "1"), spec.get("level", "0"), spec.get("task", "12800"), kw, rid,
        escape(spec.get("channel", "Security")), escape(spec.get("computer", "win-sandbox")), data)
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.connect("/var/ossec/queue/sockets/queue")
base = random.randint(10 ** 8, 9 * 10 ** 8)
for i, spec in enumerate(specs):
    msg = {"Message": spec.get("message", "jt-sandbox event"), "Event": xml(spec, base + i)}
    # "agent": [id, name] makes it that agent's event (only while no agent is registered,
    # as in a fresh sandbox), for rules with <different_location /> or per-agent counting
    loc = "[%s] (%s) any->EventChannel" % tuple(spec["agent"]) if spec.get("agent") else "EventChannel"
    s.send(("f:%s:%s" % (loc, json.dumps(msg))).encode())
    time.sleep(0.1)
last = str(base + len(specs) - 1)
ours = set(str(base + i) for i in range(len(specs)))
end = time.time() + wait
while time.time() < end:
    time.sleep(0.5)
    seen = []          # every rule the case's events raised: analysisd runs several threads,
    found = None       # so which event of a frequency sequence fires is not fixed (expect_any)
    with open(alerts) as fh:
        fh.seek(start)
        for line in fh:
            try:
                a = json.loads(line)
            except ValueError:
                continue
            rid = (((a.get("data") or {}).get("win") or {}).get("system") or {}).get("eventRecordID")
            if rid in ours:
                r = a.get("rule", {})
                seen.append([str(r.get("id")), int(r.get("level", 0)), r.get("description", "")])
                if rid == last:
                    found = seen[-1]
    if found:
        print(json.dumps(found + [seen]))
        sys.exit(0)
print(json.dumps(["none", 0, "", seen]))
'''


def win_case(name, specs, expect_alert, isolate=False):
    # analysisd is live: frequency counters and ignore windows outlast a case (and a run).
    # "isolate": true gives the case's account a fresh name each run, so it counts alone.
    if isolate:
        tag = '-%06x' % random.randrange(16 ** 6)
        net = '10.%d.%d.' % (random.randrange(1, 255), random.randrange(1, 255))
        def fresh(s):
            data = dict(s.get('data') or {})
            data['SubjectUserName'] = data.get('SubjectUserName', 'user') + tag
            if str(data.get('IpAddress', '')).startswith('10.'):      # same_field on the address
                data['IpAddress'] = net + data['IpAddress'].rsplit('.', 1)[1]
            return dict(s, data=data)
        specs = [fresh(s) for s in specs]
    wait = '15' if expect_alert else '4'
    r = run(['docker', 'exec', name, OSSEC + '/framework/python/bin/python3', '-c', WIN_EVENT,
             json.dumps(specs), wait], check=False)
    try:
        return [tuple(json.loads(r.stdout.strip().splitlines()[-1]))]
    except (ValueError, IndexError):
        sys.stderr.write(r.stderr[-500:])
        return []


# A case whose outcome depends on the manager's clock (<time>, <weekday> rules) gives
# "expect_by_clock": {"day": [rule, level], "offhours": [...], "weekend": [...]}.
# Off hours are 20:00-07:00 and take precedence over the weekend, as in the rules.
def clock_expect(case, hour, isoweekday):
    c = case.get('expect_by_clock')
    if not c:
        return case
    if (hour >= 20 or hour < 7) and 'offhours' in c:
        pick = c['offhours']
    elif isoweekday >= 6 and 'weekend' in c:
        pick = c['weekend']
    else:
        pick = c['day']
    return dict(case, expect_rule=str(pick[0]), expect_level=pick[1])


def container_clock(name):
    r = run(['docker', 'exec', name, 'date', '+%H %u'], check=False)
    h, d = r.stdout.split()
    return int(h), int(d)


def decode_case(case):
    """"log_b64" holds a line in base64: attack text that antivirus scanners quarantine
    (miner command lines, reverse shells, shadow copy deletion) stays out of the file
    in plain text. Decoded here, before anything reads "log"."""
    import base64
    c = dict(case)
    if 'log_b64' in c:
        c['log'] = base64.b64decode(c.pop('log_b64')).decode('utf-8')
    if c.get('before'):
        c['before'] = [dict(b, log=base64.b64decode(b['log_b64']).decode('utf-8'))
                       if isinstance(b, dict) and 'log_b64' in b else b for b in c['before']]
    return c


def test(pack):
    name = name_of(pack)
    with open(os.path.join(ROOT, 'tests', 'pack_cases', pack + '.json'), encoding='utf-8') as fh:
        data = json.load(fh)
    # "sequences" are cases whose "before" lines run first in the same session.
    cases = [decode_case(c) for c in data['cases'] + data.get('sequences', [])]
    failed = 0
    for i, case in enumerate(cases, 1):
        before = case.get('before', [])
        if 'fim' in case:
            spec = dict(case['fim'], before=before) if before else case['fim']
            results = fim_case(name, spec, str(case['expect_rule']) != 'none')
        elif 'win' in case:
            # "before": earlier Windows events (dicts like "win"); "repeat": send "win" N times
            specs = [dict(case['win'], **b) for b in before] + [case['win']] * int(case.get('repeat', 1))
            results = win_case(name, specs, str(case['expect_rule']) != 'none', case.get('isolate'))
            if case.get('expect_any') and results:
                # "expect_any": the expected rule from any event of the sequence counts
                hit = [s for s in results[-1][3] if s[0] == str(case['expect_rule'])]
                if hit:
                    results = [tuple(hit[0])]
        elif any(isinstance(b, dict) for b in before):
            default = case.get('location') or 'jt-sandbox'
            events = [(b.get('location') or default, b['log']) if isinstance(b, dict) else (default, b)
                      for b in before]
            events += [(default, case['log'])] * int(case.get('repeat', 1))
            results = logtest_located(name, events)
        else:
            lines = list(before) + [case['log']] * int(case.get('repeat', 1))
            results = logtest(name, lines, case.get('location'))
        got = results[-1] if results else ('none', 0, '')
        if case.get('expect_by_clock'):
            case = clock_expect(case, *container_clock(name))
        got_rule, got_level, desc = got[:3]
        decoded = got[3] if len(got) > 3 else None
        want_rule, want_level = str(case['expect_rule']), case.get('expect_level')
        if want_rule == 'none':
            ok = got_level == 0
        else:
            ok = got_rule == want_rule and (want_level is None or got_level == want_level)
        # expect_in_description: substrings the rendered description must contain,
        # which is how a case checks decoded fields that reach the alert text.
        missing = [t for t in case.get('expect_in_description', []) if t not in (desc or '')]
        if missing:
            ok = False
            desc = 'missing in description: %s | %s' % (missing, desc)
        # expect_fields: decoded fields from logtest's phase 2, {"field": "value"}, or null for
        # "must not be decoded". Only for plain logtest cases (fim and located cases have no phase 2).
        for field, want in (case.get('expect_fields') or {}).items():
            m = re.search(r"\t%s: '(.*)'" % re.escape(field), decoded or '') if decoded is not None else None
            have = m.group(1) if m else None
            if decoded is None or have != want:
                ok = False
                desc = 'field %s: want %r, decoded %r | %s' % (field, want, have, desc)
        failed += not ok
        print('%s %2d  want %-7s L%-3s got %-7s L%-3s %s'
              % ('ok  ' if ok else 'FAIL', i, want_rule, want_level if want_level is not None else '-',
                 got_rule, got_level, (desc or case.get('note', ''))[:90]))
    print('\n%d of %d cases passed' % (len(cases) - failed, len(cases)))
    return 1 if failed else 0


def down(pack):
    run(['docker', 'rm', '-f', name_of(pack)], check=False)
    print('removed %s' % name_of(pack))


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ('up', 'install', 'test', 'down', 'slim'):
        raise SystemExit(__doc__)
    action, pack_id = sys.argv[1], sys.argv[2]
    actions = {'up': up, 'install': install, 'test': test, 'down': down,
               'slim': lambda p: slim(name_of(p))}
    sys.exit(actions[action](pack_id) or 0)
