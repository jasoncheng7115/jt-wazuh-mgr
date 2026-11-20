#!/usr/bin/env python3
"""Replay real Windows events in a throwaway manager and compare the verdicts.

    tools/win_replay.py --events alerts.json [--events archives.json ...]
                        [--ruleset rules.tgz --ruleset-xml ruleset.xml]
                        [--pack jt-file-access ...] [--keep]

wazuh-logtest cannot replay Windows eventchannel events. An agent sends them to
analysisd as queue type 'f' with the event's XML, and analysisd's own
windows_eventchannel decoder builds win.system / win.eventdata from it. This
tool turns decoded events back into that XML and sends them to a container's
analysisd, so a rule change can be checked against what a site really logs.

Input (JSON lines, gzip allowed):
  * a manager's alerts.json - each Windows alert carries the decoded event and
    the rule that fired: the replay reports every event whose rule or level
    differs.
  * archives.json, or archives.log lines ending in "->EventChannel {json}" -
    events with no alert (expected: nothing at level 3 or above).

--ruleset / --ruleset-xml: a tar.gz of a manager's etc/rules, etc/decoders and
etc/lists, and its <ruleset> section, to compare against that manager's own
verdicts (built-in rules alone differ wherever a site has its own rules).
--pack adds packs from packs/ on top, which is how a candidate pack is checked
for interference before it is installed.

Known differences that are not errors: frequency rules (which event of a stream
reaches the threshold depends on order and timing), <time> / <weekday> rules,
and rules changed since the alerts were written.
"""

import argparse
import collections
import gzip
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pack_sandbox as sb    # noqa: E402

NAME = 'jtsbx-winreplay'

# Runs inside the container. Wazuh's XML parser accepts single-quoted attributes
# only (what Windows renders); double quotes make analysisd drop the event with
# "Could not read XML string".
REPLAY = r'''
import json, socket, sys, time
from xml.sax.saxutils import escape
src = json.load(open('/tmp/winreplay-in.json'))
alerts = "/var/ossec/logs/alerts/alerts.json"
def q(v):
    return "'" + escape(str(v), {"'": "&apos;", '"': "&quot;"}) + "'"
def unb(v):
    return v.replace('\\\\', '\\') if isinstance(v, str) else str(v)
def xml(win, rid):
    s = win['system']; ed = win.get('eventdata') or {}
    data = ''.join('<Data Name=%s>%s</Data>' % (q(k[0].upper() + k[1:]), escape(unb(v))) for k, v in ed.items())
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<Provider Name=%s Guid=%s/><EventID>%s</EventID><Version>%s</Version><Level>%s</Level>"
            "<Task>%s</Task><Opcode>%s</Opcode><Keywords>%s</Keywords><TimeCreated SystemTime=%s/>"
            "<EventRecordID>%d</EventRecordID><Correlation/><Execution ProcessID=%s ThreadID=%s/>"
            "<Channel>%s</Channel><Computer>%s</Computer><Security/></System><EventData>%s</EventData></Event>") % (
        q(s.get('providerName', '')), q(s.get('providerGuid', '')), escape(str(s.get('eventID', ''))),
        escape(str(s.get('version', '0'))), escape(str(s.get('level', '0'))), escape(str(s.get('task', '0'))),
        escape(str(s.get('opcode', '0'))), escape(str(s.get('keywords', '0x8000000000000000'))),
        q(s.get('systemTime', '')), rid, q(s.get('processID', '0')), q(s.get('threadID', '0')),
        escape(s.get('channel', '')), escape(s.get('computer', '')), data)
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.connect("/var/ossec/queue/sockets/queue")
with open(alerts) as fh:
    start = fh.seek(0, 2)
base = 7000000000
for i, win in enumerate(src):
    msg = unb((win['system'].get('message') or '').strip('"'))
    sock.send(("f:EventChannel:" + json.dumps({"Message": msg, "Event": xml(win, base + i)})).encode())
    time.sleep(0.02)
time.sleep(10)
got = {}
with open(alerts) as fh:
    fh.seek(start)
    for line in fh:
        try:
            a = json.loads(line)
        except ValueError:
            continue
        rid = (((a.get('data') or {}).get('win') or {}).get('system') or {}).get('eventRecordID')
        if rid and rid.isdigit() and int(rid) >= base:
            got[int(rid) - base] = [a['rule']['id'], int(a['rule']['level']), a['rule'].get('description', '')[:120]]
print(json.dumps([got.get(i) for i in range(len(src))]))
'''


def read_events(paths):
    """[(win, expected or None, origin)], expected = [rule, level] from an alert."""
    out = []
    for path in paths:
        opener = gzip.open if path.endswith('.gz') else open
        with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                i = line.find('{')
                if i < 0:
                    continue
                try:
                    obj = json.loads(line[i:])
                except ValueError:
                    continue
                if 'rule' in obj and 'data' in obj:                     # alerts.json
                    win = (obj.get('data') or {}).get('win')
                    if win:
                        out.append((win, [obj['rule']['id'], int(obj['rule']['level'])], obj.get('timestamp', '')))
                elif 'win' in obj:                                      # archives.log tail
                    out.append((obj['win'], None, ''))
                elif (obj.get('data') or {}).get('win'):                 # archives.json
                    out.append((obj['data']['win'], None, obj.get('timestamp', '')))
    return out


def prepare(args):
    sb.run(['docker', 'rm', '-f', NAME], check=False)
    sb.run(['docker', 'run', '-d', '--name', NAME, sb.IMAGE])
    sb.wait_ready(NAME)
    sb.slim(NAME)
    lists = []
    if args.ruleset:
        sb.run(['docker', 'cp', args.ruleset, NAME + ':/tmp/ruleset.tgz'])
        sb.run(['docker', 'exec', NAME, 'sh', '-c',
                'cd /var/ossec/etc && rm -rf rules decoders lists && tar xzf /tmp/ruleset.tgz && '
                'chown -R wazuh:wazuh rules decoders lists && rm /tmp/ruleset.tgz'])
    for pack in args.pack or []:
        sb.name_of(pack)
        sb.copy_pack(NAME, pack, lists)
    conf = sb.run(['docker', 'exec', NAME, 'cat', '/var/ossec/etc/ossec.conf']).stdout
    if args.ruleset_xml:
        section = open(args.ruleset_xml, encoding='utf-8').read().strip()
        conf = re.sub(r'<ruleset>.*?</ruleset>', lambda m: section, conf, count=1, flags=re.S)
    for dest in lists:
        if '<list>%s</list>' % dest not in conf:
            conf = conf.replace('</ruleset>', '  <list>%s</list>\n  </ruleset>' % dest, 1)
    # the manager's default: only alerts from level 3 reach alerts.json, as in production
    conf = re.sub(r'<log_alert_level>\d+</log_alert_level>', '<log_alert_level>3</log_alert_level>', conf)
    sb.run(['docker', 'exec', '-i', NAME, 'sh', '-c', 'cat > /var/ossec/etc/ossec.conf'], data=conf)
    check = sb.run(['docker', 'exec', NAME, '/var/ossec/bin/wazuh-analysisd', '-t'], check=False)
    bad = [l for l in (check.stdout + check.stderr).splitlines()
           if re.search(r'ERROR|CRITICAL|WARNING', l) and 'Rule tree threshold' not in l]
    if check.returncode != 0 or bad:
        raise SystemExit('ruleset check failed:\n' + '\n'.join(bad[:20]))
    sb.run(['docker', 'exec', NAME, '/var/ossec/bin/wazuh-control', 'restart'])
    sb.wait_ready(NAME)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--events', action='append', required=True)
    ap.add_argument('--ruleset', help="tar.gz of a manager's etc/rules, etc/decoders, etc/lists")
    ap.add_argument('--ruleset-xml', help="that manager's <ruleset> section")
    ap.add_argument('--pack', action='append', help='a pack from packs/ to add on top')
    ap.add_argument('--keep', action='store_true', help='leave the container running')
    ap.add_argument('--show', type=int, default=3, help='examples per difference')
    args = ap.parse_args()
    events = read_events(args.events)
    if not events:
        raise SystemExit('no Windows events in the input')
    print('%d Windows events (%d with an alert to compare)' % (len(events), sum(1 for e in events if e[1])))
    prepare(args)
    try:
        fd, tmp = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(fd, 'w') as fh:
                json.dump([e[0] for e in events], fh)
            sb.run(['docker', 'cp', tmp, NAME + ':/tmp/winreplay-in.json'])
        finally:
            os.unlink(tmp)
        r = sb.run(['docker', 'exec', NAME, '/var/ossec/framework/python/bin/python3', '-c', REPLAY])
        got = json.loads(r.stdout.strip().splitlines()[-1])
    finally:
        if not args.keep:
            sb.run(['docker', 'rm', '-f', NAME], check=False)
    same, diff, examples = 0, collections.Counter(), collections.defaultdict(list)
    for (win, want, origin), have in zip(events, got):
        w = tuple(want) if want else None
        h = (have[0], have[1]) if have else None
        if w == h:
            same += 1
            continue
        diff[(w, h)] += 1
        if len(examples[(w, h)]) < args.show:
            s = win['system']
            examples[(w, h)].append('%s %s event %s record %s %s' % (origin[:19], s.get('computer'), s.get('eventID'),
                                                                    s.get('eventRecordID'), (have or ['', 0, ''])[2]))
    print('same verdict: %d of %d' % (same, len(events)))
    for (w, h), n in diff.most_common():
        print('  %5d  original %-14s replay %s' % (n, '%s L%s' % w if w else 'none', '%s L%s' % h if h else 'none'))
        for e in examples[(w, h)]:
            print('           ' + e)
    return 0 if not diff else 1


if __name__ == '__main__':
    sys.exit(main())
