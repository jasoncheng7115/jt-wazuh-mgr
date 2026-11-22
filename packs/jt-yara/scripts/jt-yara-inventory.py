#!/usr/bin/env python3
"""jt-yara-inventory: which hosts should scan with YARA and do not report that they do.

Every host with jt-yara installed writes a status line once a day (jt-yara-status, rule
133430). This script, run hourly on every cluster node, reads this node's alerts.json from
where the last run stopped, remembers when each agent last reported, and sends:

  silent      an expected host has not reported for silent_hours (default 36)     -> 133441
  missing     an expected host has never reported since the check began           -> 133442
  unexpected  a host reports but is not expected (it would not be checked)        -> 133443
  back        a host that was silent or missing reports again                     -> 133444
  error       the check could not run                                             -> 133449

Expected hosts: members of the agent group "yara", plus the agent names listed as
    expected = host1, host2
in <wazuh>/etc/jt-packs/jt-yara.conf (a list needs no agent restart; a group does). Only agents
this node serves and that are connected are judged: a disconnected agent is a different problem.
silent and missing are repeated once a day while they last, unexpected once a week.

Read only: wazuh-db is asked with SELECT through its socket, alerts.json is read.
    --list     print what would be reported and the last status of each host, send nothing
    --dry-run  print the events instead of sending them, keep no state
"""

import argparse
import json
import os
import re
import socket
import struct
import sys
import time

VERSION = '1.0'
PROG = 'jt-yara-inventory'
LOCATION = 'jt-yara-inventory'
GROUP = 'yara'
SILENT_HOURS = 36
REMIND = {'silent': 86400, 'missing': 86400, 'unexpected': 7 * 86400}
ALERTS_FIRST_READ = 512 << 20


def log(msg):
    print('%s: %s' % (PROG, msg), file=sys.stderr)


def wdb_query(path, query):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    try:
        s.connect(path)
        body = query.encode('utf-8')
        s.sendall(struct.pack('<I', len(body)) + body)
        head = b''
        while len(head) < 4:
            chunk = s.recv(4 - len(head))
            if not chunk:
                raise OSError('wazuh-db closed the connection')
            head += chunk
        size = struct.unpack('<I', head)[0]
        data = b''
        while len(data) < size:
            chunk = s.recv(min(65536, size - len(data)))
            if not chunk:
                raise OSError('wazuh-db closed the connection')
            data += chunk
    finally:
        s.close()
    text = data.decode('utf-8', 'replace')
    status, _, payload = text.partition(' ')
    if status != 'ok':
        raise OSError('wazuh-db: %s' % text[:200])
    return json.loads(payload or '[]')


def local_node(wazuh):
    """This node's cluster name, or None when the cluster is disabled."""
    try:
        with open(os.path.join(wazuh, 'etc', 'ossec.conf'), encoding='utf-8', errors='replace') as fh:
            conf = fh.read()
    except OSError:
        return None
    m = re.search(r'<cluster>(.*?)</cluster>', re.sub(r'<!--.*?-->', '', conf, flags=re.S), re.S)
    if not m or re.search(r'<disabled>\s*yes\s*</disabled>', m.group(1)):
        return None
    n = re.search(r'<node_name>\s*([^<\s]+)\s*</node_name>', m.group(1))
    return n.group(1) if n else None


def agents(wdb):
    rows = wdb_query(wdb, 'global sql SELECT id, name, node_name, connection_status, '
                          '"group" AS groups FROM agent')
    out = []
    for a in rows:
        aid = int(a.get('id', -1))
        if aid <= 0:
            continue
        groups = [g.strip() for g in str(a.get('groups') or '').split(',') if g.strip()]
        out.append({'id': '%03d' % aid, 'name': a.get('name') or '', 'node': a.get('node_name') or '',
                    'status': a.get('connection_status') or '', 'groups': groups})
    return out


def read_conf(wazuh):
    conf = {'expected': set(), 'silent_hours': SILENT_HOURS}
    path = os.path.join(wazuh, 'etc', 'jt-packs', 'jt-yara.conf')
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip()
                if '=' not in line:
                    continue
                key, value = (x.strip() for x in line.split('=', 1))
                if key == 'expected':
                    conf['expected'] |= {n.strip() for n in value.split(',') if n.strip()}
                elif key == 'silent_hours' and value.isdigit() and int(value) >= 25:
                    conf['silent_hours'] = int(value)
    except OSError:
        pass
    return conf


# ---------------------------------------------------------------- reading alerts.json

STATUS = re.compile(rb'"yara"\s*:\s*\{[^\n]*?"level"\s*:\s*"STATUS"')
NAME_FIELD = re.compile(rb'"agent"\s*:\s*\{\s*"id"\s*:\s*"\d+"\s*,\s*"name"\s*:\s*"([^"]+)"')
TS_FIELD = re.compile(rb'^\{\s*"timestamp"\s*:\s*"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)')
STATE_FIELD = re.compile(rb'"yara"\s*:\s*\{[^\n]*?"state"\s*:\s*"(\w+)"')


def _alert_lines(path, start, gz=False):
    import gzip
    with (gzip.open if gz else open)(path, 'rb') as fh:
        if gz:
            left = start
            while left > 0:
                chunk = fh.read(min(left, 1 << 20))
                if not chunk:
                    return
                left -= len(chunk)
        else:
            fh.seek(start)
        pos = start
        for raw in fh:
            if not raw.endswith(b'\n'):
                return
            pos += len(raw)
            yield pos, raw


def note_line(raw, seen):
    if b'"STATUS"' not in raw or not STATUS.search(raw):
        return
    n, t = NAME_FIELD.search(raw), TS_FIELD.search(raw)
    if not (n and t):
        return
    try:
        ts = int(time.mktime(time.strptime(t.group(1).decode(), '%Y-%m-%dT%H:%M:%S')))
    except ValueError:
        return
    name = n.group(1).decode('utf-8', 'replace')
    st = STATE_FIELD.search(raw)
    if ts >= seen.get(name, {}).get('ts', 0):
        seen[name] = {'ts': ts, 'state': st.group(1).decode() if st else '?'}


def scan_alerts(wazuh, pos, seen, now):
    """Read alerts.json from the last offset (finishing a rotated day from its hard link or .gz).
    Returns (new pos, since): since is when the reading became gapless."""
    path = os.path.join(wazuh, 'logs', 'alerts', 'alerts.json')
    st = os.stat(path)
    pos = pos or {}
    since = pos.get('since', now)
    if not pos:
        offset = max(0, st.st_size - ALERTS_FIRST_READ)
        if offset:
            with open(path, 'rb') as fh:
                fh.seek(offset)
                offset += len(fh.readline())
        since = now
    elif pos.get('inode') != st.st_ino:
        finished = False
        try:
            day = time.strptime(pos.get('day', ''), '%Y-%m-%d')
            base = os.path.join(wazuh, 'logs', 'alerts', time.strftime('%Y', day), time.strftime('%b', day),
                                'ossec-alerts-%s.json' % time.strftime('%d', day))
        except ValueError:
            base = None
        for cand, gz in (((base, False), (base + '.gz', True)) if base else ()):
            try:
                if not gz and os.stat(cand).st_ino != pos.get('inode'):
                    continue
                for _, raw in _alert_lines(cand, pos.get('offset', 0), gz):
                    note_line(raw, seen)
                finished = True
                break
            except OSError:
                continue
        if not finished:
            since = now
        offset = 0
    elif pos.get('offset', 0) > st.st_size:
        offset, since = 0, now
    else:
        offset = pos.get('offset', 0)
    end = offset
    for end, raw in _alert_lines(path, offset):
        note_line(raw, seen)
    for key in [k for k, v in seen.items() if now - v.get('ts', 0) > 60 * 86400]:
        del seen[key]
    return {'inode': st.st_ino, 'offset': end, 'since': since,
            'day': time.strftime('%Y-%m-%d', time.localtime(st.st_mtime))}, since


# ---------------------------------------------------------------- judging

def judge(all_agents, node, conf, seen, since, now):
    """{agent name: finding} for the agents this node serves and that are connected."""
    found = {}
    limit = conf['silent_hours'] * 3600
    for a in all_agents:
        if node and a['node'] != node:
            continue
        if a['status'] != 'active':
            continue
        why = []
        if GROUP in a['groups']:
            why.append('agent group %s' % GROUP)
        if a['name'] in conf['expected']:
            why.append('listed in jt-yara.conf')
        last = seen.get(a['name'])
        base = {'agent_id': a['id'], 'agent_name': a['name'], 'why': ', '.join(why) or '-',
                'last': time.strftime('%Y-%m-%d %H:%M', time.localtime(last['ts'])) if last else 'never',
                'state': last['state'] if last else '-'}
        if why:
            if last and now - last['ts'] > limit:
                found[a['name']] = dict(base, event='silent', hours=int((now - last['ts']) / 3600))
            elif not last and now - since > limit:
                found[a['name']] = dict(base, event='missing', hours=int((now - since) / 3600))
        elif last and now - last['ts'] <= limit:
            found[a['name']] = dict(base, event='unexpected', hours=0)
    return found


def evaluate(found, previous, now):
    events, state = [], {}
    for name, f in sorted(found.items()):
        old = previous.get(name)
        if not old or old.get('event') != f['event']:
            change = 'new'
        elif now - old.get('reported', 0) >= REMIND[f['event']]:
            change = 'reminder'
        else:
            change = None
        state[name] = {'event': f['event'], 'reported': now if change else old['reported']}
        if change:
            events.append(dict(f, change=change))
    for name, old in sorted(previous.items()):
        if name not in found and old.get('event') in ('silent', 'missing'):
            events.append({'event': 'back', 'agent_name': name, 'change': 'gone', 'was': old['event']})
    return events, state


def send(queue, event, dry=False):
    body = json.dumps({'jt_yara_inv': event}, sort_keys=True, separators=(',', ':'))
    msg = '1:%s:%s' % (LOCATION, body)
    if dry:
        print(msg)
        return
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.connect(queue)
        s.send(msg.encode('utf-8'))
    finally:
        s.close()


def load_state(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(state, fh, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--wazuh-path', default='/var/ossec')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--list', action='store_true')
    args = ap.parse_args(argv)
    wazuh = args.wazuh_path
    queue = os.path.join(wazuh, 'queue', 'sockets', 'queue')
    state_path = os.path.join(wazuh, 'var', 'jt-yara-inventory.state')
    now = int(time.time())
    state = load_state(state_path)
    seen = dict(state.get('seen') or {})
    try:
        all_agents = agents(os.path.join(wazuh, 'queue', 'db', 'wdb'))
        pos, since = scan_alerts(wazuh, state.get('alerts'), seen, now)
    except (OSError, ValueError) as exc:
        log('cannot run: %s' % exc)
        if not args.dry_run and not args.list:
            try:
                send(queue, {'event': 'error', 'detail': str(exc)[:300]})
            except OSError:
                pass
        return 2
    node = local_node(wazuh)
    conf = read_conf(wazuh)
    found = judge(all_agents, node, conf, seen, since, now)
    if args.list:
        for a in sorted(all_agents, key=lambda x: x['name']):
            if (node and a['node'] != node) or a['name'] not in seen and GROUP not in a['groups'] \
                    and a['name'] not in conf['expected']:
                continue
            s = seen.get(a['name'])
            print('%-24s %-12s last %-16s state %-7s %s' % (
                a['name'][:24], a['status'], time.strftime('%Y-%m-%d %H:%M', time.localtime(s['ts'])) if s else 'never',
                s['state'] if s else '-', found.get(a['name'], {}).get('event', '')))
        print('(reading alerts without gaps since %s; silent after %d hours)' % (
            time.strftime('%Y-%m-%d %H:%M', time.localtime(since)), conf['silent_hours']))
        return 0
    events, findings = evaluate(found, state.get('findings') or {}, now)
    for ev in events:
        try:
            send(queue, ev, dry=args.dry_run)
        except OSError as exc:
            log('cannot write to the analysisd queue: %s' % exc)
            return 2
    if not args.dry_run:
        save_state(state_path, {'version': VERSION, 'alerts': pos, 'seen': seen, 'findings': findings})
    log('%d agents, %d reporting, %d findings, %d events' % (len(all_agents), len(seen), len(found), len(events)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
