#!/usr/bin/env python3
# jt-ai-agent-inventory - find AI coding agents and local model servers the audit does not cover
# Part of the jt-ai-agent rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
"""Report hosts that run an AI coding agent without the jt-ai-agent audit, and
local model servers (Ollama, llama.cpp, vLLM ...) that listen on the network.

The audit only covers hosts in the agent group "ai-agent" that have the hook
installed. Agents get installed by people, often without telling anyone. This
script reads the inventory syscollector already keeps on this manager node
(packages, running processes, listening ports) and the file integrity database
(is the hook there?), and writes one JSON event per finding into analysisd's
queue for rules 133750-133759. The events are the manager's own (location
jt-ai-agent-inventory) and name the host in their fields: analysisd drops queue
events that claim an agent's identity once agents are registered.

Findings:
  unaudited     a coding agent (Claude Code, Codex, opencode, Gemini CLI, Cursor,
                Copilot) on a host that is not in the group "ai-agent"
  hook_missing  the host is in the group, but the file integrity database has no
                /usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py
  no_hook       an agent that has no hook mechanism at all (Aider), so it cannot
                be audited this way
  model_server  a local model server is running
  model_exposed a local model server listens on a non-loopback address; Ollama and
                llama.cpp's server have no authentication by default

Each finding is reported when it appears, reminded once a week while it lasts,
and reported once more when it is gone. Processes are a snapshot (syscollector
scans them about hourly), so an agent that is only run now and then is mostly
found through its package.

It only reads the wazuh-db socket (SELECT statements). It writes its state file
and events. Run it on every node of a cluster: each node keeps the inventory of
the agents connected to it, and the script handles only those.

    jt-ai-agent-inventory.py --wazuh-path /var/ossec            normal run (cron)
    jt-ai-agent-inventory.py --wazuh-path /var/ossec --dry-run  print, send and save nothing
    jt-ai-agent-inventory.py --wazuh-path /var/ossec --list     what was found, no events
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import struct
import sys
import time

VERSION = '1.0.1'
PROG = 'jt-ai-agent-inventory'
LOCATION = 'jt-ai-agent-inventory'
GROUP = 'ai-agent'
HOOK = '/usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py'
REMIND_DAYS = 7

# tool -> (package names, case-insensitive exact; process regex on name, cmd and arguments)
# A process whose executable matches EXCLUDE[tool] belongs to something else (Ollama runs its
# own llama-server under /usr/lib/ollama/).
CODING_AGENTS = {
    'claude-code': ({'@anthropic-ai/claude-code', 'claude-code'}, r'(?:^|/)claude(?:\s|$)'),
    'codex': ({'@openai/codex', 'codex'}, r'(?:^|/)codex(?:\s|$)'),
    'opencode': ({'opencode-ai', 'opencode'}, r'(?:^|/)opencode(?:\s|$)'),
    'gemini': ({'@google/gemini-cli', 'gemini-cli'}, r'(?:^|/)gemini(?:\s|$)|@google/gemini-cli'),
    'cursor': ({'cursor', 'cursor-agent'}, r'(?:^|/)cursor-agent(?:\s|$)|(?:^|/)cursor(?:\.exe)?(?:\s|$)'),
    'copilot': ({'@github/copilot'}, r'(?:^|/)copilot(?:\s|$)|@github/copilot'),
}
NO_HOOK = {
    'aider': ({'aider-chat', 'aider'}, r'(?:^|/)aider(?:\s|$)'),
}
MODEL_SERVERS = {
    'ollama': ({'ollama'}, r'(?:^|/)ollama(?:\s|$)'),
    'llama.cpp': ({'llama.cpp', 'llama-cpp'}, r'(?:^|/)llama-server(?:\s|$)'),
    'vllm': ({'vllm'}, r'\bvllm(?:\s+serve|\.entrypoints)|^VLLM::'),
    'lm-studio': ({'lm studio', 'lm-studio'}, r'(?:^|/)lms(?:\s|$)|LM Studio'),
    'localai': ({'localai'}, r'(?:^|/)local-ai(?:\s|$)'),
}
EXCLUDE = {'llama.cpp': r'/ollama/'}
# Unprivileged LXC containers map their users to 100000 and up: on a Proxmox host those
# processes are the containers', which are agents (or not) of their own.
CONTAINER_UID = 100000
# SQL prefilter (LIKE); the exact matching is done here
PKG_LIKE = ('claude', 'codex', 'opencode', 'gemini', 'cursor', 'copilot', 'aider', 'ollama', 'llama',
            'vllm', 'lm studio', 'lm-studio', 'localai')
PROC_LIKE = ('claude', 'codex', 'opencode', 'gemini', 'cursor', 'copilot', 'aider', 'ollama', 'llama-server',
             'vllm', 'lms', 'local-ai')


def log(msg):
    print('%s: %s' % (PROG, msg), file=sys.stderr)


# ---------------------------------------------------------------- wazuh-db

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


def likes(column, words):
    return '(' + ' OR '.join("lower(%s) LIKE '%%%s%%'" % (column, w) for w in words) + ')'


def agents_of_node(wdb, node):
    rows = wdb_query(wdb, 'global sql SELECT id, name, ip, node_name, connection_status, os_platform, '
                          '"group" AS groups FROM agent')
    out = []
    for a in rows:
        aid = int(a.get('id', -1))
        if aid <= 0 or a.get('connection_status') == 'never_connected':
            continue
        if node and a.get('node_name') != node:
            continue
        groups = [g.strip() for g in str(a.get('groups') or '').split(',') if g.strip()]
        out.append({'id': '%03d' % aid, 'name': a.get('name') or '', 'ip': a.get('ip') or 'any',
                    'status': a.get('connection_status') or '', 'platform': (a.get('os_platform') or '').lower(),
                    'groups': groups})
    return out


def collect(wdb, agent):
    """Packages, processes and listening ports of one agent that could be an AI tool."""
    aid = int(agent['id'])
    data = {'packages': [], 'processes': [], 'ports': [], 'hook': None}
    data['packages'] = wdb_query(wdb, "agent %03d sql SELECT name, version, format FROM sys_programs WHERE %s"
                                 % (aid, likes('name', PKG_LIKE)))
    data['processes'] = wdb_query(wdb, "agent %03d sql SELECT pid, name, cmd, argvs, euser FROM sys_processes "
                                  "WHERE %s OR %s OR %s" % (aid, likes('name', PROC_LIKE), likes('cmd', PROC_LIKE),
                                                            likes('argvs', PROC_LIKE)))
    data['ports'] = wdb_query(wdb, "agent %03d sql SELECT protocol, local_ip, local_port, state, pid, process "
                              "FROM sys_ports WHERE state = 'listening' OR protocol LIKE 'udp%%'" % aid)
    for column in ('file', 'full_path'):
        try:
            rows = wdb_query(wdb, "agent %03d sql SELECT %s FROM fim_entry WHERE %s = '%s'" % (aid, column, column, HOOK))
        except OSError:
            continue
        data['hook'] = bool(rows)
        break
    return data


# ---------------------------------------------------------------- matching

def proc_text(p):
    argv = p.get('argvs')
    if isinstance(argv, list):
        argv = ' '.join(map(str, argv))
    return ' '.join(str(x) for x in (p.get('name') or '', p.get('cmd') or '', argv or '') if x)


def pid_of(row):
    """wazuh-db names the column PID in sys_ports and pid in sys_processes."""
    for key in ('pid', 'PID'):
        if row.get(key) is not None:
            return row[key]
    return None


def match_tools(table, data):
    """{tool: {'evidence': [...], 'pids': set()}} for the tools of one table."""
    found = {}
    for tool, (pkgs, proc) in table.items():
        rx = re.compile(proc, re.I)
        skip = re.compile(EXCLUDE[tool]) if tool in EXCLUDE else None
        ev, pids = [], set()
        for p in data['packages']:
            name = str(p.get('name') or '').strip()
            # Windows installs show as "Cursor (User)"; the rest are exact package names
            if re.sub(r'\s*\([^)]*\)$', '', name).lower() in pkgs:
                ev.append('package %s %s' % (name[:60], str(p.get('version') or '')[:30]))
        for p in data['processes']:
            text = proc_text(p)
            user = str(p.get('euser') or '')
            if user.isdigit() and int(user) >= CONTAINER_UID:
                continue
            if skip and skip.search(str(p.get('cmd') or '')):
                continue
            if rx.search(text):
                pid = pid_of(p)
                ev.append('process %s (pid %s, %s)' % (str(p.get('name') or '')[:30], pid, user[:32] or '?'))
                if pid is not None:
                    pids.add(str(pid))
        if ev:
            found[tool] = {'evidence': sorted(set(ev))[:5], 'pids': pids}
    return found


def exposed_ports(data, pids, tool):
    """Non-loopback listening sockets of a model server's processes."""
    out = []
    for p in data['ports']:
        own = str(pid_of(p)) in pids or tool.split('.')[0] in str(p.get('process') or '').lower()
        if not own:
            continue
        ip = str(p.get('local_ip') or '')
        try:
            if ipaddress.ip_address(ip).is_loopback:
                continue
        except ValueError:
            if ip not in ('', '*'):
                continue
        out.append('%s %s:%s' % (p.get('protocol') or '', ip or '*', p.get('local_port')))
    return sorted(set(out))[:5]


def findings(agent, data):
    out = {}
    audited = GROUP in agent['groups']
    for tool, f in match_tools(CODING_AGENTS, data).items():
        if not audited:
            out['%s:%s:unaudited' % (agent['id'], tool)] = {'event': 'unaudited', 'tool': tool, 'evidence': f['evidence']}
        elif data['hook'] is False:
            out['%s:%s:hook_missing' % (agent['id'], tool)] = {'event': 'hook_missing', 'tool': tool,
                                                               'evidence': f['evidence']}
    for tool, f in match_tools(NO_HOOK, data).items():
        out['%s:%s:no_hook' % (agent['id'], tool)] = {'event': 'no_hook', 'tool': tool, 'evidence': f['evidence']}
    for tool, f in match_tools(MODEL_SERVERS, data).items():
        ports = exposed_ports(data, f['pids'], tool)
        if ports:
            out['%s:%s:model_exposed' % (agent['id'], tool)] = {'event': 'model_exposed', 'tool': tool,
                                                                'evidence': f['evidence'], 'listen': ports}
        else:
            out['%s:%s:model_server' % (agent['id'], tool)] = {'event': 'model_server', 'tool': tool,
                                                               'evidence': f['evidence']}
    for f in out.values():
        f.update({'agent_id': agent['id'], 'agent_name': agent['name'], 'agent_ip': agent['ip'],
                  'in_group': audited})
    return out


# ---------------------------------------------------------------- state and events

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


def send(queue, event, dry=False):
    body = json.dumps({'jt_ai_inv': event}, sort_keys=True, separators=(',', ':'))
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


def evaluate(found, previous, scanned, now):
    """Events to send and the new state. A finding of an agent that was not scanned this
    time (disconnected, inventory unreadable) is kept, not reported as gone."""
    events, state = [], {}
    for key, f in sorted(found.items()):
        old = previous.get(key)
        if old is None:
            change = 'new'
        elif now - old.get('reported', 0) >= REMIND_DAYS * 86400:
            change = 'reminder'
        elif sorted(old.get('evidence', [])) != sorted(f['evidence']) and f['event'] == 'model_exposed':
            change = 'changed'
        else:
            change = None
        rec = {'evidence': f['evidence'], 'event': f['event'], 'agent_name': f['agent_name'], 'tool': f['tool'],
               'first': old.get('first', now) if old else now, 'reported': old.get('reported', now) if old else now}
        if change:
            ev = dict(f, change=change, evidence=', '.join(f['evidence']))
            if 'listen' in f:
                ev['listen'] = ', '.join(f['listen'])
            events.append(ev)
            rec['reported'] = now
        state[key] = rec
    for key, old in sorted(previous.items()):
        if key in found:
            continue
        if key.split(':', 1)[0] not in scanned:
            state[key] = old
            continue
        events.append({'event': 'cleared', 'was': old.get('event'), 'tool': old.get('tool'),
                       'agent_id': key.split(':', 1)[0], 'agent_name': old.get('agent_name', ''),
                       'change': 'gone'})
    return events, state


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--wazuh-path', default='/var/ossec')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--list', action='store_true')
    args = ap.parse_args(argv)
    wazuh = args.wazuh_path
    wdb = os.path.join(wazuh, 'queue', 'db', 'wdb')
    queue = os.path.join(wazuh, 'queue', 'sockets', 'queue')
    state_path = os.path.join(wazuh, 'var', 'jt-ai-agent-inventory.state')
    now = int(time.time())
    try:
        agents = agents_of_node(wdb, local_node(wazuh))
    except (OSError, ValueError) as exc:
        log('cannot read the agent list: %s' % exc)
        if not args.dry_run and not args.list:
            try:
                send(queue, {'event': 'status', 'state': 'wdb_error', 'detail': str(exc)[:300]})
            except OSError:
                pass
        return 2
    found, scanned, errors = {}, set(), 0
    for agent in agents:
        try:
            data = collect(wdb, agent)
        except (OSError, ValueError) as exc:
            errors += 1
            log('agent %s: %s' % (agent['id'], exc))
            continue
        scanned.add(agent['id'])
        found.update(findings(agent, data))
    if args.list:
        for key, f in sorted(found.items()):
            print('%s %-22s %-13s %-12s %s %s' % (f['agent_id'], f['agent_name'][:22], f['event'], f['tool'],
                                                 '; '.join(f['evidence']), ', '.join(f.get('listen', []))))
        return 0
    state = load_state(state_path)
    events, new_state = evaluate(found, state.get('findings') or {}, scanned, now)
    if agents and not scanned:
        events.append({'event': 'status', 'state': 'wdb_error', 'detail': 'no agent inventory could be read'})
    for ev in events:
        try:
            send(queue, ev, dry=args.dry_run)
        except OSError as exc:
            log('cannot write to the analysisd queue: %s' % exc)
            return 2
    if not args.dry_run:
        save_state(state_path, {'version': VERSION, 'findings': new_state, 'run': now})
    log('%d agents, %d scanned, %d findings, %d events, %d errors'
        % (len(agents), len(scanned), len(found), len(events), errors))
    return 0


if __name__ == '__main__':
    sys.exit(main())
