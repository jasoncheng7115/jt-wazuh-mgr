#!/usr/bin/env python3
# jt-ai-agent-hook - write one audit line per AI coding agent action, for Wazuh
# Part of the jt-ai-agent rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
"""Claude Code hook (PreToolUse and SessionStart) that appends one JSON line per
tool call to /var/log/jt-ai-agent/actions.log, which the Wazuh agent reads.

It records who (OS user, session, subagent), where (host, working directory,
permission mode) and what (tool; for shell commands the command line, for file
tools the path, for web tools the address) - never file contents, command
output or prompts. Secrets in command lines are replaced with *** before
anything is written: passwords and tokens in variables, options, URLs and
headers, private key blocks and the well-known token formats. A command is
kept to 2,000 characters.

It never blocks or changes anything: whatever happens it prints nothing and
exits 0, and it does not create the log (the pack's setup does), so on a host
without the log it does nothing at all.

Settings (in /etc/claude-code/managed-settings.json, so that users cannot turn
it off; ~/.claude/settings.json for one user):

  "hooks": {
    "PreToolUse":   [{"matcher": "*", "hooks": [{"type": "command",
                      "command": "/usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py", "timeout": 5}]}],
    "SessionStart": [{"hooks": [{"type": "command",
                      "command": "/usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py", "timeout": 5}]}]
  }

JT_AI_AGENT_LOG overrides the log path (tests).
"""

import json
import os
import pwd
import re
import shlex
import socket
import sys
import time

LOG = os.environ.get('JT_AI_AGENT_LOG', '/var/log/jt-ai-agent/actions.log')
MAX_CMD = 2000
MAX_SHORT = 300

# Order matters: whole private keys first, then headers, then key=value shapes.
REDACT = [
    (re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)', re.S),
     '[private key removed]'),
    (re.compile(r'(?i)\b((?:proxy-)?authorization\s*:\s*)(?:(?:bearer|basic|token|digest|negotiate)\s+)?[^\s\'"]+'),
     r'\1***'),
    (re.compile(r'(?i)\b((?:cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|private-token|'
                r'x-vault-token)\s*:\s*)[^\'"\n]+'), r'\1***'),
    (re.compile(r'(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@\'"]+:)[^@\s/\'"]+@'), r'\1***@'),
    (re.compile(r'(?i)((?:^|\s)(?:-u|--user)\s*[\'"]?[^\s:\'"]+:)[^\s\'"]+'), r'\1***'),
    (re.compile(r'(?i)(\bsshpass\s+-p\s*)("[^"]*"|\'[^\']*\'|\S+)'), r'\1***'),
    (re.compile(r'(?i)(\b(?:mysql|mariadb|mysqldump|mysqladmin|mariadb-dump)\b[^|;&\n]*?\s-p)(?=\S)'
                r'("[^"]*"|\'[^\']*\'|\S+)'), r'\1***'),
    (re.compile(r'(?i)(\b(?:[a-z0-9_]*(?:pass(?:word|wd|phrase)?|secret|token|api_?key|apikey|credentials?|'
                r'private_?key|auth_?key)[a-z0-9_]*|(?:[a-z0-9_]*_)?key)\s*=\s*)(?!(?:yes|no|true|false|on|off|none|null|[01])(?=[\s;&|,}"\']|$))("[^"]*"|\'[^\']*\'|[^\s;&|]+)'),
     r'\1***'),
    (re.compile(r'(?i)((?:^|\s)--?[a-z-]*(?:password|passwd|pass|pwd|passphrase|secret|token|api-?key|auth-?token|'
                r'client-secret|access-key|secret-key|private-key|storepass|keypass|srcstorepass|deststorepass)(?:=|\s+))("[^"]*"|\'[^\']*\'|\S+)'), r'\1***'),
    (re.compile(r'(?i)(["\']?\b[a-z0-9_]*(?:password|passwd|pwd|passphrase|secret|token|api_?key|'
                r'access_?key)\b["\']?\s*[:=]\s*)(?!(?:yes|no|true|false|on|off|none|null|[01])(?=[\s;&|,}"\']|$))("[^"]*"|\'[^\']*\'|[^\s,;&}]+)'), r'\1***'),
    (re.compile(r'(?i)(\b(?:secret|password|passwd|psk|key)\s+)("[^"]{6,}"|\'[^\']{6,}\')'), r'\1***'),
    (re.compile(r'(?i)(\b(?:aws\s+configure\s+set|git\s+config(?:\s+--\w+)*|npm\s+config\s+set|'
                r'pip\s+config\s+set|kubectl\s+config\s+set-credentials\s+\S+)\s+\S*(?:secret|token|pass|key|auth)\S*\s+)'
                r'("[^"]*"|\'[^\']*\'|\S+)'), r'\1***'),
    (re.compile(r'(?i)([?&](?:pass(?:word)?|pwd|token|key|secret|sig|signature|auth|access_token|api_key|'
                r'apikey|code|session|sid)=)[^&\s\'"#]+'), r'\1***'),
    (re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|'
                r'sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|'
                r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})'), '***'),
]

SSH_ARG_OPTS = set('BbcDEeFIiJLlmOoPpQRSWw')
SCP_ARG_OPTS = set('cDFiJloPSX')
HOST = re.compile(r'^(?:[^@\s/]+@)?(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9._-]+)$')
REMOTE_PATH = re.compile(r'^(?:[^@\s/:]+@)?([A-Za-z0-9._-]+|\[[0-9A-Fa-f:]+\]):')


def redact(text):
    for pattern, repl in REDACT:
        text = pattern.sub(repl, text)
    return text


def short(text, limit=MAX_SHORT):
    text = redact(str(text))
    return text if len(text) <= limit else text[:limit] + '...'


def remote_hosts(command):
    """Destinations of ssh / sftp / scp / rsync in a command line (best effort)."""
    try:
        words = shlex.split(command, comments=False, posix=True)
    except ValueError:
        words = command.split()
    found = []
    i = 0
    while i < len(words):
        word = os.path.basename(words[i])
        if word in ('ssh', 'sftp', 'autossh', 'mosh'):
            i += 1
            while i < len(words):
                w = words[i]
                if w.startswith('$'):
                    i += 1
                    continue
                if w.startswith('-') and len(w) > 1:
                    if w[-1] in SSH_ARG_OPTS and len(w) == 2:
                        i += 1
                    i += 1
                    continue
                m = HOST.match(w)
                if m:
                    found.append(m.group(1))
                break
        elif word in ('scp', 'rsync'):
            i += 1
            while i < len(words) and words[i] not in (';', '&&', '||', '|'):
                w = words[i]
                if w.startswith('-') and len(w) == 2 and w[1] in SCP_ARG_OPTS and word == 'scp':
                    i += 2
                    continue
                m = REMOTE_PATH.match(w)
                if m and not w.startswith('/'):
                    found.append(m.group(1))
                i += 1
            continue
        i += 1
    out = []
    for h in found:
        if h not in out:
            out.append(h)
    return ','.join(out[:5])


def record(event):
    rec = {'v': 1, 'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'host': socket.gethostname()}
    uid = os.getuid()
    try:
        rec['user'] = pwd.getpwuid(uid).pw_name
    except KeyError:
        rec['user'] = str(uid)
    for src, dst in (('hook_event_name', 'event'), ('session_id', 'session'), ('cwd', 'cwd'),
                     ('permission_mode', 'mode'), ('agent_type', 'subagent'), ('agent_id', 'subagent_id'),
                     ('tool_name', 'tool'), ('tool_use_id', 'call'), ('source', 'source'), ('model', 'model')):
        value = event.get(src)
        if isinstance(value, str) and value:
            rec[dst] = value[:MAX_SHORT]
    rec['agent'] = 'claude-code'
    ti = event.get('tool_input')
    if not isinstance(ti, dict):
        return rec
    tool = rec.get('tool', '')
    if tool == 'Bash':
        command = str(ti.get('command', ''))
        clean = redact(command)
        rec['cmd'] = clean if len(clean) <= MAX_CMD else clean[:MAX_CMD] + '...'
        rec['cmd_len'] = len(command)
        if ti.get('run_in_background'):
            rec['background'] = True
        hosts = remote_hosts(command)
        if hosts:
            rec['remote'] = hosts
    elif tool == 'Agent' or tool == 'Task':
        for key in ('subagent_type', 'description', 'model'):
            if ti.get(key):
                rec['task_' + key] = short(ti[key])
    else:
        for key in ('file_path', 'notebook_path', 'path'):
            if ti.get(key):
                rec['path'] = short(ti[key], 1000)
                break
        if isinstance(ti.get('content'), str):
            rec['size'] = len(ti['content'])
        for key in ('pattern', 'glob', 'query', 'url'):
            if ti.get(key):
                rec[key] = short(ti[key], 1000 if key == 'url' else MAX_SHORT)
        if not any(k in rec for k in ('path', 'pattern', 'glob', 'query', 'url')):
            rec['input_keys'] = ','.join(sorted(ti)[:20])
    return rec


def main():
    try:
        event = json.loads(sys.stdin.buffer.read().decode('utf-8', 'replace'))
        if not isinstance(event, dict):
            return
        line = json.dumps({'jt_ai': record(event)}, ensure_ascii=False, separators=(',', ':')) + '\n'
        fd = os.open(LOG, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(fd, line.encode('utf-8'))
        finally:
            os.close(fd)
    except Exception:
        pass


if __name__ == '__main__':
    main()
    sys.exit(0)
