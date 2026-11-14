#!/usr/bin/env python3
# jt-ai-agent-hook - write one audit line per AI coding agent action, for Wazuh
# Part of the jt-ai-agent rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
"""Audit hook for AI coding agents - Claude Code, Codex, opencode, Gemini CLI,
Cursor and GitHub Copilot (CLI, and VS Code agent mode on the Copilot harness) -
that appends one JSON line per tool call to /var/log/jt-ai-agent/actions.log,
which the Wazuh agent reads. Claude Code and Codex call it as a PreToolUse and
SessionStart hook (both send the same JSON on stdin); opencode calls it from
the pack's plugin (agent/jt-ai-agent-opencode.js) with the same shape. Gemini
CLI, Cursor and Copilot send their own shapes, which normalise() turns into
Claude Code's (1.3).

  --agent claude-code|codex|opencode|gemini|cursor|copilot   which agent called
                                                             (default claude-code)
  --event NAME     Copilot only: its camelCase payload has no event name, so the
                   hook configuration passes it (sessionStart, preToolUse...)

Cursor is recorded after the fact (postToolUse and postToolUseFailure): its
"before" hooks are permission hooks, and a hook that answers wrongly there
blocks the call, which an audit must never do. Every Cursor call is therefore
one PostToolUse line, with failed and error when it failed or was denied, so
the detection rules see denied attempts as well.

Gemini CLI, Cursor and Copilot read the hook's standard output as JSON, and
Copilot denies a preToolUse call when the hook exits non-zero: for those three
the hook always prints {} (no decision) and exits 0.

Events recorded (1.2): PreToolUse and SessionStart (1.0), and PermissionRequest (the agent
asked the user to allow a call), PostToolUseFailure (Claude Code) or a failed PostToolUse
(Codex, opencode), SubagentStart and SessionEnd. Each line also says who is behind the
agent (real_user from sudo, login_user from the audit login uid, ssh_from) and the git
project and branch it works in (repo, branch), read from files, never from a subprocess.

Tool names are normalised to Claude Code's (Bash, Read, Write, Edit, WebFetch,
Task...) so that one rule set covers all three; the agent's own name is kept in
tool_raw. Codex's apply_patch becomes Edit (Write when it only adds files),
with the patched paths and never the patch text.

It records who (OS user, session, subagent), where (host, working directory,
permission mode) and what (tool; for shell commands the command line, for file
tools the path, for web tools the address) - never file contents, command
output or prompts. Secrets in command lines are replaced with *** before
anything is written: passwords and tokens in variables, options, URLs and
headers, private key blocks and the well-known token formats. A command is
kept to 2,000 characters.

It never blocks or changes anything: whatever happens it exits 0 and prints
nothing (Gemini CLI, Cursor, Copilot: only {}), and it does not create the log (the pack's setup does), so on a host
without the log it does nothing at all.

Claude Code settings (in /etc/claude-code/managed-settings.json, so that users
cannot turn it off; ~/.claude/settings.json for one user):

  "hooks": {
    "PreToolUse":   [{"matcher": "*", "hooks": [{"type": "command",
                      "command": "/usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py", "timeout": 5}]}],
    "SessionStart": [{"hooks": [{"type": "command",
                      "command": "/usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py", "timeout": 5}]}]
  }

Codex: the same two hooks in /etc/codex/requirements.toml (managed hooks, with
--agent codex). opencode: /etc/opencode/plugins/jt-ai-agent.js. The pack's
setup guide has both.

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

AGENTS = ('claude-code', 'codex', 'opencode', 'gemini', 'cursor', 'copilot')
# agents that parse the hook's stdout as JSON: always answer {} (no decision, never block)
JSON_OUT = ('gemini', 'cursor', 'copilot')
# opencode's tool names -> Claude Code's (the rules match these)
OPENCODE_TOOLS = {'bash': 'Bash', 'shell': 'Bash', 'read': 'Read', 'write': 'Write', 'edit': 'Edit',
                  'multiedit': 'MultiEdit', 'patch': 'Edit', 'apply_patch': 'Edit', 'webfetch': 'WebFetch',
                  'websearch': 'WebSearch', 'task': 'Task', 'glob': 'Glob', 'grep': 'Grep', 'list': 'LS',
                  'ls': 'LS', 'todowrite': 'TodoWrite', 'todoread': 'TodoRead', 'skill': 'Skill',
                  'subagent': 'Task'}
CODEX_TOOLS = {'shell': 'Bash', 'exec_command': 'Bash', 'local_shell': 'Bash', 'spawn_agent': 'Task'}
GEMINI_TOOLS = {'run_shell_command': 'Bash', 'read_file': 'Read', 'read_many_files': 'Read',
                'write_file': 'Write', 'replace': 'Edit', 'glob': 'Glob', 'grep_search': 'Grep',
                'search_file_content': 'Grep', 'list_directory': 'LS', 'web_fetch': 'WebFetch',
                'google_web_search': 'WebSearch', 'write_todos': 'TodoWrite', 'ask_user': 'AskUserQuestion',
                'activate_skill': 'Skill'}
GEMINI_EVENTS = {'BeforeTool': 'PreToolUse', 'AfterTool': 'PostToolUse', 'SessionStart': 'SessionStart',
                 'SessionEnd': 'SessionEnd'}
CURSOR_TOOLS = {'Shell': 'Bash', 'Terminal': 'Bash', 'Read': 'Read', 'Write': 'Write', 'Edit': 'Edit',
                'StrReplace': 'Edit', 'Delete': 'Delete', 'Grep': 'Grep', 'Glob': 'Glob', 'LS': 'LS',
                'Task': 'Task', 'WebFetch': 'WebFetch', 'WebSearch': 'WebSearch'}
CURSOR_EVENTS = {'sessionStart': 'SessionStart', 'sessionEnd': 'SessionEnd', 'postToolUse': 'PostToolUse',
                 'postToolUseFailure': 'PostToolUse'}
COPILOT_TOOLS = {'bash': 'Bash', 'powershell': 'Bash', 'view': 'Read', 'create': 'Write', 'edit': 'Edit',
                 'str_replace_editor': 'Edit', 'grep': 'Grep', 'rg': 'Grep', 'glob': 'Glob',
                 'web_fetch': 'WebFetch', 'web_search': 'WebSearch', 'task': 'Task',
                 'update_todo': 'TodoWrite', 'ask_user': 'AskUserQuestion'}
COPILOT_EVENTS = {'sessionStart': 'SessionStart', 'sessionEnd': 'SessionEnd', 'preToolUse': 'PreToolUse',
                  'postToolUse': 'PostToolUse', 'postToolUseFailure': 'PostToolUseFailure',
                  'subagentStart': 'SubagentStart', 'permissionRequest': 'PermissionRequest'}
URL_IN_TEXT = re.compile(r'https?://[^\s\'"<>)]+')
PATCH_FILE = re.compile(r'^\*\*\* (Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$', re.M)


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


def patch_summary(ti, rec):
    """Codex apply_patch: the files it touches, never the patch text. Edit, or Write when it only adds."""
    text = ti.get('command') if isinstance(ti.get('command'), str) else ti.get('input')
    if not isinstance(text, str):
        text = ''
    kinds, paths = set(), []
    for m in PATCH_FILE.finditer(text):
        kinds.add(m.group(1) or 'Move')
        path = (m.group(2) or m.group(3) or '').strip()
        if path and path not in paths:
            paths.append(path)
    cwd = rec.get('cwd', '')
    if cwd.startswith('/'):
        paths = [p if p.startswith('/') else os.path.normpath(os.path.join(cwd, p)) for p in paths]
    if paths:
        rec['path'] = short(paths[0], 1000)
        if len(paths) > 1:
            rec['paths'] = short(','.join(paths[:20]), 1000)
    rec['size'] = len(text)
    if 'Delete' in kinds:
        rec['patch_delete'] = True
    return 'Write' if kinds == {'Add'} else 'Edit'


FAILURE_HINTS = ('error', 'failed', 'failure')


def who_and_where(rec, cwd):
    """The person behind the agent and the project it works in (1.2). Environment and files only:
    no subprocess, so the hook stays fast."""
    sudo_user = os.environ.get('SUDO_USER')
    if sudo_user and sudo_user != rec.get('user'):
        rec['real_user'] = sudo_user[:64]
    try:
        with open('/proc/self/loginuid') as fh:
            luid = int(fh.read().strip())
        if luid != 4294967295 and luid != os.getuid():
            rec['login_user'] = pwd.getpwuid(luid).pw_name
    except (OSError, ValueError, KeyError):
        pass
    ssh = os.environ.get('SSH_CONNECTION') or os.environ.get('SSH_CLIENT') or ''
    if ssh.split():
        rec['ssh_from'] = ssh.split()[0][:64]
    entry = os.environ.get('CLAUDE_CODE_ENTRYPOINT')
    if entry and rec.get('agent') == 'claude-code':
        rec['entry'] = entry[:32]
    if os.environ.get('CI'):
        rec['ci'] = True
    # git project: walk up from the working directory to the first .git (file or directory)
    d = cwd if isinstance(cwd, str) and cwd.startswith('/') else ''
    for _ in range(25):
        if not d or d == '/':
            break
        git = os.path.join(d, '.git')
        try:
            head_path = None
            if os.path.isdir(git):
                head_path = os.path.join(git, 'HEAD')
            elif os.path.isfile(git):
                with open(git) as fh:
                    gd = fh.read().strip()
                if gd.startswith('gitdir:'):
                    gd = gd[7:].strip()
                    head_path = os.path.join(gd if gd.startswith('/') else os.path.join(d, gd), 'HEAD')
            if head_path:
                rec['repo'] = os.path.basename(d)[:MAX_SHORT]
                with open(head_path) as fh:
                    head = fh.read(200).strip()
                if head.startswith('ref: refs/heads/'):
                    rec['branch'] = head[16:][:MAX_SHORT]
                break
        except OSError:
            break
        d = os.path.dirname(d)


def failed(response):
    """Did a tool call fail? Codex and opencode report it in the response; the output itself is
    never read beyond these markers."""
    if not isinstance(response, dict):
        return False
    for key in ('exit_code', 'exitCode', 'returncode'):
        if isinstance(response.get(key), int) and response[key] != 0:
            return True
    if response.get('success') is False or response.get('ok') is False:
        return True
    status = response.get('status')
    if isinstance(status, str) and status.lower() in FAILURE_HINTS:
        return True
    return bool(response.get('error'))


def as_dict(value):
    """Tool arguments arrive as an object or as a JSON string (Copilot toolArgs, Cursor MCP)."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.lstrip().startswith('{'):
        try:
            value = json.loads(value)
        except ValueError:
            return None
        return value if isinstance(value, dict) else None
    return None


def mcp_name(server, tool):
    return 'mcp__%s__%s' % (server or 'unknown', tool)


def normalise(event, agent, event_name=None):
    """Turn a Gemini CLI, Cursor or Copilot payload into Claude Code's shape (1.3). The fields
    kept are the ones record() reads; prompts, file contents and tool output are dropped here."""
    if agent == 'gemini':
        name = event.get('hook_event_name')
        out = {k: event.get(k) for k in ('session_id', 'cwd', 'source', 'reason')}
        if name == 'Notification':
            if event.get('notification_type') != 'ToolPermission':
                return None
            out['hook_event_name'] = 'PermissionRequest'
            details = event.get('details') if isinstance(event.get('details'), dict) else {}
            tool = details.get('toolName') or details.get('tool_name') or details.get('name')
            if isinstance(tool, str):
                out['tool_name'] = tool
            return out
        if name not in GEMINI_EVENTS:
            return None
        out['hook_event_name'] = GEMINI_EVENTS[name]
        tool = event.get('tool_name')
        ti = as_dict(event.get('tool_input')) or {}
        mcp = event.get('mcp_context') if isinstance(event.get('mcp_context'), dict) else {}
        if isinstance(tool, str):
            server = mcp.get('server_name') or mcp.get('serverName')
            if server or tool.startswith('mcp_'):
                bare = mcp.get('tool_name') or mcp.get('toolName')
                if not bare and tool.startswith('mcp_'):
                    rest = tool[4:]
                    if server and rest.startswith(server + '_'):
                        bare = rest[len(server) + 1:]
                    else:
                        server, _, bare = rest.partition('_')
                out['tool_raw'] = tool
                tool = mcp_name(server, bare or tool)
            out['tool_name'] = tool
            if tool == 'web_fetch' and isinstance(ti.get('prompt'), str):
                urls = URL_IN_TEXT.findall(ti['prompt'])
                ti = {'url': ','.join(urls[:5])} if urls else {}
            elif tool == 'read_many_files':
                inc = ti.get('include') or ti.get('paths')
                ti = {'path': ','.join(inc[:20]) if isinstance(inc, list) else inc} if inc else {}
            if 'dir_path' in ti and tool == 'list_directory':
                ti = {'path': ti['dir_path']}
        out['tool_input'] = ti
        if name == 'AfterTool':
            resp = event.get('tool_response') if isinstance(event.get('tool_response'), dict) else {}
            out['tool_response'] = resp
            err = resp.get('error')
            if isinstance(err, dict):
                err = err.get('message') or err.get('type')
            if isinstance(err, str):
                out['error'] = err
        return out

    if agent == 'cursor':
        name = event.get('hook_event_name')
        if name not in CURSOR_EVENTS:
            return None
        roots = event.get('workspace_roots')
        cwd = event.get('cwd') or (roots[0] if isinstance(roots, list) and roots and isinstance(roots[0], str) else None)
        out = {'hook_event_name': CURSOR_EVENTS[name], 'cwd': cwd, 'reason': event.get('reason'),
               'session_id': event.get('conversation_id') or event.get('session_id'),
               'model': event.get('model'), 'tool_use_id': event.get('tool_use_id'),
               'account': event.get('user_email'), 'permission_mode': event.get('composer_mode')}
        if event.get('is_background_agent'):
            out['source'] = 'background'
        tool = event.get('tool_name')
        ti = as_dict(event.get('tool_input')) or {}
        if isinstance(tool, str):
            if tool.startswith('MCP:') or event.get('mcp_server_name'):
                out['tool_raw'] = tool
                tool = mcp_name(event.get('mcp_server_name'), tool[4:] if tool.startswith('MCP:') else tool)
            out['tool_name'] = tool
            if isinstance(ti.get('working_directory'), str) and not out['cwd']:
                out['cwd'] = ti['working_directory']
        out['tool_input'] = ti
        if name == 'postToolUseFailure':
            out['failed'] = True
            kind, msg = event.get('failure_type'), event.get('error_message')
            out['error'] = ': '.join(x for x in (kind, msg) if isinstance(x, str) and x) or 'failed'
        return out

    if agent == 'copilot':
        name = event_name or event.get('hook_event_name')
        name = COPILOT_EVENTS.get(name, name)
        if name not in COPILOT_EVENTS.values():
            return None
        out = {'hook_event_name': name, 'cwd': event.get('cwd'),
               'session_id': event.get('sessionId') or event.get('session_id'),
               'source': event.get('source'), 'reason': event.get('reason'),
               'agent_type': event.get('agentName') or event.get('agent_type')}
        tool = event.get('toolName') or event.get('tool_name')
        if isinstance(tool, str):
            out['tool_name'] = tool
        out['tool_input'] = (as_dict(event.get('toolArgs')) or as_dict(event.get('toolInput'))
                             or as_dict(event.get('tool_input')) or {})
        result = event.get('toolResult') if isinstance(event.get('toolResult'), dict) else None
        if result is not None:
            out['tool_response'] = {'error': result.get('resultType') not in (None, 'success')}
        err = event.get('error')
        if isinstance(err, dict):
            err = err.get('message')
        if isinstance(err, str):
            out['error'] = err
        return out
    return event


def record(event, agent='claude-code'):
    rec = {'v': 1, 'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'host': socket.gethostname()}
    uid = os.getuid()
    try:
        rec['user'] = pwd.getpwuid(uid).pw_name
    except KeyError:
        rec['user'] = str(uid)
    for src, dst in (('hook_event_name', 'event'), ('session_id', 'session'), ('cwd', 'cwd'),
                     ('permission_mode', 'mode'), ('agent_type', 'subagent'), ('agent_id', 'subagent_id'),
                     ('tool_name', 'tool'), ('tool_use_id', 'call'), ('source', 'source'), ('model', 'model'),
                     ('reason', 'reason'), ('account', 'account'), ('tool_raw', 'tool_raw')):
        value = event.get(src)
        if isinstance(value, str) and value:
            rec[dst] = value[:MAX_SHORT]
    rec['agent'] = agent
    who_and_where(rec, event.get('cwd'))
    after_only = agent == 'cursor'          # Cursor: every call is recorded after it ran (or was refused)
    if rec.get('event') in ('PostToolUseFailure', 'PostToolUse') and not after_only:
        rec['event'] = 'PostToolUseFailure'
    if after_only and event.get('failed'):
        rec['failed'] = True
    err = event.get('error')
    if rec.get('event') in ('PostToolUseFailure', 'PostToolUse') and isinstance(err, str) and err:
        rec['error'] = short(err.splitlines()[0] if err.splitlines() else err, 200)
    ti = event.get('tool_input')
    tool = rec.get('tool', '')
    if tool:
        canon = tool
        if agent == 'opencode':
            canon = OPENCODE_TOOLS.get(tool.lower(), tool)
        elif agent == 'codex':
            canon = CODEX_TOOLS.get(tool, tool)
        elif agent == 'gemini':
            canon = GEMINI_TOOLS.get(tool, tool)
        elif agent == 'cursor':
            canon = CURSOR_TOOLS.get(tool, tool)
        elif agent == 'copilot':
            canon = COPILOT_TOOLS.get(tool.lower(), tool)
        if tool == 'apply_patch' and isinstance(ti, dict):
            canon = patch_summary(ti, rec)
            ti = None
        if canon != tool:
            rec.setdefault('tool_raw', tool)
            rec['tool'] = tool = canon
    if tool.startswith('mcp__'):
        parts = tool.split('__')
        if len(parts) >= 3:
            rec['mcp_server'] = parts[1][:MAX_SHORT]
            rec['mcp_tool'] = '__'.join(parts[2:])[:MAX_SHORT]
    if not isinstance(ti, dict) or not ti:
        return rec
    if tool == 'Bash':
        command = str(ti.get('command', ''))
        clean = redact(command)
        rec['cmd'] = clean if len(clean) <= MAX_CMD else clean[:MAX_CMD] + '...'
        rec['cmd_len'] = len(command)
        if clean != command:
            rec['redacted'] = True
        if ti.get('run_in_background'):
            rec['background'] = True
        hosts = remote_hosts(command)
        if hosts:
            rec['remote'] = hosts
    elif tool == 'Agent' or tool == 'Task':
        for key, out in (('subagent_type', 'subagent_type'), ('subagentType', 'subagent_type'), ('agent', 'subagent_type'),
                         ('description', 'description'), ('model', 'model')):
            if ti.get(key) and 'task_' + out not in rec:
                rec['task_' + out] = short(ti[key])
    else:
        for key in ('file_path', 'filePath', 'notebook_path', 'path', 'target_file', 'dir_path'):
            if ti.get(key):
                rec['path'] = short(ti[key], 1000)
                break
        for key in ('content', 'file_text', 'contents'):
            if isinstance(ti.get(key), str):
                rec['size'] = len(ti[key])
                break
        for key in ('pattern', 'glob', 'query', 'url'):
            if ti.get(key):
                rec[key] = short(ti[key], 1000 if key == 'url' else MAX_SHORT)
        if not any(k in rec for k in ('path', 'pattern', 'glob', 'query', 'url')):
            rec['input_keys'] = ','.join(sorted(ti)[:20])
    return rec


def options(args):
    agent, event_name = 'claude-code', None
    i = 0
    while i + 1 < len(args):
        if args[i] == '--agent' and args[i + 1] in AGENTS:
            agent = args[i + 1]
        elif args[i] == '--event':
            event_name = args[i + 1][:64]
        i += 2
    return agent, event_name


def main():
    agent, event_name = options(sys.argv[1:])
    try:
        write(agent, event_name)
    except Exception:
        pass
    finally:
        if agent in JSON_OUT:
            try:
                sys.stdout.write('{}\n')
                sys.stdout.flush()
            except Exception:
                pass


def write(agent, event_name):
    event = json.loads(sys.stdin.buffer.read().decode('utf-8', 'replace'))
    if not isinstance(event, dict):
        return
    event = normalise(event, agent, event_name)
    if not event:
        return
    # a successful call is already on record (PreToolUse); only failures are worth a line
    # (Cursor has no PreToolUse here: all its calls are PostToolUse lines)
    if (event.get('hook_event_name') == 'PostToolUse' and agent != 'cursor'
            and not failed(event.get('tool_response'))):
        return
    line = json.dumps({'jt_ai': record(event, agent)}, ensure_ascii=False, separators=(',', ':')) + '\n'
    fd = os.open(LOG, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, line.encode('utf-8'))
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()
    sys.exit(0)
