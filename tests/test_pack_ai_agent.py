"""jt-ai-agent: the Claude Code audit hook (packs/jt-ai-agent/agent/jt-ai-agent-hook.py).

The hook runs before every tool call of every agent on a host, so two
properties matter more than anything it records: it must never block or
change a call, and it must not write secrets into a log that goes to Wazuh.
"""

import hashlib
import importlib.util
import json
import re
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, 'packs', 'jt-ai-agent', 'agent', 'jt-ai-agent-hook.py')

sys.dont_write_bytecode = True     # no __pycache__ inside packs/ (packs/INDEX lists every file)
spec = importlib.util.spec_from_file_location('jt_ai_agent_hook', HOOK)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


def run_hook(stdin, log):
    env = dict(os.environ, JT_AI_AGENT_LOG=log)
    return subprocess.run([sys.executable, HOOK], input=stdin, capture_output=True, env=env, timeout=30)


class TestRedaction(unittest.TestCase):
    SECRETS = [
        ('SSHPASS=Hunter2pass sshpass -e ssh user@192.0.2.5', 'Hunter2pass'),
        ("sshpass -p 'My Pass' ssh root@host1", 'My Pass'),
        ("mysql -uroot -pS3cretPw -e 'select 1'", 'S3cretPw'),
        ('curl -u admin:S3cretCurl https://x/api', 'S3cretCurl'),
        ("curl -H 'Authorization: Bearer abc.def.ghi' https://x", 'abc.def.ghi'),
        ('curl -H "Cookie: session=abcdef123" https://x', 'abcdef123'),
        ('git clone https://bob:pw123@example.com/repo.git', 'pw123'),
        ("curl 'https://x/api?user=a&token=abcd1234&page=2'", 'abcd1234'),
        ('export API_KEY=sk-abcdefghijklmnopqrstuvwxyz123', 'abcdefghijklmnop'),
        ('export ENCRYPTION_KEY=sBDWTP054hNRrK1tZoXVX2a', 'sBDWTP054hNR'),
        ('python3 x.py --password hunter2 --verbose', 'hunter2'),
        ('kc --username u1 --new-password Pw-123456789', 'Pw-123456789'),
        ('python3 x.py --token=abc123xyz', 'abc123xyz'),
        ('echo \'{"bind_password": "Adm1n-Passw0rd!"}\' > f.json', 'Adm1n-Passw0rd'),
        ('userPassword: Alice07-Pass-2026', 'Alice07-Pass-2026'),
        ('DB_PASSWORD=no-way-123 ./run', 'no-way-123'),
        ('git clone https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123@git.example.com/x/y', 'ghp_ABCDEFGHIJKLMNOPQRST'),
        ('aws configure set aws_secret_access_key wJalrXUtnFEMI', 'wJalrXUtnFEMI'),
        ('keytool -list -cacerts -storepass changeit', 'changeit'),
        ('algorithm hmac-sha256; secret "c2VjcmV0LXRoYXQ=";', 'c2VjcmV0LXRoYXQ'),
        ('cat <<EOF > k\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n'
         '-----END OPENSSH PRIVATE KEY-----\nEOF', 'b3BlbnNzaC1rZXktdjEAAAA'),
    ]
    KEPT = [
        'grep -i password /etc/app.conf',
        'mkdir -p /tmp/x && tar -pxf a.tar',
        "ssh -i /root/.ssh/id_ed25519_x -o BatchMode=yes root@192.0.2.105 'nginx -t'",
        'ssh -o PasswordAuthentication=no host',
        'ls --sort=time /var/log',
        'tar --passive x',
        'curl -s "https://x/?q=password+reset"',
    ]

    def test_secrets_are_replaced(self):
        for command, secret in self.SECRETS:
            with self.subTest(command=command):
                self.assertNotIn(secret, hook.redact(command))
                self.assertIn('***' if 'PRIVATE KEY' not in command else 'private key removed', hook.redact(command))

    def test_ordinary_commands_are_kept(self):
        for command in self.KEPT:
            with self.subTest(command=command):
                self.assertEqual(hook.redact(command), command)


class TestRemoteHosts(unittest.TestCase):
    def test_destinations(self):
        for command, hosts in [
            ("ssh $K root@192.0.2.105 'x'", '192.0.2.105'),
            ('scp -q $K a.conf root@192.0.2.105:/root/', '192.0.2.105'),
            ("ssh -n -i k -p 2222 admin@host.example.com 'ls'", 'host.example.com'),
            ('rsync -a ./ backup@10.0.0.5:/srv/', '10.0.0.5'),
            ('ssh -o BatchMode=yes host2 uptime; ssh host3', 'host2,host3'),
            ('scp root@a.example.com:/etc/x ./', 'a.example.com'),
            ('cd /opt && ls', ''),
        ]:
            with self.subTest(command=command):
                self.assertEqual(hook.remote_hosts(command), hosts)


class TestRecord(unittest.TestCase):
    def test_file_contents_are_never_recorded(self):
        rec = hook.record({'hook_event_name': 'PreToolUse', 'tool_name': 'Write',
                           'tool_input': {'file_path': '/opt/p/.env', 'content': 'DB_PASSWORD=x9secret\n'}})
        self.assertEqual(rec['path'], '/opt/p/.env')
        self.assertEqual(rec['size'], len('DB_PASSWORD=x9secret\n'))
        self.assertNotIn('x9secret', json.dumps(rec))
        rec = hook.record({'hook_event_name': 'PreToolUse', 'tool_name': 'Edit',
                           'tool_input': {'file_path': '/opt/p/a.py', 'old_string': 'k1secret', 'new_string': 'k2secret'}})
        self.assertNotIn('secret', json.dumps(rec))

    def test_subagent_and_mode_are_recorded(self):
        rec = hook.record({'hook_event_name': 'PreToolUse', 'tool_name': 'Bash', 'permission_mode': 'bypassPermissions',
                           'agent_id': 'a1', 'agent_type': 'Explore', 'tool_input': {'command': 'ls'}})
        self.assertEqual((rec['mode'], rec['subagent'], rec['subagent_id'], rec['cmd']),
                         ('bypassPermissions', 'Explore', 'a1', 'ls'))

    def test_long_commands_are_cut(self):
        rec = hook.record({'tool_name': 'Bash', 'tool_input': {'command': 'echo ' + 'x' * 5000}})
        self.assertLessEqual(len(rec['cmd']), hook.MAX_CMD + 3)
        self.assertEqual(rec['cmd_len'], 5005)


class TestNeverBlocks(unittest.TestCase):
    def test_writes_one_json_line_and_prints_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'actions.log')
            open(log, 'w').close()
            event = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                     'tool_input': {'command': 'echo "x\ny" ; ls'}}
            r = run_hook(json.dumps(event).encode(), log)
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b'', b''))
            lines = open(log, encoding='utf-8').read().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])['jt_ai']['tool'], 'Bash')

    def test_bad_input_or_missing_log_still_exits_0_silently(self):
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, 'no-such-dir', 'actions.log')
            for stdin in (b'', b'not json', b'[1,2]', b'\xff\xfe', json.dumps({'tool_name': 'Bash'}).encode()):
                with self.subTest(stdin=stdin):
                    r = run_hook(stdin, missing)
                    self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b'', b''))
            self.assertFalse(os.path.exists(missing), 'the hook must not create the log')



class TestOtherAgents(unittest.TestCase):
    """1.1: Codex (managed hooks) and opencode (the pack's plugin) call the same hook."""

    def test_codex_apply_patch_records_paths_never_the_patch(self):
        patch = ('*** Begin Patch\n*** Update File: src/app.py\n@@\n-x\n+DB_PASSWORD=p4tchSecret\n'
                 '*** Add File: /opt/p/new.py\n+print(1)\n*** End Patch')
        rec = hook.record({'hook_event_name': 'PreToolUse', 'tool_name': 'apply_patch', 'cwd': '/opt/p',
                           'tool_input': {'command': patch}}, 'codex')
        self.assertEqual((rec['agent'], rec['tool'], rec['tool_raw']), ('codex', 'Edit', 'apply_patch'))
        self.assertEqual(rec['path'], '/opt/p/src/app.py')
        self.assertEqual(rec['paths'], '/opt/p/src/app.py,/opt/p/new.py')
        self.assertNotIn('p4tchSecret', json.dumps(rec))
        rec = hook.record({'tool_name': 'apply_patch', 'cwd': '/opt/p',
                           'tool_input': {'command': '*** Begin Patch\n*** Add File: a.txt\n+hi\n*** End Patch'}}, 'codex')
        self.assertEqual(rec['tool'], 'Write')

    def test_codex_shell_is_bash(self):
        rec = hook.record({'tool_name': 'Bash', 'tool_input': {'command': 'mysql -pS3cret'}}, 'codex')
        self.assertEqual((rec['tool'], rec['cmd']), ('Bash', 'mysql -p***'))
        self.assertNotIn('tool_raw', rec)

    def test_opencode_tool_names_are_mapped(self):
        for raw, canon, ti, key in (('bash', 'Bash', {'command': 'ls'}, 'cmd'),
                                    ('read', 'Read', {'filePath': '/root/.ssh/id_rsa'}, 'path'),
                                    ('write', 'Write', {'filePath': '/tmp/a', 'content': 'k3ySecret'}, 'path'),
                                    ('edit', 'Edit', {'filePath': '/tmp/a', 'oldString': 'a', 'newString': 'b'}, 'path'),
                                    ('webfetch', 'WebFetch', {'url': 'https://example.com/'}, 'url'),
                                    ('task', 'Task', {'subagentType': 'general', 'description': 'd', 'prompt': 'p'},
                                     'task_subagent_type'),
                                    ('subagent', 'Task', {'agent': 'explore', 'description': 'd', 'prompt': 'p'},
                                     'task_subagent_type')):
            with self.subTest(raw=raw):
                rec = hook.record({'hook_event_name': 'PreToolUse', 'tool_name': raw, 'tool_input': ti}, 'opencode')
                self.assertEqual((rec['agent'], rec['tool'], rec['tool_raw']), ('opencode', canon, raw))
                self.assertIn(key, rec)
                self.assertNotIn('k3ySecret', json.dumps(rec))

    def test_agent_option(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'actions.log')
            open(log, 'w').close()
            env = dict(os.environ, JT_AI_AGENT_LOG=log)
            event = json.dumps({'hook_event_name': 'SessionStart', 'session_id': 's'}).encode()
            for args, want in (([], 'claude-code'), (['--agent', 'codex'], 'codex'),
                               (['--agent', 'opencode'], 'opencode'), (['--agent', 'bogus'], 'claude-code')):
                r = subprocess.run([sys.executable, HOOK] + args, input=event, capture_output=True, env=env, timeout=30)
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b'', b''))
            agents = [json.loads(x)['jt_ai']['agent'] for x in open(log, encoding='utf-8').read().splitlines()]
            self.assertEqual(agents, ['claude-code', 'codex', 'opencode', 'claude-code'])

    def test_opencode_plugin_never_blocks_and_calls_the_hook(self):
        import shutil
        node = shutil.which('node')
        if not node:
            self.skipTest('node not installed')
        plugin = os.path.join(ROOT, 'packs', 'jt-ai-agent', 'agent', 'jt-ai-agent-opencode.js')
        src = open(plugin, encoding='utf-8').read()
        self.assertIn('/usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py', src)
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'actions.log')
            open(log, 'w').close()
            wrapper = os.path.join(d, 'hook.sh')
            with open(wrapper, 'w') as fh:
                fh.write('#!/bin/sh\nJT_AI_AGENT_LOG=%s exec %s %s "$@"\n' % (log, sys.executable, HOOK))
            os.chmod(wrapper, 0o755)
            with open(os.path.join(d, 'plugin.mjs'), 'w') as fh:
                fh.write(src.replace('/usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py', wrapper))
            with open(os.path.join(d, 'run.mjs'), 'w') as fh:
                fh.write("""import p from './plugin.mjs'
const hooks = {}
async function* events() { yield { type: 'session.updated', properties: { info: { id: 'ses_v2' } } }; yield { type: 'session.created', properties: { info: { id: 'ses_v2' } } }; yield { type: 'session.created', properties: { info: { id: 'ses_v2' } } }; yield { type: 'message.part.updated', properties: {} } }
const ctx = { location: { directory: '/srv/p' }, tool: { hook: async (n, cb) => { hooks[n] = cb } },
  event: { subscribe: () => events() } }
await p.setup(ctx)
const input = { command: 'ls' }
const ev = { tool: 'bash', sessionID: 'ses_v2', callID: 'c1', input }
const r = hooks['execute.before'](ev)
if (r !== undefined || ev.input !== input || input.command !== 'ls') { console.log('CHANGED'); process.exit(3) }
const v1 = await p.server({ directory: '/srv/v1' })
await v1['tool.execute.before']({ tool: 'read', sessionID: 'ses_v1', callID: 'c2' }, { args: { filePath: '/etc/hosts' } })
await v1['tool.execute.before'](undefined, undefined)
setTimeout(() => {}, 1500)
""")
            r = subprocess.run([node, 'run.mjs'], cwd=d, capture_output=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            recs = [json.loads(x)['jt_ai'] for x in open(log, encoding='utf-8').read().splitlines()]
            got = sorted((x['event'], x.get('tool', ''), x['agent']) for x in recs)
            self.assertIn(('PreToolUse', 'Bash', 'opencode'), got)
            self.assertIn(('PreToolUse', 'Read', 'opencode'), got)
            self.assertIn(('SessionStart', '', 'opencode'), got)
            # only session.created counts, once per session (2.0.32 sent hundreds of other events)
            self.assertEqual(sum(1 for x in recs if x['event'] == 'SessionStart' and x.get('session') == 'ses_v2'), 1)



class TestContext12(unittest.TestCase):
    """1.2: who is behind the agent, which project, failures, MCP, credentials in commands."""

    def test_identity_and_project(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, 'proj', '.git'))
            with open(os.path.join(d, 'proj', '.git', 'HEAD'), 'w') as fh:
                fh.write('ref: refs/heads/feature-x\n')
            os.makedirs(os.path.join(d, 'proj', 'src'))
            env = {'SUDO_USER': 'alice', 'SSH_CONNECTION': '198.51.100.9 50000 10.0.0.5 22', 'CI': '1'}
            old = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                rec = hook.record({'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                                   'cwd': os.path.join(d, 'proj', 'src'), 'tool_input': {'command': 'ls'}})
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            if rec['user'] != 'alice':
                self.assertEqual(rec['real_user'], 'alice')
            self.assertEqual((rec['ssh_from'], rec['repo'], rec['branch'], rec['ci']),
                             ('198.51.100.9', 'proj', 'feature-x', True))

    def test_only_failed_post_tool_use_is_written(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'actions.log')
            open(log, 'w').close()
            ok = {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash', 'tool_input': {'command': 'ls'},
                  'tool_response': {'exit_code': 0, 'stdout': 'S3cretOutput'}}
            bad = dict(ok, tool_response={'exit_code': 2, 'stdout': 'S3cretOutput'})
            for e in (ok, bad):
                run_hook(json.dumps(e).encode(), log)
            lines = open(log, encoding='utf-8').read().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])['jt_ai']['event'], 'PostToolUseFailure')
            self.assertNotIn('S3cretOutput', lines[0], 'tool output must never be written')

    def test_mcp_server_and_tool_and_redacted_flag(self):
        rec = hook.record({'tool_name': 'mcp__wazuh__get_alerts', 'tool_input': {'query': 'x'}})
        self.assertEqual((rec['mcp_server'], rec['mcp_tool']), ('wazuh', 'get_alerts'))
        rec = hook.record({'tool_name': 'Bash', 'tool_input': {'command': 'mysql -pHunter2xx -e 1'}})
        self.assertTrue(rec['redacted'])
        self.assertNotIn('Hunter2xx', json.dumps(rec))
        rec = hook.record({'tool_name': 'Bash', 'tool_input': {'command': 'ls -la'}})
        self.assertNotIn('redacted', rec)


class TestGeminiCursorCopilot(unittest.TestCase):
    """1.3: Gemini CLI, Cursor and Copilot read the hook's stdout as JSON, and Copilot denies a
    preToolUse call when the hook exits non-zero: the hook must answer {} and exit 0 whatever
    happens, and must never record output, file contents or prompts."""

    def run_agent(self, args, payload, log):
        env = dict(os.environ, JT_AI_AGENT_LOG=log)
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return subprocess.run([sys.executable, HOOK] + args, input=data, capture_output=True, env=env, timeout=30)

    def lines(self, log):
        return [json.loads(x)['jt_ai'] for x in open(log, encoding='utf-8').read().splitlines()]

    def test_always_answers_empty_json_and_exits_0(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'actions.log')
            for args in (['--agent', 'gemini'], ['--agent', 'cursor'], ['--agent', 'copilot', '--event', 'preToolUse']):
                for stdin in (b'not json', b'', b'[]', json.dumps({'toolName': 'bash'}).encode()):
                    with self.subTest(args=args, stdin=stdin):
                        out = self.run_agent(args, stdin, os.path.join(d, 'missing.log'))
                        self.assertEqual((out.returncode, out.stdout.strip()), (0, b'{}'))
            open(log, 'w').close()
            out = self.run_agent(['--agent', 'claude-code'], {'tool_name': 'Bash', 'tool_input': {'command': 'ls'}}, log)
            self.assertEqual((out.returncode, out.stdout), (0, b''), 'Claude Code: still prints nothing')

    def test_gemini(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'actions.log')
            open(log, 'w').close()
            base = {'session_id': 'g1', 'cwd': '/opt/p'}
            for e in (dict(base, hook_event_name='BeforeTool', tool_name='run_shell_command',
                           tool_input={'command': 'mysql -pS3cretGem -e 1'}),
                      dict(base, hook_event_name='BeforeTool', tool_name='mcp_my_srv_query', tool_input={'q': 1},
                           mcp_context={'server_name': 'my_srv'}),
                      dict(base, hook_event_name='BeforeTool', tool_name='write_file',
                           tool_input={'file_path': '/opt/p/a', 'content': 'S3cretContent'}),
                      dict(base, hook_event_name='AfterTool', tool_name='read_file', tool_input={'file_path': '/x'},
                           tool_response={'llmContent': 'S3cretOutput'}),
                      dict(base, hook_event_name='AfterTool', tool_name='read_file', tool_input={'file_path': '/x'},
                           tool_response={'llmContent': 'S3cretOutput', 'error': 'no such file'}),
                      dict(base, hook_event_name='BeforeAgent', prompt='S3cretPrompt'),
                      dict(base, hook_event_name='Notification', notification_type='ToolPermission',
                           details={'toolName': 'run_shell_command'})):
                self.run_agent(['--agent', 'gemini'], e, log)
            text = open(log, encoding='utf-8').read()
            for secret in ('S3cretGem', 'S3cretContent', 'S3cretOutput', 'S3cretPrompt'):
                self.assertNotIn(secret, text)
            recs = self.lines(log)
            self.assertEqual([(r['event'], r.get('tool')) for r in recs],
                             [('PreToolUse', 'Bash'), ('PreToolUse', 'mcp__my_srv__query'), ('PreToolUse', 'Write'),
                              ('PostToolUseFailure', 'Read'), ('PermissionRequest', 'Bash')])
            self.assertEqual((recs[1]['mcp_server'], recs[1]['mcp_tool']), ('my_srv', 'query'))
            self.assertEqual(recs[0]['tool_raw'], 'run_shell_command')
            self.assertTrue(all(r['agent'] == 'gemini' for r in recs))

    def test_cursor_records_every_call_after_the_fact(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'actions.log')
            open(log, 'w').close()
            base = {'conversation_id': 'c1', 'cwd': '/opt/p', 'user_email': 'dev@example.org'}
            for e in (dict(base, hook_event_name='postToolUse', tool_name='Shell', tool_input={'command': 'make'},
                           tool_output='S3cretOutput'),
                      dict(base, hook_event_name='postToolUseFailure', tool_name='Shell',
                           tool_input={'command': 'rm -rf /'}, error_message='denied', failure_type='permission_denied'),
                      dict(base, hook_event_name='preToolUse', tool_name='Shell', tool_input={'command': 'x'}),
                      dict(base, hook_event_name='beforeSubmitPrompt', prompt='S3cretPrompt'),
                      dict(base, hook_event_name='postToolUse', tool_name='MCP:search', tool_input='{"q": "a"}',
                           mcp_server_name='docs')):
                self.run_agent(['--agent', 'cursor'], e, log)
            text = open(log, encoding='utf-8').read()
            self.assertNotIn('S3cretOutput', text)
            self.assertNotIn('S3cretPrompt', text)
            recs = self.lines(log)
            self.assertEqual([(r['event'], r['tool'], r.get('failed')) for r in recs],
                             [('PostToolUse', 'Bash', None), ('PostToolUse', 'Bash', True),
                              ('PostToolUse', 'mcp__docs__search', None)])
            self.assertEqual(recs[1]['cmd'], 'rm -rf /')
            self.assertIn('permission_denied', recs[1]['error'])
            self.assertEqual(recs[0]['account'], 'dev@example.org')

    def test_copilot_camel_case_and_event_option(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'actions.log')
            open(log, 'w').close()
            base = {'sessionId': 'p1', 'cwd': '/opt/p'}
            for event, e in (('sessionStart', dict(base, source='startup', initialPrompt='S3cretPrompt')),
                             ('preToolUse', dict(base, toolName='bash', toolArgs=json.dumps({'command': 'ls'}))),
                             ('preToolUse', dict(base, toolName='create',
                                                 toolArgs={'path': '/opt/p/a', 'file_text': 'S3cretContent'})),
                             ('postToolUse', dict(base, toolName='bash', toolArgs={'command': 'ls'},
                                                  toolResult={'resultType': 'success', 'textResultForLlm': 'S3cretOutput'})),
                             ('postToolUseFailure', dict(base, toolName='view', toolArgs={'path': '/x'}, error='nope')),
                             ('subagentStart', dict(base, agentName='explore')),
                             ('agentStop', dict(base))):
                out = self.run_agent(['--agent', 'copilot', '--event', event], e, log)
                self.assertEqual(out.stdout.strip(), b'{}')
            text = open(log, encoding='utf-8').read()
            for secret in ('S3cretPrompt', 'S3cretContent', 'S3cretOutput'):
                self.assertNotIn(secret, text)
            recs = self.lines(log)
            self.assertEqual([(r['event'], r.get('tool')) for r in recs],
                             [('SessionStart', None), ('PreToolUse', 'Bash'), ('PreToolUse', 'Write'),
                              ('PostToolUseFailure', 'Read'), ('SubagentStart', None)])
            self.assertEqual((recs[1]['cmd'], recs[2]['path'], recs[2]['size'], recs[4]['subagent']),
                             ('ls', '/opt/p/a', 13, 'explore'))

    def test_installer_configs_never_block(self):
        """The Copilot command must end in exit 0; Cursor must not use permission hooks."""
        m = json.load(open(os.path.join(ROOT, 'packs', 'jt-ai-agent', 'manifest.json'), encoding='utf-8'))
        body = [st['body'] for st in m['setup'] if st.get('since') == '1.3'][0]
        for line in body.splitlines():
            if '--agent copilot' in line:
                self.assertIn('; exit 0', line)
        for blocking in ('beforeShellExecution', 'beforeMCPExecution', 'beforeReadFile', '"preToolUse"'):
            cursor = body.split('Cursor:')[1].split('GitHub Copilot')[0]
            self.assertNotIn(blocking, cursor)


INV = os.path.join(ROOT, 'packs', 'jt-ai-agent', 'scripts', 'jt-ai-agent-inventory.py')
_spec = importlib.util.spec_from_file_location('jt_ai_agent_inventory', INV)
inv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inv)


class TestInventory14(unittest.TestCase):
    """1.4: jt-ai-agent-inventory.py, from syscollector data to findings and events."""

    def data(self, packages=(), processes=(), ports=(), hook=None):
        return {'packages': list(packages), 'processes': list(processes), 'ports': list(ports), 'hook': hook}

    def agent(self, groups=('default',)):
        return {'id': '012', 'name': 'build7', 'ip': 'any', 'status': 'active', 'platform': 'ubuntu',
                'groups': list(groups)}

    def test_unaudited_hook_missing_and_audited(self):
        d = self.data(packages=[{'name': '@anthropic-ai/claude-code', 'version': '2.1.0', 'format': 'npm'}])
        f = inv.findings(self.agent(), d)
        self.assertEqual([(v['event'], v['tool']) for v in f.values()], [('unaudited', 'claude-code')])
        d['hook'] = False
        f = inv.findings(self.agent(('default', 'ai-agent')), d)
        self.assertEqual([v['event'] for v in f.values()], ['hook_missing'])
        d['hook'] = True
        self.assertEqual(inv.findings(self.agent(('default', 'ai-agent')), d), {})

    def test_process_matching_is_not_a_substring_search(self):
        procs = [{'pid': 1, 'name': 'node', 'cmd': '/usr/bin/node', 'argvs': '/usr/local/bin/codex exec x', 'euser': 'dev'},
                 {'pid': 2, 'name': 'grep', 'cmd': '/usr/bin/grep', 'argvs': 'claude notes.txt', 'euser': 'dev'},
                 {'pid': 3, 'name': 'vim', 'cmd': '/usr/bin/vim', 'argvs': 'gemini-notes.md', 'euser': 'dev'}]
        f = inv.findings(self.agent(), self.data(processes=procs))
        self.assertEqual(sorted(v['tool'] for v in f.values()), ['codex'])

    def test_windows_display_name_and_aider(self):
        d = self.data(packages=[{'name': 'Cursor (User)', 'version': '2.0.1', 'format': 'win'},
                                {'name': 'aider-chat', 'version': '0.86.0', 'format': 'pypi'},
                                {'name': 'cursor-theme-pack', 'version': '1', 'format': 'deb'}])
        f = inv.findings(self.agent(), d)
        self.assertEqual(sorted((v['event'], v['tool']) for v in f.values()),
                         [('no_hook', 'aider'), ('unaudited', 'cursor')])

    def test_model_server_exposure_by_pid_and_name(self):
        procs = [{'pid': 900, 'name': 'ollama', 'cmd': '/usr/local/bin/ollama', 'argvs': 'serve', 'euser': 'ollama'}]
        local = [{'protocol': 'tcp', 'local_ip': '127.0.0.1', 'local_port': 11434, 'state': 'listening', 'pid': 900,
                  'process': 'ollama'}]
        f = inv.findings(self.agent(), self.data(processes=procs, ports=local))
        self.assertEqual([v['event'] for v in f.values()], ['model_server'])
        wide = local + [{'protocol': 'tcp6', 'local_ip': '::', 'local_port': 11434, 'state': 'listening', 'pid': 900,
                         'process': 'ollama'}]
        f = inv.findings(self.agent(), self.data(processes=procs, ports=wide))
        (only,) = f.values()
        self.assertEqual((only['event'], only['listen']), ('model_exposed', ['tcp6 :::11434']))
        vllm = [{'pid': 77, 'name': 'python3', 'cmd': '/usr/bin/python3', 'argvs': '-m vllm.entrypoints.openai.api_server',
                 'euser': 'ai'}]
        port = [{'protocol': 'tcp', 'local_ip': '0.0.0.0', 'local_port': 8000, 'state': 'listening', 'pid': 77,
                 'process': 'python3'}]
        (only,) = inv.findings(self.agent(), self.data(processes=vllm, ports=port)).values()
        self.assertEqual((only['tool'], only['event']), ('vllm', 'model_exposed'))

    def test_production_shapes_from_a_gpu_host_and_a_proxmox_host(self):
        """1.0.1: shapes seen on the first production run."""
        procs = [{'pid': '4052', 'name': 'ollama', 'cmd': '/bin/ollama', 'argvs': 'serve', 'euser': 'root'},
                 {'pid': '3717175', 'name': 'llama-server', 'cmd': '/usr/lib/ollama/llama-server',
                  'argvs': '--model x --port 35233 --host 127.0.0.1', 'euser': 'root'},
                 {'pid': '804302', 'name': 'VLLM::EngineCore', 'cmd': 'VLLM::EngineCore', 'euser': 'root'},
                 {'pid': '397329', 'name': 'opencode', 'cmd': '/opt/opencode/2.0.32/opencode', 'euser': '101000'}]
        ports = [{'protocol': 'tcp', 'local_ip': '127.0.0.1', 'local_port': 35233, 'state': 'listening',
                  'PID': 3717175, 'process': 'llama-server'},
                 {'protocol': 'tcp6', 'local_ip': '::', 'local_port': 46845, 'state': 'listening', 'PID': 804302,
                  'process': 'VLLM::EngineCor'},
                 {'protocol': 'tcp', 'local_ip': '0.0.0.0', 'local_port': 11434, 'state': 'listening', 'PID': 37634,
                  'process': 'python3'}]
        f = inv.findings(self.agent(), self.data(processes=procs, ports=ports))
        got = sorted((v['tool'], v['event'], tuple(v.get('listen', ()))) for v in f.values())
        self.assertEqual(got, [('ollama', 'model_server', ()), ('vllm', 'model_exposed', ('tcp6 :::46845',))],
                         'container processes and Ollama\'s own runner are not findings; PID is upper case in sys_ports')

    def test_evaluate_reports_once_reminds_weekly_and_clears(self):
        found = inv.findings(self.agent(), self.data(packages=[{'name': 'codex', 'version': '0.1', 'format': 'brew'}]))
        now = 1_800_000_000
        ev, st = inv.evaluate(found, {}, {'012'}, now)
        self.assertEqual([(e['event'], e['change']) for e in ev], [('unaudited', 'new')])
        ev, st2 = inv.evaluate(found, st, {'012'}, now + 3600)
        self.assertEqual(ev, [])
        ev, st3 = inv.evaluate(found, st2, {'012'}, now + 8 * 86400)
        self.assertEqual([e['change'] for e in ev], ['reminder'])
        ev, st4 = inv.evaluate({}, st3, set(), now + 9 * 86400)
        self.assertEqual((ev, st4), ([], st3), 'an agent not scanned keeps its findings')
        ev, st5 = inv.evaluate({}, st3, {'012'}, now + 9 * 86400)
        self.assertEqual([(e['event'], e['was']) for e in ev], [('cleared', 'unaudited')])
        self.assertEqual(st5, {})

    def test_agents_of_node_and_queries_are_select_only(self):
        seen = []
        rows = {'global': [{'id': 0, 'name': 'mgr', 'node_name': 'n1', 'connection_status': 'active'},
                           {'id': 12, 'name': 'build7', 'node_name': 'n1', 'connection_status': 'active',
                            'groups': 'default,ai-agent'},
                           {'id': 13, 'name': 'win', 'node_name': 'n2', 'connection_status': 'active'},
                           {'id': 14, 'name': 'new', 'node_name': 'n1', 'connection_status': 'never_connected'}]}
        saved = inv.wdb_query
        try:
            inv.wdb_query = lambda path, q: (seen.append(q), rows['global'] if q.startswith('global') else [])[1]
            agents = inv.agents_of_node('/x', 'n1')
            self.assertEqual([(a['id'], a['groups']) for a in agents], [('012', ['default', 'ai-agent'])])
            inv.collect('/x', agents[0])
        finally:
            inv.wdb_query = saved
        for q in seen:
            self.assertRegex(q, r'^(?:global|agent \d{3}) sql SELECT ')
            self.assertNotRegex(q.upper(), r'\b(?:INSERT|UPDATE|DELETE|DROP|ATTACH|PRAGMA)\b')


class TestBrowser15(unittest.TestCase):
    """1.5: browser automation through MCP: the action is recorded, never what was typed or run."""

    def rec(self, tool, ti):
        return hook.record({'hook_event_name': 'PreToolUse', 'tool_name': tool, 'tool_input': ti})

    def test_actions_and_no_content(self):
        cases = [
            ('mcp__claude-in-chrome__computer', {'action': 'screenshot', 'tabId': 3}, 'screenshot'),
            ('mcp__claude-in-chrome__computer', {'action': 'left_click', 'coordinate': [1, 2]}, 'click'),
            ('mcp__claude-in-chrome__computer', {'action': 'type', 'text': 'S3cretTyped'}, 'type'),
            ('mcp__claude-in-chrome__javascript_tool', {'action': 'javascript_exec', 'text': 'S3cretCode()'}, 'evaluate'),
            ('mcp__playwright__browser_type', {'element': 'Password', 'ref': 'e1', 'text': 'S3cretPw'}, 'type'),
            ('mcp__playwright__browser_fill_form', {'fields': [{'name': 'Password', 'type': 'textbox', 'ref': 'e2',
                                                              'value': 'S3cretFill'}]}, 'fill'),
            ('mcp__chrome-devtools__evaluate_script', {'function': '() => S3cretFn'}, 'evaluate'),
            ('mcp__puppeteer__puppeteer_navigate', {'url': 'https://example.org/'}, 'navigate'),
            ('mcp__playwright__browser_network_requests', {}, 'network'),
            ('mcp__playwright__browser_file_upload', {'paths': ['/tmp/a.pdf']}, 'upload'),
        ]
        for tool, ti, action in cases:
            with self.subTest(tool=tool, action=action):
                r = self.rec(tool, ti)
                self.assertEqual(r.get('browser_action'), action)
                self.assertNotIn('S3cret', json.dumps(r))
        r = self.rec('mcp__playwright__browser_type', {'element': 'Password', 'ref': 'e1', 'text': 'S3cretPw'})
        self.assertEqual((r['text_len'], r.get('browser_secret')), (8, True))
        r = self.rec('mcp__claude-in-chrome__javascript_tool', {'action': 'javascript_exec', 'text': 'S3cretCode()'})
        self.assertEqual(r['js_len'], 12)
        self.assertNotIn('browser_action', self.rec('mcp__docs__search', {'query': 'x'}))


class TestOpencodeMcp152(unittest.TestCase):
    """1.5.2: opencode names an MCP tool <server>_<tool>; the server names come from its config."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {'HOME': self.tmp}, clear=False)
        self.env.start()
        os.environ.pop('XDG_CONFIG_HOME', None)
        os.environ.pop('OPENCODE_CONFIG', None)
        conf = os.path.join(self.tmp, '.config', 'opencode')
        os.makedirs(conf)
        with open(os.path.join(conf, 'opencode.jsonc'), 'w') as fh:
            fh.write('{\n // servers\n "mcp": {"pve": {"url": "http://10.0.0.1//sse"}, "jt-ipam": {},'
                     ' "zimbra_mail1": {}, "zimbra": {},},\n}')
        self.pw = mock.patch.object(hook.pwd, 'getpwuid', side_effect=KeyError)
        self.pw.start()

    def tearDown(self):
        self.pw.stop()
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rec(self, tool, ti=None, cwd='/nonexistent/project'):
        return hook.record({'hook_event_name': 'PreToolUse', 'tool_name': tool, 'tool_input': ti or {'a': 1},
                            'cwd': cwd}, 'opencode')

    def test_server_prefix(self):
        r = self.rec('pve_get_cluster_nodes')
        self.assertEqual((r['tool'], r['mcp_server'], r['mcp_tool'], r['tool_raw']),
                         ('mcp__pve__get_cluster_nodes', 'pve', 'get_cluster_nodes', 'pve_get_cluster_nodes'))
        self.assertEqual(self.rec('jt-ipam_search')['mcp_server'], 'jt-ipam')
        # the longest server name wins over a shorter one that also prefixes the tool
        self.assertEqual(self.rec('zimbra_mail1_send')['mcp_server'], 'zimbra_mail1')
        self.assertEqual(self.rec('zimbra_quota')['mcp_server'], 'zimbra')

    def test_builtin_and_unknown_tools_unchanged(self):
        self.assertEqual(self.rec('bash', {'command': 'ls'})['tool'], 'Bash')
        r = self.rec('other_tool')
        self.assertEqual(r['tool'], 'other_tool')
        self.assertNotIn('mcp_server', r)
        self.assertNotIn('mcp_server', self.rec('pve'))

    def test_project_config_and_other_agents(self):
        proj = os.path.join(self.tmp, 'work', 'sub')
        os.makedirs(proj)
        with open(os.path.join(self.tmp, 'work', 'opencode.json'), 'w') as fh:
            json.dump({'mcp': {'docs': {}}}, fh)
        self.assertEqual(self.rec('docs_search', cwd=proj)['mcp_server'], 'docs')
        r = hook.record({'hook_event_name': 'PreToolUse', 'tool_name': 'pve_get_cluster_nodes',
                         'tool_input': {'a': 1}}, 'claude-code')
        self.assertNotIn('mcp_server', r)

    def test_code_mode_records_length_only(self):
        r = self.rec('execute', {'code': 'await pve.secret_S3cret()'})
        self.assertEqual((r['tool'], r['tool_raw'], r['js_len']), ('CodeMode', 'execute', 25))
        self.assertNotIn('S3cret', json.dumps(r))


class TestGeminiHookOff153(unittest.TestCase):
    """1.5.3: a user or project Gemini setting that turns the audit hook off is reported at session start."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {'HOME': self.tmp}, clear=False)
        self.env.start()
        self.pw = mock.patch.object(hook.pwd, 'getpwuid', side_effect=KeyError)
        self.pw.start()
        self.proj = os.path.join(self.tmp, 'work', 'app')
        os.makedirs(self.proj)

    def tearDown(self):
        self.pw.stop()
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def settings(self, where, text):
        d = os.path.join(where, '.gemini')
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, 'settings.json'), 'w') as fh:
            fh.write(text)

    def start(self, agent='claude-code'):
        return hook.record({'hook_event_name': 'SessionStart', 'source': 'startup', 'cwd': self.proj}, agent)

    def test_nothing_when_not_disabled(self):
        self.settings(self.tmp, '{"mcpServers": {"x": {"env": {"TOKEN": "S3cret"}}}}')
        r = self.start()
        self.assertNotIn('gemini_hook_off', r)
        self.assertNotIn('S3cret', json.dumps(r))

    def test_user_disabled_list(self):
        self.settings(self.tmp, '{\n // mine\n "hooksConfig": {"disabled": ["jt-ai-agent"]},'
                                ' "mcpServers": {"x": {"env": {"TOKEN": "S3cret"}}},\n}')
        r = self.start()
        self.assertIn('user:', r['gemini_hook_off'])
        self.assertIn('jt-ai-agent disabled', r['gemini_hook_off'])
        self.assertNotIn('S3cret', json.dumps(r))

    def test_project_and_hooks_off(self):
        self.settings(os.path.join(self.tmp, 'work'), '{"hooksConfig": {"enabled": false}}')
        r = self.start('gemini')
        self.assertIn('project:%s' % os.path.join(self.tmp, 'work', '.gemini', 'settings.json'), r['gemini_hook_off'])
        self.assertIn('hooks off', r['gemini_hook_off'])

    def test_by_command_and_old_key(self):
        self.settings(self.tmp, '{"hooks": {"disabled": ["/usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py --agent gemini"]}}')
        self.assertIn('jt-ai-agent disabled', self.start()['gemini_hook_off'])

    def test_only_at_session_start(self):
        self.settings(self.tmp, '{"hooksConfig": {"disabled": ["jt-ai-agent"]}}')
        r = hook.record({'hook_event_name': 'PreToolUse', 'tool_name': 'Bash', 'tool_input': {'command': 'ls'},
                         'cwd': self.proj})
        self.assertNotIn('gemini_hook_off', r)


class TestInventorySilent153(unittest.TestCase):
    """1.5.3: an audited agent that is running but sends nothing (hook turned off)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, 'logs', 'alerts'))
        self.path = os.path.join(self.tmp, 'logs', 'alerts', 'alerts.json')
        open(self.path, 'w').close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def alert(self, when, host, agent):
        ts = time.strftime('%Y-%m-%dT%H:%M:%S.000+0800', time.localtime(when))
        return json.dumps({'timestamp': ts, 'rule': {'id': '133702'}, 'agent': {'id': '012', 'name': host},
                           'data': {'jt_ai': {'v': '1', 'host': host, 'agent': agent}},
                           'full_log': 'jt-ai-agent: {"jt_ai":{"agent":"%s"}}' % agent}) + '\n'

    def write(self, *lines):
        with open(self.path, 'a') as fh:
            fh.writelines(lines)

    def running(self, start, tool_proc='gemini'):
        return {'packages': [], 'ports': [], 'hook': True,
                'processes': [{'pid': 7, 'name': 'node', 'cmd': '/usr/bin/node', 'argvs': '/usr/bin/%s' % tool_proc,
                               'euser': 'dev', 'start_time': start}]}

    def agent(self):
        return {'id': '012', 'name': 'build7', 'ip': 'any', 'groups': ['default', 'ai-agent']}

    def test_incremental_reading_and_partial_lines(self):
        now = int(time.time())
        self.write(self.alert(now - 100, 'build7', 'gemini'), '{"timestamp":"2026-11-16T10:00:00", "partial')
        seen = {}
        pos, since = inv.scan_alerts(self.tmp, None, seen, now)
        self.assertEqual(since, now)                       # the first run vouches only from now on
        self.assertEqual(list(seen), ['build7|gemini'])
        self.assertLess(pos['offset'], os.path.getsize(self.path))   # stops before the partial line
        self.write(' line"}\n', self.alert(now - 50, 'build7', 'claude-code'))
        pos, _ = inv.scan_alerts(self.tmp, pos, seen, now)
        self.assertEqual(sorted(seen), ['build7|claude-code', 'build7|gemini'])
        self.assertEqual(pos['offset'], os.path.getsize(self.path))

    def test_silent_when_started_and_never_heard_from(self):
        now = int(time.time())
        a, since = self.agent(), now - 48 * 3600
        d = self.running(now - 3600)
        f = inv.findings(a, d, {}, now, since)
        self.assertEqual([(v['event'], v['tool']) for v in f.values()], [('silent', 'gemini')])
        self.assertIn('none seen', ' '.join(f['012:gemini:silent']['evidence']))
        # heard from after it started: fine
        self.assertEqual(inv.findings(a, d, {'build7|gemini': now - 3000}, now, since), {})
        # heard from only before it started: silent
        self.assertIn('012:gemini:silent', inv.findings(a, d, {'build7|gemini': now - 7200}, now, since))
        # started a minute ago: give the session-start line time to arrive
        self.assertEqual(inv.findings(a, self.running(now - 60), {}, now, since), {})
        # started before the alerts were read without gaps, or more than a day ago: not judged
        self.assertEqual(inv.findings(a, d, {}, now, now - 1800), {})
        self.assertEqual(inv.findings(a, self.running(now - 30 * 3600), {}, now, since), {})
        # a long-running server (opencode serve) sits idle legitimately
        srv = self.running(now - 3600, 'opencode serve --port 4096')
        self.assertEqual(inv.findings(a, srv, {}, now, since), {})
        # agents that only log once they are used (the Cursor app) are not judged
        self.assertEqual(inv.findings(a, self.running(now - 3600, 'cursor'), {}, now, since), {})
        # an installed package alone (no process) is not "started"
        pkg = {'packages': [{'name': '@google/gemini-cli', 'version': '1', 'format': 'npm'}], 'processes': [],
               'ports': [], 'hook': True}
        self.assertEqual(inv.findings(a, pkg, {}, now, since), {})
        # no alerts reading: nothing judged
        self.assertEqual(inv.findings(a, d, {}, now, None), {})

    def test_rotation_reads_the_rest_of_the_old_day(self):
        now = int(time.time())
        self.write(self.alert(now - 300, 'build7', 'codex'))
        seen = {}
        pos, _ = inv.scan_alerts(self.tmp, None, seen, now)
        pos['since'] = now - 30 * 3600
        self.write(self.alert(now - 200, 'build7', 'gemini'))      # after the last read, before midnight
        day = time.strptime(pos['day'], '%Y-%m-%d')
        d = os.path.join(self.tmp, 'logs', 'alerts', time.strftime('%Y', day), time.strftime('%b', day))
        os.makedirs(d)
        os.link(self.path, os.path.join(d, 'ossec-alerts-%s.json' % time.strftime('%d', day)))
        os.unlink(self.path)
        with open(self.path, 'w') as fh:
            fh.write(self.alert(now - 10, 'build7', 'opencode'))
        pos2, since = inv.scan_alerts(self.tmp, pos, seen, now)
        self.assertEqual(since, now - 30 * 3600)
        self.assertEqual(sorted(seen), ['build7|codex', 'build7|gemini', 'build7|opencode'])
        # the old day gone: not covered any more
        shutil.rmtree(os.path.join(self.tmp, 'logs', 'alerts', time.strftime('%Y', day)))
        pos2['inode'] = -1
        _, since = inv.scan_alerts(self.tmp, pos2, seen, now)
        self.assertEqual(since, now)


class TestPrompts16(unittest.TestCase):
    """1.6: prompts, off unless the server turns them on."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = os.path.join(self.tmp, 'actions.log')
        self.plog = os.path.join(self.tmp, 'prompts.log')
        self.conf = os.path.join(self.tmp, 'config')
        for f in (self.log, self.plog):
            open(f, 'w').close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_hook(self, payload, mode=None, args=('--agent', 'claude-code')):
        if mode is not None:
            with open(self.conf, 'w') as fh:
                fh.write('# x\nprompts = %s\n' % mode)
        env = dict(os.environ, JT_AI_AGENT_LOG=self.log, JT_AI_AGENT_PROMPT_LOG=self.plog,
                   JT_AI_AGENT_CONFIG=self.conf, HOME=self.tmp)
        r = subprocess.run([sys.executable, HOOK] + list(args), input=json.dumps(payload), capture_output=True,
                           text=True, env=env)
        lines = [json.loads(x) for x in open(self.log).read().splitlines()]
        plines = [json.loads(x) for x in open(self.plog).read().splitlines()]
        return r, lines, plines

    P = {'hook_event_name': 'UserPromptSubmit', 'session_id': 's1', 'cwd': '/tmp',
         'prompt': 'deploy with DB_PASSWORD=S3cretPw please'}

    def test_off_by_default_and_when_off(self):
        for mode in (None, 'off', 'garbage'):
            with self.subTest(mode=mode):
                if mode is None and os.path.exists(self.conf):
                    os.unlink(self.conf)
                r, lines, plines = self.run_hook(self.P, mode)
                self.assertEqual((r.returncode, r.stdout, lines, plines), (0, '', [], []))

    def test_local_keeps_the_text_on_the_host_only(self):
        r, lines, plines = self.run_hook(self.P, 'local')
        self.assertEqual(r.stdout, '')                       # Claude Code: stdout would become context
        j = lines[0]['jt_ai']
        self.assertEqual((j['event'], j['prompt_len'], j['prompt_redacted'], j['prompt_stored']),
                         ('UserPromptSubmit', len(self.P['prompt']), True, True))
        self.assertNotIn('prompt', j)
        self.assertNotIn('S3cret', json.dumps(lines) + json.dumps(plines))
        self.assertIn('DB_PASSWORD=***', plines[0]['jt_ai_prompt']['prompt'])
        self.assertEqual(plines[0]['jt_ai_prompt']['prompt_sha'], j['prompt_sha'])

    def test_wazuh_sends_the_beginning(self):
        long = dict(self.P, prompt='x' * 5000)
        _, lines, plines = self.run_hook(long, 'wazuh')
        j = lines[0]['jt_ai']
        self.assertEqual(len(j['prompt']), 2003)
        self.assertEqual(len(plines[0]['jt_ai_prompt']['prompt']), 5000)

    def test_gemini_and_copilot_shapes(self):
        r, lines, _ = self.run_hook({'hook_event_name': 'BeforeAgent', 'session_id': 'g', 'cwd': '/tmp',
                                     'prompt': 'hello'}, 'local', ('--agent', 'gemini'))
        self.assertEqual(r.stdout.strip(), '{}')
        self.assertEqual((lines[0]['jt_ai']['event'], lines[0]['jt_ai']['agent']), ('UserPromptSubmit', 'gemini'))
        r, lines, _ = self.run_hook({'sessionId': 'c', 'cwd': '/tmp', 'timestamp': 1, 'prompt': 'hi'}, 'local',
                                    ('--agent', 'copilot', '--event', 'userPromptSubmitted'))
        self.assertEqual(lines[-1]['jt_ai']['event'], 'UserPromptSubmit')
        self.assertEqual(lines[-1]['jt_ai']['prompt_len'], 2)

    def test_no_prompt_log_still_records_the_line(self):
        os.unlink(self.plog)
        with open(self.conf, 'w') as fh:
            fh.write('prompts = local\n')
        env = dict(os.environ, JT_AI_AGENT_LOG=self.log, JT_AI_AGENT_PROMPT_LOG=self.plog,
                   JT_AI_AGENT_CONFIG=self.conf, HOME=self.tmp)
        subprocess.run([sys.executable, HOOK], input=json.dumps(self.P), capture_output=True, text=True, env=env)
        j = json.loads(open(self.log).read().splitlines()[0])['jt_ai']
        self.assertFalse(j['prompt_stored'])

    def test_parse_config(self):
        self.assertEqual(hook.parse_config('prompts = LOCAL # x\nprompts = off\n'), {'prompts': 'local'})
        self.assertEqual(hook.parse_config('prompts = all\nother = 1\n'), {})

    def test_sync_config_copies_and_reports_changes(self):
        shared = os.path.join(self.tmp, 'shared.conf')
        with mock.patch.object(hook, 'CONFIG_SHARED', (shared,)), mock.patch.object(hook, 'CONFIG_LOCAL', self.conf), \
                mock.patch.object(hook, 'LOG', self.log):
            hook.sync_config()                                    # nothing delivered yet: nothing happens
            self.assertFalse(os.path.exists(self.conf))
            with open(shared, 'w') as fh:
                fh.write('# from the manager\nprompts = local\n')
            hook.sync_config()
            self.assertEqual(hook.parse_config(open(self.conf).read()), {'prompts': 'local'})
            self.assertEqual(oct(os.stat(self.conf).st_mode & 0o777), '0o644')
            hook.sync_config()                                    # unchanged: no second line
            with open(shared, 'w') as fh:
                fh.write('prompts = off\n')
            hook.sync_config()
        lines = [json.loads(x)['jt_ai'] for x in open(self.log).read().splitlines()]
        self.assertEqual([(x['event'], x['prompts'], x['previous']) for x in lines],
                         [('AuditConfig', 'local', 'none'), ('AuditConfig', 'off', 'local')])


AGENT_DIR = os.path.join(ROOT, 'packs', 'jt-ai-agent', 'agent')
PWSH_IMAGE = 'mcr.microsoft.com/powershell:latest'


def _ps1(name):
    with open(os.path.join(AGENT_DIR, name), 'rb') as fh:
        return fh.read()


def _ps_map(text, key):
    """The 'k' = 'v' pairs of one entry of a PowerShell hashtable literal ('copilot' = @{ ... })."""
    i = re.search(r"'%s'\s*=\s*@\{" % re.escape(key), text).start() if key else 0
    start = text.index('@{', i) + 2
    body = text[start:text.index('}', start)]
    return dict(re.findall(r"'([^']+)'\s*=\s*'([^']+)'", body))


class TestWindowsBeta16(unittest.TestCase):
    """1.6: the Windows PowerShell hook and installer (BETA)."""

    def test_scripts_are_ascii_with_crlf(self):
        # Windows PowerShell 5.1 reads a script without a byte-order mark as the ANSI code page:
        # anything but ASCII would be read differently on a Chinese or Japanese Windows
        for name in ('jt-ai-agent-hook.ps1', 'jt-ai-agent-install.ps1', 'jt-ai-agent-uninstall.ps1',
                     'jt-ai-agent-check.ps1'):
            data = _ps1(name)
            data.decode('ascii')
            self.assertNotIn(b'\n', data.replace(b'\r\n', b''), name)

    def test_marked_beta(self):
        for name in ('jt-ai-agent-hook.ps1', 'jt-ai-agent-install.ps1', 'jt-ai-agent-uninstall.ps1',
                     'jt-ai-agent-check.ps1'):
            self.assertIn(b'BETA', _ps1(name)[:1500], name)
        self.assertIn(b"$rec['hook'] = 'ps1-beta'", _ps1('jt-ai-agent-hook.ps1'))
        m = json.load(open(os.path.join(ROOT, 'packs', 'jt-ai-agent', 'manifest.json'), encoding='utf-8'))
        win = [s for s in m['setup'] if s['platform'] == 'windows']
        self.assertTrue(win)
        for s in win:
            self.assertIn('(beta)', s['title'])
            self.assertIn('（beta）', s['title_zh'])
            self.assertTrue(s['body'].startswith('BETA'))
            self.assertTrue(s['body_zh'].startswith('BETA'))
        self.assertTrue(any('BETA' in n and 'Windows' in n for n in m['notes']))
        self.assertTrue(any('BETA' in n and 'Windows' in n for n in m['notes_zh']))
        for f in ('jt-ai-agent-hook.ps1', 'jt-ai-agent-install.ps1', 'jt-ai-agent-uninstall.ps1', 'jt-ai-agent-check.ps1'):
            self.assertIn(f, m['agent_group']['files'])

    def test_redact_block_is_generated_from_the_python_hook(self):
        spec = importlib.util.spec_from_file_location('gen_ps1_redact', os.path.join(ROOT, 'tools', 'gen_ps1_redact.py'))
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        text = _ps1('jt-ai-agent-hook.ps1').decode('ascii').replace('\r\n', '\n')
        i, j = text.index(gen.BEGIN), text.index(gen.END) + len(gen.END)
        self.assertEqual(text[i:j], gen.block(), 'run tools/gen_ps1_redact.py --write')
        # .NET regexes are case-sensitive unless told otherwise
        for rx, _ in hook.REDACT:
            if rx.flags & re.I:
                self.assertTrue(rx.pattern.startswith('(?i)') or '(?i)' in rx.pattern, rx.pattern)

    def test_tool_and_event_maps_match_the_python_hook(self):
        text = _ps1('jt-ai-agent-hook.ps1').decode('ascii')
        for agent, py in (('codex', hook.CODEX_TOOLS), ('gemini', hook.GEMINI_TOOLS),
                          ('copilot', hook.COPILOT_TOOLS)):
            self.assertEqual(_ps_map(text, agent), py, agent)
        cursor = {k: v for k, v in hook.CURSOR_TOOLS.items() if k != v or k == 'Delete'}
        self.assertEqual(_ps_map(text, 'cursor'), cursor)
        gem = text[text.index('$GeminiEvents'):]
        self.assertEqual(_ps_map(gem, ''), hook.GEMINI_EVENTS)

    def test_installer_hooks_every_prompt_event(self):
        inst = _ps1('jt-ai-agent-install.ps1').decode('ascii')
        for ev in ("'UserPromptSubmit'", "'BeforeAgent'", "'userPromptSubmitted'"):
            self.assertIn(ev, inst)
        # Cursor's prompt hook can block the prompt; its before-hooks are permission hooks
        cursor = inst[inst.index('== Cursor'):inst.index('== GitHub Copilot')]
        self.assertNotRegex(cursor, r"'before\w+'")
        self.assertIn("; exit 0", inst)          # Copilot denies preToolUse when a hook fails
        self.assertIn('-TestRoot', inst)
        self.assertIn('[string]$Agents', inst)
        self.assertIn("[ValidateSet('', 'off', 'local', 'wazuh')][string]$Prompts", inst)
        un = _ps1('jt-ai-agent-uninstall.ps1').decode('ascii')
        self.assertIn('jt-ai-agent-hook\\.ps1', un)           # only our own entries are taken out
        self.assertIn('[switch]$RemoveLogs', un)

    def test_inventory_looks_for_the_windows_hook_on_windows(self):
        seen = []
        saved = inv.wdb_query
        try:
            inv.wdb_query = lambda path, q: (seen.append(q), [])[1]
            inv.collect('/x', {'id': '044', 'platform': 'windows'})
            inv.collect('/x', {'id': '045', 'platform': 'ubuntu'})
        finally:
            inv.wdb_query = saved
        fim = [q for q in seen if 'fim_entry' in q]
        self.assertTrue(any(inv.HOOK_WINDOWS in q and q.startswith('agent 044') for q in fim))
        self.assertTrue(any(inv.HOOK in q and q.startswith('agent 045') for q in fim))
        self.assertTrue(all('COLLATE NOCASE' in q for q in fim))

    def test_agent_conf_collects_the_windows_log(self):
        conf = open(os.path.join(AGENT_DIR, 'agent.conf'), encoding='utf-8').read()
        win = conf[conf.index('os="Windows"'):]
        win = win[:win.index('</agent_config>')]
        self.assertIn(r'C:\ProgramData\jt-ai-agent\actions.log', win)
        self.assertIn('jt-ai-agent: $(log)', win)
        self.assertIn(r'C:\Program Files\jt-ai-agent', win)

    @unittest.skipUnless(shutil.which('docker') and subprocess.run(
        ['docker', 'image', 'inspect', PWSH_IMAGE], capture_output=True).returncode == 0,
        'PowerShell container image not present')
    def test_hook_in_powershell(self):
        """Runs the hook in PowerShell 7 (Linux container) on the same inputs as the Python hook."""
        tmp = tempfile.mkdtemp()
        try:
            shutil.copy(os.path.join(AGENT_DIR, 'jt-ai-agent-hook.ps1'), tmp)
            for name in ('actions.log', 'prompts.log'):    # the installer creates them; the hook only appends
                open(os.path.join(tmp, name), 'w').close()
            inputs = [
                ('claude-code', '', {'hook_event_name': 'PreToolUse', 'session_id': 's', 'cwd': 'C:\\w', 'tool_name': 'PowerShell',
                                     'tool_input': {'command': 'git push https://u:ghp_abcdefghijklmnopqrstuvwx@h/r'}}),
                ('codex', '', {'hook_event_name': 'PreToolUse', 'session_id': 's', 'tool_name': 'shell',
                               'tool_input': {'command': ['powershell', '-c', 'dir']}}),
                ('gemini', '', {'hook_event_name': 'BeforeTool', 'session_id': 's', 'tool_name': 'read_file',
                                'tool_input': {'file_path': 'C:\\Users\\a\\notes.txt'}}),
                ('cursor', '', {'hook_event_name': 'postToolUse', 'conversation_id': 'u', 'tool_name': 'Shell',
                                'tool_input': {'command': 'dir'}}),
                ('copilot', 'preToolUse', {'timestamp': 1, 'cwd': 'C:\\w', 'toolName': 'powershell',
                                           'toolArgs': json.dumps({'command': 'dir'})}),
                ('claude-code', '', {'hook_event_name': 'UserPromptSubmit', 'session_id': 's',
                                     'prompt': '\u4e2d\u6587 DB_PASSWORD=hunter2'}),
            ]
            script = ["$env:JT_AI_AGENT_LOG = '/w/actions.log'; $env:JT_AI_AGENT_PROMPT_LOG = '/w/prompts.log'",
                      "$env:JT_AI_AGENT_CONFIG = '/w/config'; Set-Content /w/config 'prompts = wazuh'"]
            for n, (agent, event, data) in enumerate(inputs):
                with open(os.path.join(tmp, 'in%d.json' % n), 'w', encoding='utf-8') as fh:
                    json.dump(data, fh, ensure_ascii=False)
                ev = (' -Event ' + event) if event else ''
                script.append("Get-Content -Raw -Encoding utf8 /w/in%d.json | pwsh -NoProfile -File /w/jt-ai-agent-hook.ps1 -Agent %s%s | Out-Null"
                              % (n, agent, ev))
            with open(os.path.join(tmp, 'run.ps1'), 'w') as fh:
                fh.write('\n'.join(script) + '\n')
            r = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '-v', '%s:/w' % tmp, PWSH_IMAGE,
                                'pwsh', '-NoProfile', '-File', '/w/run.ps1'], capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(tmp, 'actions.log'), encoding='utf-8') as fh:
                lines = [json.loads(x)['jt_ai'] for x in fh if x.strip()]
            self.assertEqual(len(lines), len(inputs))
            for rec in lines:
                self.assertEqual((rec['platform'], rec['hook']), ('windows', 'ps1-beta'))
            self.assertEqual([r_.get('tool') for r_ in lines[:5]], ['Bash', 'Bash', 'Read', 'Bash', 'Bash'])
            self.assertNotIn('ghp_', lines[0]['cmd'])
            self.assertTrue(lines[0].get('redacted'))
            self.assertEqual(lines[2]['path'], 'C:/Users/a/notes.txt')
            self.assertEqual(lines[5]['event'], 'UserPromptSubmit')
            self.assertEqual(lines[5]['prompt'], '\u4e2d\u6587 DB_PASSWORD=***')
            # same length and hash as the Python hook gives
            prompt = '\u4e2d\u6587 DB_PASSWORD=hunter2'
            self.assertEqual(lines[5]['prompt_len'], len(prompt))
            self.assertEqual(lines[5]['prompt_sha'],
                             hashlib.sha256(hook.redact(prompt).encode('utf-8')).hexdigest()[:16])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestEnvOverrides161(unittest.TestCase):
    """1.6.1: the installed hook ignores the JT_AI_AGENT_* test variables (the
    user who runs the agent controls the environment)."""

    def test_installed_python_hook_ignores_the_variables(self):
        with mock.patch.dict(os.environ, {'JT_AI_AGENT_LOG': '/tmp/elsewhere.log'}):
            with mock.patch.object(hook, 'INSTALLED', True):
                self.assertEqual(hook._test_path('JT_AI_AGENT_LOG', '/var/log/x'), '/var/log/x')
            with mock.patch.object(hook, 'INSTALLED', False):
                self.assertEqual(hook._test_path('JT_AI_AGENT_LOG', '/var/log/x'), '/tmp/elsewhere.log')
        self.assertEqual(hook.INSTALL_DIR, '/usr/local/lib/jt-ai-agent')
        self.assertFalse(hook.INSTALLED)          # the repository copy is not the installed one

    def test_python_hook_reads_the_variables_only_through_test_path(self):
        src = open(HOOK, encoding='utf-8').read()
        reads = re.findall(r"os\.environ(?:\.get)?[\[(]'(JT_AI_AGENT_\w+)'", src)
        self.assertEqual(reads, [], 'read JT_AI_AGENT_* only through _test_path')
        self.assertIn("CONFIG_OVERRIDDEN = not INSTALLED and 'JT_AI_AGENT_CONFIG' in os.environ", src)
        self.assertNotIn("'JT_AI_AGENT_CONFIG' in os.environ\n", src.replace(
            "CONFIG_OVERRIDDEN = not INSTALLED and 'JT_AI_AGENT_CONFIG' in os.environ\n", ''))

    def test_powershell_hook_takes_paths_from_windows(self):
        src = _ps1('jt-ai-agent-hook.ps1').decode('ascii')
        for var in ('$env:JT_AI_AGENT_LOG', '$env:JT_AI_AGENT_PROMPT_LOG', '$env:ProgramData', '$env:ProgramFiles',
                    '${env:ProgramFiles(x86)}'):
            self.assertNotIn(var, src)
        self.assertIn("GetFolderPath($name)", src)
        self.assertIn("if ($Installed) { return $default }", src)
        self.assertIn("} catch { $Installed = $true }", src)     # unsure: treat as installed
        inst = _ps1('jt-ai-agent-install.ps1').decode('ascii')
        self.assertNotIn('$env:ProgramFiles', inst)
        self.assertNotIn('$env:ProgramData', inst)


class TestRemoteCommands163(unittest.TestCase):
    """1.6.3: what ssh runs over there is recorded apart from the rest of the line."""

    def test_remote_part_only(self):
        cases = [
            ("ssh -i $K -o BatchMode=yes root@10.0.5.20 'touch /x; systemctl start y' ; shred -u /opt/k",
             'touch /x; systemctl start y'),
            ("ssh root@host 'rm -rf /var/lib/x'", 'rm -rf /var/lib/x'),
            ('ssh -p 2222 admin@host rm -rf /', 'rm -rf /'),
            ("ssh host bash -s <<'EOF'\nrm -rf /srv\nEOF", 'bash -s <<EOF rm -rf /srv EOF'),
            ('ssh host', ''),
            ("scp a host:/tmp/ && ssh host 'ls' | grep x", 'ls'),
            ('ls; rm -rf /tmp/x', ''),
        ]
        for cmd, want in cases:
            self.assertEqual(hook.remote_commands(cmd), want, cmd)

    def test_remote_command_is_redacted_and_recorded(self):
        rec = hook.record({'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                           'tool_input': {'command': "ssh host 'mysql -pS3cretPw -e drop database x'; ls"}})
        self.assertEqual(rec['remote'], 'host')
        self.assertNotIn('S3cretPw', rec['remote_cmd'])
        self.assertIn('drop database', rec['remote_cmd'])
        rec = hook.record({'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                           'tool_input': {'command': 'ssh host'}})
        self.assertNotIn('remote_cmd', rec)

    def test_rule_133716_uses_the_destructive_pattern_of_133712(self):
        xml = open(os.path.join(ROOT, 'packs', 'jt-ai-agent', 'rules', 'zz-133700-jt_ai_agent_rules.xml'),
                   encoding='utf-8').read()
        local = re.search(r'<rule id="133712".*?<field name="jt_ai.cmd" type="pcre2">(.*?)</field>', xml, re.S).group(1)
        remote = re.search(r'<rule id="133716".*?<field name="jt_ai.remote_cmd" type="pcre2">(.*?)</field>',
                           xml, re.S).group(1)
        self.assertEqual(local, remote, 'change 133712 and 133716 together')


class TestInventory13(unittest.TestCase):
    """inventory 1.3: Antigravity CLI and agents that work without an audit line."""

    def agent(self):
        return {'id': '021', 'name': 'build7', 'ip': '10.0.5.7', 'groups': ['default', 'ai-agent']}

    def data(self, procs):
        return {'packages': [], 'processes': procs, 'ports': [], 'hook': True}

    def claude(self, start, cpu, pid=1227):
        return {'pid': pid, 'name': 'claude', 'cmd': '/root/.local/bin/claude', 'argvs': '--resume x',
                'euser': 'root', 'start_time': start, 'utime': cpu, 'stime': 0}

    def test_antigravity_cli_is_reported_as_unsupported(self):
        d = self.data([{'pid': 9, 'name': 'agy', 'cmd': '/home/u/.local/bin/agy', 'argvs': '-i', 'euser': 'u',
                        'start_time': 1, 'utime': 0, 'stime': 0}])
        f = inv.findings(self.agent(), d)
        self.assertEqual([v['event'] for v in f.values()], ['unsupported'])
        self.assertEqual(list(f.values())[0]['tool'], 'antigravity-cli')
        self.assertEqual(inv.findings(self.agent(), self.data([{'pid': 9, 'name': 'agyx', 'cmd': '/usr/bin/agyx',
                                                                 'euser': 'u', 'start_time': 1}])), {})

    def run_twice(self, prev_cpu, now_cpu, last_seen, since, start=1_700_000_000, prev_start=None):
        prev_t, now = 1_800_000_000, 1_800_021_600
        cpu_prev = {'021:1227': [prev_start or start, prev_cpu, prev_t]}
        cpu_now = {}
        seen = {'build7|claude-code': last_seen} if last_seen else {}
        f = inv.findings(self.agent(), self.data([self.claude(start, now_cpu)]), seen, now, since, cpu_prev, cpu_now)
        self.assertEqual(cpu_now['021:1227'], [start, now_cpu, now])
        return [v for v in f.values() if v['event'] == 'busy_silent']

    def test_busy_without_audit_lines(self):
        hit = self.run_twice(1000, 1000 + 61 * 100, last_seen=0, since=1_799_000_000)
        self.assertEqual(len(hit), 1)
        self.assertIn('61 CPU seconds', hit[0]['evidence'][0])
        self.assertIn('last audit line: none seen', hit[0]['evidence'][0])

    def test_not_busy_or_audited_or_new_or_uncovered(self):
        self.assertEqual(self.run_twice(1000, 1000 + 30 * 100, 0, 1_799_000_000), [])          # idle
        self.assertEqual(self.run_twice(1000, 99999, 1_800_000_100, 1_799_000_000), [])        # audited since
        self.assertEqual(self.run_twice(1000, 99999, 0, 1_799_000_000, prev_start=1), [])      # another process
        self.assertEqual(self.run_twice(1000, 99999, 0, 1_800_000_500), [])                    # alerts not read for it

    def test_cursor_and_hookless_hosts_are_not_judged(self):
        d = self.data([dict(self.claude(1, 99999), name='cursor', cmd='/usr/bin/cursor')])
        f = inv.findings(self.agent(), d, {}, 1_800_021_600, 1_799_000_000,
                         {'021:1227': [1, 0, 1_800_000_000]}, {})
        self.assertFalse([v for v in f.values() if v['event'] == 'busy_silent'])
        d = self.data([self.claude(1, 99999)]); d['hook'] = False
        f = inv.findings(self.agent(), d, {}, 1_800_021_600, 1_799_000_000, {'021:1227': [1, 0, 1_800_000_000]}, {})
        self.assertEqual(sorted(v['event'] for v in f.values()), ['hook_missing'])


if __name__ == '__main__':
    unittest.main()
