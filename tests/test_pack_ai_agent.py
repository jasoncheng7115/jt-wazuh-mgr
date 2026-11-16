"""jt-ai-agent: the Claude Code audit hook (packs/jt-ai-agent/agent/jt-ai-agent-hook.py).

The hook runs before every tool call of every agent on a host, so two
properties matter more than anything it records: it must never block or
change a call, and it must not write secrets into a log that goes to Wazuh.
"""

import importlib.util
import json
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


if __name__ == '__main__':
    unittest.main()
