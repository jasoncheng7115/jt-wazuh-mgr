"""jt-ai-agent: the Claude Code audit hook (packs/jt-ai-agent/agent/jt-ai-agent-hook.py).

The hook runs before every tool call of every agent on a host, so two
properties matter more than anything it records: it must never block or
change a call, and it must not write secrets into a log that goes to Wazuh.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
