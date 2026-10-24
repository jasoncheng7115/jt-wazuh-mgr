"""jt-web 1.1: the edge-blocking active responses, offline.

jt-nginx-deny runs on a reverse proxy as root and rewrites nginx's
configuration; jt-cloudflare-block runs on a manager node and calls
Cloudflare's API with a token. Both act on an address taken from an alert, so
what these tests pin down is what they refuse (private, Cloudflare and
allowlisted addresses, anything that is not a bare address), that a repeat is
harmless, that a configuration nginx rejects is put back byte for byte, that
only their own Cloudflare rules are ever deleted, and that neither the token
nor the attacker's request text reaches a log. nginx and Cloudflare are fakes:
no process is started and no network is used.
"""

import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

sys.dont_write_bytecode = True      # no __pycache__ inside the shipped pack

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACK = os.path.join(ROOT, 'packs', 'jt-web')
NGINX_SCRIPT = os.path.join(PACK, 'agent', 'jt-nginx-deny')
CF_SCRIPT = os.path.join(PACK, 'scripts', 'jt-cloudflare-block')


def _load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


nd = _load('jt_nginx_deny', NGINX_SCRIPT)
cf = _load('jt_cloudflare_block', CF_SCRIPT)

PUBLIC4, PUBLIC4B = '9.9.9.9', '8.8.4.4'
PUBLIC6 = '2001:4860:4860::8888'
TOKEN = 'tok_' + 'A1b2C3d4E5f6G7h8I9j0' * 2
ACCOUNT = 'a' * 32
ZONE1, ZONE2 = 'b' * 32, 'c' * 32


def message(command='add', srcip=PUBLIC4, rule='133022', agent='web-01', url='/x'):
    return json.dumps({
        'version': 1, 'origin': {'name': 'node01', 'module': 'wazuh-analysisd'}, 'command': command,
        'parameters': {'extra_args': [], 'program': 'active-response/bin/x', 'alert': {
            'rule': {'id': rule, 'level': 12}, 'agent': {'id': '021', 'name': agent},
            'data': {'srcip': srcip, 'url': url}, 'full_log': 'GET %s' % url}}}) + '\n'


# ---------------------------------------------------------------- shared code

class SharedCode(unittest.TestCase):

    def test_the_shared_block_is_identical_in_both_scripts(self):
        # Two files because each is installed alone (one on the agents, one on
        # the managers); the address checks must not drift apart.
        def block(path):
            with io.open(path, encoding='utf-8') as fh:
                body = fh.read()
            m = re.search(r'# ---- shared:.*?# ---- end shared ----', body, re.S)
            self.assertIsNotNone(m, path)
            return m.group(0)
        self.assertEqual(block(NGINX_SCRIPT), block(CF_SCRIPT))

    def test_scripts_use_the_system_python_and_only_the_standard_library(self):
        for path in (NGINX_SCRIPT, CF_SCRIPT):
            with io.open(path, encoding='utf-8') as fh:
                body = fh.read()
            with self.subTest(path=os.path.basename(path)):
                # Wazuh's bundled Python has no CA certificates (jt-alert-digest 1.6.1)
                self.assertTrue(body.startswith('#!/usr/bin/python3\n'))
                for mod in re.findall(r'^(?:import|from) (\w+)', body, re.M):
                    self.assertIn(mod, sys.stdlib_module_names, mod)


class AddressPolicy(unittest.TestCase):

    def test_public_addresses_are_accepted_as_plain_addresses(self):
        self.assertEqual(nd.block_target(PUBLIC4)[0], PUBLIC4)
        self.assertEqual(nd.block_target(PUBLIC6)[0], PUBLIC6)
        self.assertEqual(nd.block_target('2001:4860:4860:0:0:0:0:8888')[0], PUBLIC6)

    def test_an_ipv4_mapped_address_is_blocked_as_ipv4(self):
        # pitfall 28: a decoder that writes ::ffff:a.b.c.d made firewall-drop
        # write ip6tables, which IPv4 traffic never meets
        self.assertEqual(nd.block_target('::ffff:9.9.9.9')[0], PUBLIC4)
        with self.assertRaises(nd.Refused):
            nd.block_target('::ffff:10.0.0.5')

    def test_never_blocks_addresses_that_are_not_public(self):
        for ip in ('10.0.0.5', '192.168.0.10', '172.31.255.1', '127.0.0.1', '169.254.1.1',
                   '100.64.0.1', '100.127.255.254', '192.0.2.1', '198.51.100.7', '203.0.113.9',
                   '198.18.0.1', '0.0.0.0', '255.255.255.255', '224.0.0.1', '240.0.0.1',
                   '::1', '::', 'fe80::1', 'fd00::5', 'fc00::1', '2001:db8::1', 'ff02::1',
                   '2002:909:909::1', '2001:0:4136:e378::1', '64:ff9b::909:909'):
            with self.subTest(ip=ip):
                with self.assertRaises(nd.Refused) as ctx:
                    nd.block_target(ip)
                self.assertEqual(ctx.exception.kind, 'scope')

    def test_never_blocks_cloudflare(self):
        # A Cloudflare address in a web log means realip is not set for that
        # site; blocking it would block every visitor behind that edge node.
        for ip in ('173.245.48.1', '104.16.0.1', '104.27.255.254', '172.64.1.1', '172.71.255.1',
                   '162.158.0.1', '198.41.200.1', '2606:4700::1111', '2a06:98c0::1', '::ffff:104.16.1.1'):
            with self.subTest(ip=ip):
                with self.assertRaises(nd.Refused) as ctx:
                    nd.block_target(ip)
                self.assertEqual(ctx.exception.kind, 'cloudflare')

    def test_only_a_bare_address_is_accepted(self):
        for raw in (None, 909, '', ' 9.9.9.9', '9.9.9.9 ', '9.9.9.9:80', '[2001:4860:4860::8888]',
                    '9.9.9.0/24', '9.9.9.9\n', 'fe80::1%eth0', '010.1.1.1', '9.9.9', 'example.com',
                    '9.9.9.9; deny all', 'unix:', '1' * 50, ['9.9.9.9']):
            with self.subTest(raw=raw):
                with self.assertRaises(nd.Refused) as ctx:
                    nd.block_target(raw)
                self.assertEqual(ctx.exception.kind, 'invalid')

    def test_allowlist_entries_and_networks_are_never_blocked(self):
        allow = [nd.ipaddress.ip_network('9.9.9.0/24'), nd.ipaddress.ip_network('2001:4860:4860::8888')]
        for ip in ('9.9.9.9', '9.9.9.200', PUBLIC6):
            with self.subTest(ip=ip):
                with self.assertRaises(nd.Refused) as ctx:
                    nd.block_target(ip, allow)
                self.assertEqual(ctx.exception.kind, 'allowlist')
        self.assertEqual(nd.block_target(PUBLIC4B, allow)[0], PUBLIC4B)

    def test_ipv6_prefix_blocks_the_network_and_respects_the_allowlist_inside_it(self):
        self.assertEqual(nd.block_target(PUBLIC6, ipv6_prefix=64)[0], '2001:4860:4860::/64')
        self.assertEqual(nd.block_target(PUBLIC4, ipv6_prefix=64)[0], PUBLIC4)
        allow = [nd.ipaddress.ip_network('2001:4860:4860::1234')]
        with self.assertRaises(nd.Refused):
            nd.block_target(PUBLIC6, allow, ipv6_prefix=64)

    def test_unblocking_applies_no_policy(self):
        # added to the allowlist after it was blocked: it must still come off
        self.assertEqual(nd.parse_target(PUBLIC4)[0], PUBLIC4)
        self.assertEqual(nd.parse_target('::ffff:9.9.9.9')[0], PUBLIC4)
        with self.assertRaises(nd.Refused):
            nd.parse_target('9.9.9.9:80')

    def test_allowlist_file(self):
        tmp = tempfile.mkdtemp(prefix='jtedge-')
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, 'allow.txt')
        self.assertEqual(nd.load_allowlist(path), [])
        with open(path, 'w') as fh:
            fh.write('# monitoring\n9.9.9.9\n  2001:4860::/32   # partner\n\n')
        self.assertEqual([str(n) for n in nd.load_allowlist(path)], ['9.9.9.9/32', '2001:4860::/32'])
        with open(path, 'a') as fh:
            fh.write('9.9.9.300\n')
        # a typo must not leave the administrator it was meant to protect blockable
        with self.assertRaises(ValueError):
            nd.load_allowlist(path)


class Protocol(unittest.TestCase):

    def test_reads_add_and_delete(self):
        for command in ('add', 'delete'):
            msg = nd.read_message(io.StringIO(message(command)))
            self.assertEqual(msg['command'], command)
            self.assertEqual(nd.alert_fields(msg), (PUBLIC4, '133022', 'web-01'))

    def test_rejects_malformed_messages(self):
        for raw in ('', '\n', 'not json\n', '[]\n', '{"command":"add"}\n',
                    '{"command":"flush","parameters":{"alert":{}}}\n',
                    '{"command":"add","parameters":{"alert":"x"}}\n'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    nd.read_message(io.StringIO(raw))

    def test_alert_fields_are_made_safe(self):
        msg = nd.read_message(io.StringIO(message(rule='1; rm -rf', agent='web 01"}{\n')))
        _ip, rule, agent = nd.alert_fields(msg)
        self.assertEqual(rule, '-')
        self.assertEqual(agent, 'web01')

    def test_check_keys(self):
        for answer, expected in (('{"command":"continue"}', 'continue'), ('{"command":"abort"}', 'abort'),
                                 ('{"command":"maybe"}', None), ('garbage', None), ('', None)):
            out = io.StringIO()
            got = nd.check_keys('active-response/bin/jt-nginx-deny', [PUBLIC4],
                                io.StringIO(answer + '\n'), out)
            self.assertEqual(got, expected)
            sent = json.loads(out.getvalue())
            self.assertEqual(sent['command'], 'check_keys')
            self.assertEqual(sent['parameters']['keys'], [PUBLIC4])
            self.assertEqual(sent['origin'], {'name': 'active-response/bin/jt-nginx-deny',
                                              'module': 'active-response'})

    def test_record_carries_only_validated_fields(self):
        line = nd.ar_record('active-response/bin/jt-nginx-deny', 'add', PUBLIC4, '133022', 'web-01', 'blocked')
        rec = json.loads(line)
        self.assertEqual(rec['parameters']['alert'], {'rule': {'id': '133022'}, 'agent': {'name': 'web-01'},
                                                      'data': {'srcip': PUBLIC4}})
        self.assertEqual(rec['parameters']['program'], 'active-response/bin/jt-nginx-deny')

    def test_program_name_matches_what_execd_uses(self):
        self.assertEqual(nd.program_name('/var/ossec/active-response/bin/jt-nginx-deny'),
                         'active-response/bin/jt-nginx-deny')
        self.assertEqual(nd.program_name('active-response/bin/jt-nginx-deny'),
                         'active-response/bin/jt-nginx-deny')

    def test_log_lines_stay_one_line(self):
        self.assertNotIn('\n', nd.clean('a\nb'))
        self.assertEqual(nd.clean('x{"a":1}<b>\\'), 'x??a?:1??b??')


# ---------------------------------------------------------------- nginx

class FakeNginx(object):
    """Records the commands; -t fails while self.broken is true."""

    def __init__(self):
        self.calls, self.broken, self.reload_fails = [], False, False

    def __call__(self, cmd, timeout=120):
        self.calls.append(list(cmd))
        if '-t' in cmd:
            return (1, 'nginx: [emerg] unknown directive "x" in /etc/nginx/conf.d/zz.conf:1\n'
                    'nginx: configuration file /etc/nginx/nginx.conf test failed\n') if self.broken else (0, '')
        if self.reload_fails:
            return 1, 'nginx: [error] invalid PID number "" in "/run/nginx.pid"'
        return 0, ''


class NginxDenyBase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='jtedge-nginx-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cfg = dict(nd.DEFAULTS)
        for key, name in (('map_file', 'jt-ar-deny.map'), ('rules_file', 'jt-ar-deny.rules'),
                          ('allow_file', 'jt-ar-allow.txt'), ('log_file', 'active-responses.log'),
                          ('lock_file', 'jt-nginx-deny.lock')):
            self.cfg[key] = os.path.join(self.tmp, name)
        self.cfg.update(ipv6_prefix=128, max_entries=10000, max_age=604800)
        for key in ('map_file', 'rules_file'):
            open(self.cfg[key], 'w').close()
        self.clock = [1792800000.0]
        self.nginx = FakeNginx()
        self.deny = nd.Deny(self.cfg, 'active-response/bin/jt-nginx-deny',
                            now=lambda: self.clock[0], runner=self.nginx)

    def read(self, key):
        with open(self.cfg[key], encoding='utf-8') as fh:
            return fh.read()

    def log(self):
        try:
            return self.read('log_file')
        except FileNotFoundError:
            return ''

    def run_alert(self, command='add', answer='continue', **kw):
        stdin = io.StringIO(message(command, **kw) + ('{"command":"%s"}\n' % answer if answer else ''))
        stdout = io.StringIO()
        rc = nd.handle_alert(self.deny, stdin, stdout)
        return rc, stdout.getvalue()


class NginxDeny(NginxDenyBase):

    def test_add_writes_both_files_then_tests_then_reloads(self):
        outcome, _ = self.deny.apply(add=(PUBLIC4, '133022', 'web-01'))
        self.assertEqual(outcome, 'blocked')
        self.assertIn('\n9.9.9.9 1; # added=1792800000 rule=133022 agent=web-01\n', self.read('map_file'))
        self.assertIn('\ndeny 9.9.9.9; # added=1792800000 rule=133022 agent=web-01\n', self.read('rules_file'))
        self.assertEqual(self.nginx.calls, [[self.cfg['nginx'], '-t', '-q'], [self.cfg['nginx'], '-s', 'reload']])

    def test_systemctl_reload(self):
        self.cfg['reload'] = 'systemctl'
        self.deny.apply(add=(PUBLIC4, '133022', 'web-01'))
        self.assertEqual(self.nginx.calls[-1], ['systemctl', 'reload', 'nginx'])

    def test_add_is_idempotent(self):
        self.deny.apply(add=(PUBLIC4, '133022', 'web-01'))
        before = self.read('map_file')
        self.nginx.calls.clear()
        self.clock[0] += 60
        outcome, _ = self.deny.apply(add=(PUBLIC4, '133041', 'web-02'))
        self.assertEqual(outcome, 'already blocked')
        self.assertEqual(self.read('map_file'), before, 'the first block keeps its time stamp')
        self.assertEqual(self.nginx.calls, [], 'no change, no reload')

    def test_delete_removes_and_a_second_delete_does_nothing(self):
        self.deny.apply(add=(PUBLIC4, '133022', 'web-01'))
        self.deny.apply(add=(PUBLIC6, '133022', 'web-01'))
        outcome, _ = self.deny.apply(remove=PUBLIC4)
        self.assertEqual(outcome, 'unblocked')
        self.assertNotIn(PUBLIC4, self.read('map_file'))
        self.assertNotIn(PUBLIC4, self.read('rules_file'))
        self.assertIn('deny %s;' % PUBLIC6, self.read('rules_file'))
        self.nginx.calls.clear()
        outcome, _ = self.deny.apply(remove=PUBLIC4)
        self.assertEqual(outcome, 'not in the list')
        self.assertEqual(self.nginx.calls, [])

    def test_entries_are_sorted_ipv4_first(self):
        for ip in (PUBLIC6, PUBLIC4, PUBLIC4B):
            self.deny.apply(add=(ip, '133022', 'w'))
        ips = re.findall(r'^deny (\S+);', self.read('rules_file'), re.M)
        self.assertEqual(ips, [PUBLIC4B, PUBLIC4, PUBLIC6])

    def test_a_configuration_nginx_rejects_is_put_back_byte_for_byte(self):
        self.deny.apply(add=(PUBLIC4, '133022', 'web-01'))
        before_map, before_rules = self.read('map_file'), self.read('rules_file')
        self.nginx.broken = True
        self.nginx.calls.clear()
        with self.assertRaises(nd.Failure) as ctx:
            self.deny.apply(add=(PUBLIC4B, '133022', 'web-01'))
        self.assertIn('unknown directive', str(ctx.exception))
        self.assertEqual(self.read('map_file'), before_map)
        self.assertEqual(self.read('rules_file'), before_rules)
        self.assertEqual(self.nginx.calls, [[self.cfg['nginx'], '-t', '-q']], 'never reloaded')
        self.assertEqual([f for f in os.listdir(self.tmp) if f.startswith('.jt-ar-deny-')], [])

    def test_a_failed_reload_is_an_error_but_the_valid_list_stays(self):
        self.nginx.reload_fails = True
        with self.assertRaises(nd.Failure) as ctx:
            self.deny.apply(add=(PUBLIC4, '133022', 'web-01'))
        self.assertIn('did not reload', str(ctx.exception))
        self.assertIn('deny 9.9.9.9;', self.read('rules_file'))

    def test_a_write_that_fails_leaves_the_old_file(self):
        self.deny.apply(add=(PUBLIC4, '133022', 'web-01'))
        before = self.read('map_file')
        with mock.patch.object(nd.os, 'replace', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.deny.apply(add=(PUBLIC4B, '133022', 'web-01'))
        self.assertEqual(self.read('map_file'), before)
        self.assertEqual([f for f in os.listdir(self.tmp) if f.startswith('.jt-ar-deny-')], [])

    def test_files_are_world_readable_for_nginx_but_written_atomically(self):
        self.deny.apply(add=(PUBLIC4, '133022', 'web-01'))
        self.assertEqual(os.stat(self.cfg['map_file']).st_mode & 0o777, 0o644)

    def test_refuses_a_map_with_lines_it_did_not_write(self):
        with open(self.cfg['map_file'], 'a') as fh:
            fh.write('9.9.9.0/24 1;\n')
        with self.assertRaises(nd.Failure):
            self.deny.apply(add=(PUBLIC4B, '133022', 'w'))
        self.assertEqual(self.read('map_file'), '9.9.9.0/24 1;\n')
        self.assertEqual(self.nginx.calls, [])

    def test_max_entries(self):
        self.cfg['max_entries'] = 1
        self.deny.apply(add=(PUBLIC4, '133022', 'w'))
        with self.assertRaises(nd.Failure):
            self.deny.apply(add=(PUBLIC4B, '133022', 'w'))

    def test_old_entries_expire_on_the_next_run(self):
        # execd keeps its timers in memory: an agent restart loses the delete
        self.deny.apply(add=(PUBLIC4, '133022', 'w'))
        self.clock[0] += 604800 + 1
        outcome, expired = self.deny.apply(add=(PUBLIC4B, '133022', 'w'))
        self.assertEqual(expired, [PUBLIC4])
        self.assertNotIn(PUBLIC4 + ' 1;', self.read('map_file'))
        self.assertIn(PUBLIC4B + ' 1;', self.read('map_file'))
        self.cfg['max_age'] = 0
        self.clock[0] += 10 * 604800
        self.assertEqual(self.deny.apply()[1], [])

    def test_runs_are_serialised(self):
        with nd.Lock(self.cfg['lock_file']):
            locker = nd.Lock(self.cfg['lock_file'], wait=0.3)
            with self.assertRaises(nd.Failure):
                locker.__enter__()
        # released: the next run gets it
        with nd.Lock(self.cfg['lock_file'], wait=0.3):
            pass

    def test_concurrent_adds_all_land(self):
        errors = []

        def add(ip):
            try:
                self.deny.apply(add=(ip, '133022', 'w'))
            except Exception as e:      # pragma: no cover - reported below
                errors.append(e)
        threads = [threading.Thread(target=add, args=('9.9.9.%d' % i,)) for i in range(1, 9)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(re.findall(r'^deny ', self.read('rules_file'), re.M)), 8)

    def test_config_file(self):
        path = os.path.join(self.tmp, 'jt-nginx-deny.conf')
        with open(path, 'w') as fh:
            fh.write('# site\nipv6_prefix = 64\nreload=systemctl\n')
        cfg = nd.load_config(path)
        self.assertEqual((cfg['ipv6_prefix'], cfg['reload']), (64, 'systemctl'))
        for bad in ('colour=red\n', 'ipv6_prefix=56\n', 'reload=restart\n', 'map_file=relative.map\n',
                    'max_age=soon\n'):
            with open(path, 'w') as fh:
                fh.write(bad)
            with self.subTest(bad=bad):
                with self.assertRaises(nd.Failure):
                    nd.load_config(path)
        self.assertEqual(nd.load_config(os.path.join(self.tmp, 'absent.conf'))['ipv6_prefix'], 128)


class NginxDenyAlerts(NginxDenyBase):
    """The whole run as execd starts it: message, check_keys, change, log."""

    def test_add_asks_execd_then_blocks(self):
        rc, out = self.run_alert('add')
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)['parameters']['keys'], [PUBLIC4])
        self.assertIn('deny 9.9.9.9;', self.read('rules_file'))
        rec = json.loads(self.log().strip().split(': ', 1)[1])
        self.assertEqual((rec['command'], rec['jt']['result']), ('add', 'blocked'))

    def test_abort_means_already_blocked_and_changes_nothing(self):
        rc, _ = self.run_alert('add', answer='abort')
        self.assertEqual(rc, 0)
        self.assertEqual(self.read('rules_file'), '')
        self.assertEqual(self.nginx.calls, [])
        self.assertIn('timer running', self.log())

    def test_no_answer_from_execd_blocks_nothing(self):
        rc, _ = self.run_alert('add', answer=None)
        self.assertEqual(rc, 1)
        self.assertEqual(self.read('rules_file'), '')
        self.assertIn('ERROR execd did not answer', self.log())

    def test_delete_needs_no_check_keys(self):
        self.run_alert('add')
        rc, out = self.run_alert('delete', answer=None)
        self.assertEqual((rc, out), (0, ''))
        self.assertNotIn('deny 9.9.9.9', self.read('rules_file'))

    def test_delete_works_for_an_address_allowlisted_after_it_was_blocked(self):
        self.run_alert('add')
        with open(self.cfg['allow_file'], 'w') as fh:
            fh.write('9.9.9.9\n')
        self.run_alert('delete', answer=None)
        self.assertNotIn('deny 9.9.9.9', self.read('rules_file'))

    def test_refused_addresses_never_reach_execd_or_nginx(self):
        for ip in ('10.0.0.5', '104.16.0.1', 'fe80::1', '9.9.9.9 1; } deny all; #'):
            with self.subTest(ip=ip):
                rc, out = self.run_alert('add', srcip=ip)
                self.assertEqual((rc, out), (0, ''))
        self.assertEqual(self.nginx.calls, [])
        self.assertEqual(self.read('rules_file'), '')
        self.assertEqual(self.log().count(' refused '), 4)
        self.assertNotIn('deny all', self.log())

    def test_a_broken_allowlist_blocks_nothing(self):
        with open(self.cfg['allow_file'], 'w') as fh:
            fh.write('admin-pc\n')
        rc, out = self.run_alert('add')
        self.assertEqual((rc, out), (1, ''))
        self.assertIn('ERROR', self.log())
        self.assertEqual(self.read('rules_file'), '')

    def test_a_host_without_the_nginx_snippet_is_left_alone(self):
        os.unlink(self.cfg['map_file'])
        rc, out = self.run_alert('add')
        self.assertEqual((rc, out), (0, ''))
        self.assertIn('not set up on this host', self.log())
        self.assertEqual(self.nginx.calls, [])
        self.assertFalse(os.path.exists(self.cfg['map_file']))

    def test_nginx_failure_is_logged_as_an_error_line(self):
        self.nginx.broken = True
        rc, _ = self.run_alert('add')
        self.assertEqual(rc, 1)
        line = self.log().strip()
        self.assertRegex(line, r'^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d active-response/bin/jt-nginx-deny: ERROR add 9\.9\.9\.9: nginx -t failed')
        self.assertEqual(self.read('rules_file'), '')

    def test_the_attackers_request_never_reaches_the_log(self):
        self.run_alert('add', url='/x"}\n2026/10/24 00:00:00 active-response/bin/firewall-drop: {"command":"add"}')
        self.run_alert('add', srcip='10.0.0.5', url='/evil-marker')
        log = self.log()
        self.assertNotIn('evil-marker', log)
        self.assertNotIn('firewall-drop', log)
        self.assertEqual(len(log.strip().split('\n')), 2)

    def test_garbage_on_stdin(self):
        rc = nd.handle_alert(self.deny, io.StringIO('hello\n'), io.StringIO())
        self.assertEqual(rc, 1)
        self.assertIn('ERROR the message is not JSON', self.log())


class NginxDenyCommandLine(NginxDenyBase):

    def main(self, *args):
        conf = os.path.join(self.tmp, 'jt-nginx-deny.conf')
        with open(conf, 'w') as fh:
            for key in ('map_file', 'rules_file', 'allow_file', 'log_file', 'lock_file'):
                fh.write('%s=%s\n' % (key, self.cfg[key]))
            fh.write('nginx=/bin/true\n')
        out = io.StringIO()
        with mock.patch.object(nd, 'CONF_FILE', conf), mock.patch('sys.stdout', out), \
                mock.patch('sys.stderr', io.StringIO()):
            rc = nd.main(['/var/ossec/active-response/bin/jt-nginx-deny'] + list(args))
        return rc, out.getvalue()

    def test_block_list_unblock(self):
        self.assertEqual(self.main('--block', PUBLIC4)[0], 0)
        rc, out = self.main('--list')
        self.assertIn(PUBLIC4, out)
        self.assertEqual(self.main('--unblock', PUBLIC4)[0], 0)
        self.assertNotIn(PUBLIC4, self.main('--list')[1])

    def test_manual_block_has_the_same_policy(self):
        self.assertEqual(self.main('--block', '192.168.0.10')[0], 1)
        self.assertEqual(self.read('rules_file'), '')

    def test_check(self):
        rc, out = self.main('--check')
        self.assertEqual(rc, 0)
        self.assertIn('nginx -t ok', out)


# ---------------------------------------------------------------- Cloudflare

class FakeResponse(object):
    def __init__(self, status, payload):
        self.status, self._body = status, json.dumps(payload).encode()

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeCloudflare(object):
    """A small in-memory IP Access Rules API: {path: {id: rule}}."""

    def __init__(self):
        self.rules, self.requests, self.fail_post, self.down, self.seq = {}, [], None, False, 0

    def add_rule(self, kind, ident, value, notes, target='ip', scope=None, mode='block'):
        self.seq += 1
        rid = '%032x' % self.seq
        path = '/client/v4/%s/%s/firewall/access_rules/rules' % (kind, ident)
        self.rules.setdefault(path, {})[rid] = {
            'id': rid, 'mode': mode, 'notes': notes, 'configuration': {'target': target, 'value': value},
            'scope': {'type': scope or kind[:-1]}}
        return rid

    def open(self, req, timeout=None):
        url = cf.urllib.parse.urlsplit(req.full_url)
        body = json.loads(req.data) if req.data else None
        self.requests.append({'method': req.get_method(), 'path': url.path,
                              'query': dict(cf.urllib.parse.parse_qsl(url.query)), 'body': body,
                              'headers': dict(req.header_items()), 'timeout': timeout})
        if self.down:
            raise cf.urllib.error.URLError(OSError('Network is unreachable'))
        path = url.path
        query = self.requests[-1]['query']
        if req.get_method() == 'GET':
            items = list(self.rules.get(path, {}).values())
            if 'configuration.value' in query:
                items = [r for r in items if r['configuration']['value'] == query['configuration.value']
                         and r['configuration']['target'] == query['configuration.target']]
            if 'notes' in query:
                items = [r for r in items if query['notes'].lower() in r['notes'].lower()]
            return FakeResponse(200, {'success': True, 'errors': [], 'result': items})
        if req.get_method() == 'POST':
            if self.fail_post:
                code, then_add = self.fail_post
                if then_add:
                    kind, ident = path.split('/')[3:5]
                    self.add_rule(kind, ident, body['configuration']['value'], 'someone')
                raise cf.urllib.error.HTTPError(req.full_url, code, 'err', {}, io.BytesIO(json.dumps(
                    {'success': False, 'errors': [{'code': 10009, 'message': 'duplicate of existing'}]}).encode()))
            kind, ident = path.split('/')[3:5]
            rid = self.add_rule(kind, ident, body['configuration']['value'], body['notes'],
                                body['configuration']['target'], mode=body['mode'])
            return FakeResponse(200, {'success': True, 'errors': [], 'result': self.rules[path][rid]})
        if req.get_method() == 'DELETE':
            base, rid = path.rsplit('/', 1)
            self.rules.get(base, {}).pop(rid)
            return FakeResponse(200, {'success': True, 'errors': [], 'result': {'id': rid}})
        raise AssertionError(req.get_method())


class CloudflareBase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='jtedge-cf-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.conf = os.path.join(self.tmp, 'jt-cloudflare-block.conf')
        self.token_file = os.path.join(self.tmp, 'jt-cloudflare.token')
        fd = os.open(self.token_file, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, (TOKEN + '\n').encode())
        os.close(fd)
        self.write_conf('scope=account\naccount_id=%s\n' % ACCOUNT)
        self.fake = FakeCloudflare()

    def write_conf(self, text):
        with open(self.conf, 'w') as fh:
            fh.write(text + 'token_file=%s\nallow_file=%s\nlog_file=%s\n' % (
                self.token_file, os.path.join(self.tmp, 'allow.txt'), os.path.join(self.tmp, 'ar.log')))
        self.cfg = cf.load_config(self.conf)

    def api(self):
        return cf.Cloudflare(self.cfg, cf.read_token(self.cfg['token_file']), opener=self.fake)

    def log(self):
        try:
            with open(self.cfg['log_file']) as fh:
                return fh.read()
        except FileNotFoundError:
            return ''

    def run_alert(self, command='add', answer='continue', **kw):
        stdin = io.StringIO(message(command, **kw) + ('{"command":"%s"}\n' % answer if answer else ''))
        out = io.StringIO()
        rc = cf.handle_alert(self.cfg, 'active-response/bin/jt-cloudflare-block', stdin, out,
                             api_factory=lambda c: cf.Cloudflare(c, cf.read_token(c['token_file']),
                                                                 opener=self.fake))
        return rc, out.getvalue()

    def rules(self, kind='accounts', ident=ACCOUNT):
        return list(self.fake.rules.get('/client/v4/%s/%s/firewall/access_rules/rules' % (kind, ident), {}).values())


class CloudflareSettings(CloudflareBase):

    def test_settings_are_validated(self):
        for bad in ('scope=account\naccount_id=xyz\n', 'scope=zone\nzone_ids=\n',
                    'scope=zone\nzone_ids=%s,nothex\n' % ZONE1, 'scope=org\n',
                    'scope=account\naccount_id=%s\nmode=allow\n' % ACCOUNT,
                    'scope=account\naccount_id=%s\napi=http://api.cloudflare.com/client/v4\n' % ACCOUNT,
                    'scope=account\naccount_id=%s\nipv6_prefix=56\n' % ACCOUNT,
                    'scope=account\naccount_id=%s\nsecret=1\n' % ACCOUNT):
            with self.subTest(bad=bad):
                with self.assertRaises(cf.Failure):
                    self.write_conf(bad)
        with self.assertRaises(cf.Failure):
            cf.load_config(os.path.join(self.tmp, 'absent.conf'))
        self.write_conf('scope=zone\nzone_ids=%s, %s\n' % (ZONE1, ZONE2))
        self.assertEqual(self.cfg['targets'], [('zones', ZONE1), ('zones', ZONE2)])

    def test_token_file_must_be_private_and_is_never_echoed(self):
        self.assertEqual(cf.read_token(self.token_file), TOKEN)
        os.chmod(self.token_file, 0o640)
        with self.assertRaises(cf.Failure) as ctx:
            cf.read_token(self.token_file)
        self.assertIn('chmod 600', str(ctx.exception))
        os.chmod(self.token_file, 0o600)
        with open(self.token_file, 'w') as fh:
            fh.write('Bearer ' + TOKEN + ' # mine')
        with self.assertRaises(cf.Failure) as ctx:
            cf.read_token(self.token_file)
        self.assertNotIn(TOKEN, str(ctx.exception))
        with self.assertRaises(cf.Failure):
            cf.read_token(os.path.join(self.tmp, 'absent.token'))
        link = os.path.join(self.tmp, 'link.token')
        os.symlink(self.token_file, link)
        with self.assertRaises(cf.Failure):
            cf.read_token(link)


class CloudflareApi(CloudflareBase):

    def test_block_creates_one_rule_with_our_note(self):
        outcomes = self.api().block(cf.ipaddress.ip_network(PUBLIC4), cf.note_for('133022', 'web-01'))
        self.assertEqual(outcomes, ['account aaaaaaaa: blocked (block)'])
        post = [r for r in self.fake.requests if r['method'] == 'POST'][0]
        self.assertEqual(post['path'], '/client/v4/accounts/%s/firewall/access_rules/rules' % ACCOUNT)
        self.assertEqual(post['body']['mode'], 'block')
        self.assertEqual(post['body']['configuration'], {'target': 'ip', 'value': PUBLIC4})
        self.assertTrue(post['body']['notes'].startswith('jt-wazuh-mgr active response: rule 133022 on web-01'))
        self.assertEqual(post['headers']['Authorization'], 'Bearer ' + TOKEN)
        self.assertEqual(post['timeout'], 15)

    def test_targets_for_ipv6_and_ranges(self):
        api = self.api()
        self.assertEqual(api.configuration(cf.ipaddress.ip_network(PUBLIC6)), {'target': 'ip6', 'value': PUBLIC6})
        self.assertEqual(api.configuration(cf.ipaddress.ip_network('2001:4860:4860::/64')),
                         {'target': 'ip_range', 'value': '2001:4860:4860::/64'})

    def test_block_is_idempotent(self):
        net = cf.ipaddress.ip_network(PUBLIC4)
        self.api().block(net, cf.note_for('133022', 'w'))
        self.assertEqual(self.api().block(net, cf.note_for('133022', 'w')), ['account aaaaaaaa: already blocked'])
        self.assertEqual(len(self.rules()), 1)

    def test_a_rule_someone_else_made_is_left_alone(self):
        self.fake.add_rule('accounts', ACCOUNT, PUBLIC4, 'blocked by hand', mode='challenge')
        net = cf.ipaddress.ip_network(PUBLIC4)
        outcome = self.api().block(net, cf.note_for('133022', 'w'))
        self.assertIn('left alone', outcome[0])
        self.assertEqual([r['method'] for r in self.fake.requests], ['GET'])
        self.assertEqual(self.api().unblock(net), ['account aaaaaaaa: no rule of this response'])
        self.assertEqual(len(self.rules()), 1, 'never deletes a rule it did not create')

    def test_unblock_deletes_only_our_rule_of_our_scope(self):
        net = cf.ipaddress.ip_network(PUBLIC4)
        self.api().block(net, cf.note_for('133022', 'w'))
        self.fake.add_rule('accounts', ACCOUNT, PUBLIC4B, 'jt-wazuh-mgr active response: other address')
        self.fake.add_rule('accounts', ACCOUNT, PUBLIC4, 'jt-wazuh-mgr active response: org', scope='organization')
        self.assertEqual(self.api().unblock(net), ['account aaaaaaaa: unblocked'])
        left = sorted((r['configuration']['value'], r['scope']['type']) for r in self.rules())
        self.assertEqual(left, [(PUBLIC4B, 'account'), (PUBLIC4, 'organization')])
        deletes = [r['path'] for r in self.fake.requests if r['method'] == 'DELETE']
        self.assertEqual(len(deletes), 1)
        self.assertRegex(deletes[0], r'/accounts/a{32}/firewall/access_rules/rules/[0-9a-f]{32}$')

    def test_zone_scope_blocks_in_every_zone(self):
        self.write_conf('scope=zone\nzone_ids=%s,%s\nmode=managed_challenge\n' % (ZONE1, ZONE2))
        outcomes = self.api().block(cf.ipaddress.ip_network(PUBLIC4), cf.note_for('133022', 'w'))
        self.assertEqual(outcomes, ['zone bbbbbbbb: blocked (managed_challenge)',
                                    'zone cccccccc: blocked (managed_challenge)'])
        self.assertEqual(len(self.rules('zones', ZONE1)), 1)
        self.assertEqual(len(self.rules('zones', ZONE2)), 1)
        self.api().unblock(cf.ipaddress.ip_network(PUBLIC4))
        self.assertEqual(self.rules('zones', ZONE1) + self.rules('zones', ZONE2), [])

    def test_a_race_with_the_other_node_is_not_an_error(self):
        self.fake.fail_post = (400, True)
        outcome = self.api().block(cf.ipaddress.ip_network(PUBLIC4), cf.note_for('133022', 'w'))
        self.assertEqual(outcome, ['account aaaaaaaa: already blocked'])

    def test_api_errors_carry_codes_never_the_token(self):
        self.fake.fail_post = (403, False)
        with self.assertRaises(cf.ApiError) as ctx:
            self.api().block(cf.ipaddress.ip_network(PUBLIC4), cf.note_for('133022', 'w'))
        text = str(ctx.exception)
        self.assertIn('403', text)
        self.assertIn('10009', text)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(TOKEN, repr(self.api()))

    def test_unreachable(self):
        self.fake.down = True
        with self.assertRaises(cf.Failure) as ctx:
            self.api().block(cf.ipaddress.ip_network(PUBLIC4), 'n')
        self.assertIn('unreachable', str(ctx.exception))


class CloudflareAlerts(CloudflareBase):

    def test_add_then_delete(self):
        rc, out = self.run_alert('add')
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)['parameters']['keys'], [PUBLIC4])
        self.assertEqual(len(self.rules()), 1)
        rc, out = self.run_alert('delete', answer=None)
        self.assertEqual((rc, out), (0, ''))
        self.assertEqual(self.rules(), [])
        records = [json.loads(l.split(': ', 1)[1]) for l in self.log().strip().split('\n')]
        self.assertEqual([r['command'] for r in records], ['add', 'delete'])

    def test_refused_addresses_never_reach_cloudflare(self):
        for ip in ('172.31.255.9', '2606:4700::1', '9.9.9.9:443'):
            self.run_alert('add', srcip=ip)
        self.assertEqual(self.fake.requests, [])

    def test_abort_calls_nothing(self):
        self.run_alert('add', answer='abort')
        self.assertEqual(self.fake.requests, [])

    def test_errors_are_logged_without_the_token(self):
        self.fake.fail_post = (403, False)
        rc, _ = self.run_alert('add')
        self.assertEqual(rc, 1)
        log = self.log()
        self.assertIn('active-response/bin/jt-cloudflare-block: ERROR add 9.9.9.9: Cloudflare API POST', log)
        self.assertNotIn(TOKEN, log)

    def test_a_readable_token_blocks_nothing(self):
        os.chmod(self.token_file, 0o644)
        rc, _ = self.run_alert('add')
        self.assertEqual(rc, 1)
        self.assertIn('chmod 600', self.log())
        self.assertEqual(self.fake.requests, [])


# ---------------------------------------------------------------- manifests

class ShippedActiveResponses(unittest.TestCase):
    """Every active_response a pack ships meets what the enable route accepts
    (_ar_definitions in web_ui drops a malformed entry without a word, so the
    operator would simply not see it), says what it blocks in both languages,
    and names rules that exist. A command that is not Wazuh's own needs its
    <command> block in a setup step."""

    BUILTIN = {'firewall-drop', 'host-deny', 'route-null', 'disable-account', 'restart-wazuh',
               'netsh', 'win_route-null', 'restart-ossec'}

    def setUp(self):
        import glob
        self.packs = []
        for mf in sorted(glob.glob(os.path.join(ROOT, 'packs', '*', 'manifest.json'))):
            with io.open(mf, encoding='utf-8') as fh:
                self.packs.append((os.path.dirname(mf), json.load(fh)))

    def pack_rules(self, pdir, m):
        ids = set()
        for e in m['files']:
            if e['type'] == 'rule':
                with io.open(os.path.join(pdir, 'rules', e['name']), encoding='utf-8') as fh:
                    ids |= set(re.findall(r'<rule id="(\d+)"', fh.read()))
        return ids

    def test_entries_are_well_formed(self):
        all_rules = set()
        for pdir, m in self.packs:
            all_rules |= self.pack_rules(pdir, m)
        commands_in_setup = set()
        for _pdir, m in self.packs:
            for st in m.get('setup') or []:
                commands_in_setup |= set(re.findall(r'<name>([^<]+)</name>', st.get('code') or ''))
        seen = 0
        for pdir, m in self.packs:
            ids = set()
            for entry in m.get('active_response') or []:
                seen += 1
                with self.subTest(pack=m['id'], ar=entry.get('id')):
                    self.assertRegex(entry['id'], r'^[a-z0-9]+(?:-[a-z0-9]+)*$')
                    self.assertLessEqual(len(entry['id']), 64)
                    self.assertNotIn(entry['id'], ids)
                    ids.add(entry['id'])
                    self.assertRegex(entry['command'], r'^[A-Za-z0-9_.]+(?:-[A-Za-z0-9_.]+)*$')
                    self.assertIn(entry['location'], ('local', 'server', 'defined-agent', 'all'))
                    self.assertTrue(entry['rules_id'] and len(entry['rules_id']) <= 50)
                    for rid in entry['rules_id']:
                        self.assertRegex(rid, r'^\d{1,7}$')
                    lo, hi = (int(x) for x in m['rule_id_range'].split('-'))
                    for rid in entry['rules_id']:
                        if lo <= int(rid) <= hi:
                            self.assertIn(rid, all_rules, 'rule %s is not in the pack' % rid)
                    self.assertTrue(60 <= int(entry['timeout']) <= 7 * 86400)
                    for field in ('title', 'title_zh', 'body', 'body_zh'):
                        self.assertTrue(entry.get(field), field)
                    if entry['command'] not in self.BUILTIN:
                        self.assertIn(entry['command'], commands_in_setup,
                                      'no setup step defines the command %s' % entry['command'])
        self.assertGreater(seen, 0)

    def test_edge_blocking_is_offered_only_for_high_confidence_rules(self):
        wanted = {'jt-web': {'133012', '133022', '133040', '133041', '133042'},
                  'jt-php': {'133180', '133181'}}
        for _pdir, m in self.packs:
            if m['id'] not in wanted:
                continue
            for entry in m['active_response']:
                if entry['command'] in ('jt-nginx-deny', 'jt-cloudflare-block'):
                    with self.subTest(pack=m['id'], ar=entry['id']):
                        self.assertLessEqual(set(entry['rules_id']), wanted[m['id']])
                        self.assertEqual(entry['location'],
                                         'local' if entry['command'] == 'jt-nginx-deny' else 'server')

    def test_the_agent_group_carries_the_nginx_script(self):
        m = [m for _p, m in self.packs if m['id'] == 'jt-web'][0]
        self.assertIn('jt-nginx-deny', m['agent_group']['files'])
        self.assertIn('jt-ar-deny-nginx.conf', m['agent_group']['files'])
        self.assertEqual([s['name'] for s in m['scripts']], ['jt-cloudflare-block'])
        self.assertFalse(m['scripts'][0].get('cron'), 'an active response is started by execd, not cron')


if __name__ == '__main__':
    unittest.main()
