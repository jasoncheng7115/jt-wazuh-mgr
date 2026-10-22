"""jt-alert-digest 1.4: the reader, the delivery path and the self-reporting.

The script runs from cron as root on every manager node, so its failures are
the quiet kind: in 1.3 a rotation dropped the tail of the day, a backlog above
the ceiling crashed every run, a half-written last line was skipped for good,
and recipients of <reports> received every digest. Each of those has a test
here. Everything runs in temporary directories; mail goes to a stand-in or to
a server on 127.0.0.1 that this file starts and stops.
"""

import base64
import email
import email.policy
import gzip
import http.server
import io
import json
import os
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs

sys.dont_write_bytecode = True      # no __pycache__ inside the shipped pack

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'packs', 'jt-alert-digest', 'scripts', 'jt-alert-digest.py')

OSSEC = """<ossec_config>
  <global>
    <email_notification>no</email_notification>
    <smtp_server>%(smtp)s</smtp_server>
    <email_from>wazuh@example.com</email_from>
    <email_to>soc@example.com</email_to>
    <email_to>SOC@example.com</email_to>
    <!-- <email_to>commented@example.com</email_to> -->
  </global>
  <alerts><log_alert_level>3</log_alert_level><email_alert_level>12</email_alert_level></alerts>
  <cluster><node_name>node02</node_name><node_type>worker</node_type><disabled>no</disabled></cluster>
</ossec_config>
<ossec_config>
  <global><white_list>127.0.0.1</white_list></global>
  <reports><title>r</title><email_to>reports-only@example.com</email_to></reports>
</ossec_config>
"""

T0 = time.mktime((2026, 10, 11, 12, 0, 0, 0, 0, -1))     # local noon


def load():
    import importlib.util
    spec = importlib.util.spec_from_file_location('jt_alert_digest_14', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def stamp(epoch):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(epoch)) + '.000+0000'


def alert(n, level=12, rule='100001', agent='host1', agent_id='001', when=None, desc=None,
          mail=None, **extra):
    a = {'timestamp': stamp(when if when is not None else T0 - 60 + n % 50),
         'rule': {'level': level, 'description': desc or ('Thing on item %d' % n), 'id': rule,
                  'mail': (level >= 12) if mail is None else mail, 'groups': ['t']},
         'agent': {'id': agent_id, 'name': agent, 'ip': '192.0.2.10'},
         'id': '1.%d' % n, 'full_log': 'line %d' % n, 'location': '/var/log/x'}
    a.update(extra)
    return json.dumps(a, separators=(',', ':'))


def names_rule(rule_id):
    """A Zulip post names a rule in its table row, or as "rule N" on a compact line."""
    import re
    return re.compile(r'(\| Rule \| |rule )\[?%d\b' % rule_id)


class Tree(object):
    """A manager directory laid out the way analysisd and monitord leave it."""

    def __init__(self, test, smtp='192.0.2.25', conf='repeat = 0\ndaily = off\n'):
        self.root = tempfile.mkdtemp(prefix='jtad-')
        test.addCleanup(self._remove)
        for d in ('etc/jt-packs', 'logs/alerts', 'var', 'queue/sockets'):
            os.makedirs(os.path.join(self.root, d))
        with io.open(self.path('etc/ossec.conf'), 'w', encoding='utf-8') as fh:
            fh.write(OSSEC % {'smtp': smtp})
        self.conf(conf)
        self.newday(10)

    def _remove(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def path(self, rel):
        return os.path.join(self.root, rel)

    def conf(self, text):
        with io.open(self.path('etc/jt-packs/jt-alert-digest.conf'), 'w', encoding='utf-8') as fh:
            fh.write(text)

    def dated(self, d=None):
        return self.path('logs/alerts/2026/Oct/ossec-alerts-%02d.json' % (d or self.day))

    def newday(self, d):
        self.day = d
        os.makedirs(os.path.dirname(self.dated()), exist_ok=True)
        open(self.dated(), 'a').close()
        cur = self.path('logs/alerts/alerts.json')
        if os.path.exists(cur):
            os.unlink(cur)
        os.link(self.dated(), cur)

    def compress(self, d):
        with open(self.dated(d), 'rb') as fh, gzip.open(self.dated(d) + '.gz', 'wb') as out:
            out.write(fh.read())
        os.unlink(self.dated(d))

    def write(self, *lines, **kw):
        with open(self.path('logs/alerts/alerts.json'), 'a') as fh:
            for line in lines:
                fh.write(line + '\n')
            if kw.get('partial'):
                fh.write(kw['partial'])

    def state(self):
        with open(self.path('var/jt-alert-digest.state')) as fh:
            return json.load(fh)


class DigestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(SCRIPT):
            raise unittest.SkipTest('jt-alert-digest is not present')
        cls.mod = load()
        cls.originals = {k: getattr(cls.mod, k) for k in ('deliver', 'emit', 'log', 'NOW', 'MAX_ALERTS')}

    def setUp(self):
        self.sent, self.events, self.logs, self.refuse = [], [], [], None
        mod = self.mod

        def deliver(message, options):
            if self.refuse:
                raise mod.DeliveryError(self.refuse, 'refused: %s' % self.refuse)
            self.sent.append(message)
            return {}
        mod.deliver = deliver
        mod.emit = lambda event, **fields: self.events.append(dict(fields, event=event))
        mod.log = self.logs.append
        mod.NOW = T0

    def tearDown(self):
        for k, v in self.originals.items():
            setattr(self.mod, k, v)

    def run_digest(self, tree, *args):
        return self.mod.run(self.mod.parse_args(['--wazuh-path', tree.root] + list(args)))

    def body(self, message=None):
        message = message or self.sent[-1]
        return message.get_body(('plain',)).get_content()

    def kinds(self):
        return [e['event'] for e in self.events]


class TestReader(DigestCase):

    def test_rotation_reads_the_rotated_tail_and_whole_days_in_between(self):
        """1.3 restarted at 0 in the new file: the old file's tail, and on a node
        that could not deliver the whole day's backlog, were never read."""
        t = Tree(self)
        self.run_digest(t)
        t.write(alert(1))
        self.refuse = 'rcpt-450'
        self.assertEqual(self.run_digest(t), 1)
        t.write(alert(2))
        t.newday(11)
        t.write(alert(3, rule='100003'))
        t.compress(10)
        t.newday(12)
        t.write(alert(4, rule='100004'))
        self.refuse = None
        self.assertEqual(self.run_digest(t), 0)
        text = self.body()
        for n in (1, 2, 3, 4):
            self.assertIn('line %d' % n, text)
        self.assertEqual(t.state()['pos']['path'], '2026/Oct/ossec-alerts-12.json')
        self.assertNotIn('skipped', self.kinds())

    def test_a_reused_inode_number_is_not_taken_for_the_old_file(self):
        """After monitord deletes the compressed day's plain file, a later file
        may get its inode number; the dated name decides."""
        t = Tree(self)
        t.write(alert(1))
        t.newday(11)
        t.write(alert(2, rule='100002'))
        cur = os.stat(t.path('logs/alerts/alerts.json'))
        position = {'ino': cur.st_ino, 'dev': cur.st_dev, 'path': '2026/Oct/ossec-alerts-10.json', 'offset': 0}
        segments, lost = self.mod.plan(t.path('logs/alerts/alerts.json'), position)
        self.assertEqual([s['rel'] for s in segments],
                         ['2026/Oct/ossec-alerts-10.json', '2026/Oct/ossec-alerts-11.json'])
        self.assertEqual(lost, [])

    def test_a_vanished_rotated_file_is_reported_once(self):
        t = Tree(self)
        self.run_digest(t)
        t.write(alert(1))
        self.refuse = 'rcpt-450'
        self.run_digest(t)
        t.newday(11)
        os.unlink(t.dated(10))
        t.write(alert(2))
        self.run_digest(t)
        self.run_digest(t)
        self.assertEqual(self.kinds().count('skipped'), 1)
        self.refuse = None
        self.run_digest(t)
        self.assertIn('line 2', self.body())

    def test_partial_last_line_is_left_for_the_next_run(self):
        t = Tree(self)
        self.run_digest(t)
        line = alert(1)
        t.write(partial=line[:30])
        self.run_digest(t)
        self.assertEqual(self.sent, [])
        self.assertEqual(t.state()['pos']['offset'], 0)
        with open(t.path('logs/alerts/alerts.json'), 'a') as fh:
            fh.write(line[30:] + '\n')
        self.run_digest(t)
        self.assertIn('line 1', self.body())

    def test_a_backlog_above_the_ceiling_is_sent_in_parts(self):
        """1.3 raised 'telling position disabled by next() call' here, every run."""
        self.mod.MAX_ALERTS = 5
        t = Tree(self)
        self.run_digest(t)
        t.write(*[alert(i, rule=str(110000 + i)) for i in range(8)])
        self.assertEqual(self.run_digest(t), 0)
        self.assertIn('5 alerts at level 12', self.body())
        self.assertIn('More alerts are waiting', self.body())
        self.run_digest(t)
        self.assertIn('3 alerts at level 12', self.body())

    def test_a_13_state_is_continued(self):
        t = Tree(self)
        t.write(alert(1))
        with open(t.path('var/jt-alert-digest.state'), 'w') as fh:
            fh.write(str(os.path.getsize(t.dated())))
        t.write(alert(2))
        self.run_digest(t)
        self.assertIn('Thing on item 2', self.body())
        self.assertNotIn('item 1', self.body())
        self.assertEqual(t.state()['v'], 2)

    def test_a_13_offset_written_before_midnight_finishes_the_old_file(self):
        t = Tree(self)
        t.write(alert(1, when=T0 - 300))
        offset = os.path.getsize(t.dated())
        t.write(alert(2, when=T0 - 200))
        with open(t.path('var/jt-alert-digest.state'), 'w') as fh:
            fh.write(str(offset))
        os.utime(t.path('var/jt-alert-digest.state'), (T0 - 250, T0 - 250))
        t.newday(11)
        t.write(alert(3, when=T0 - 100))      # same length as line 1: the offset alone is ambiguous
        self.run_digest(t)
        text = self.body()
        self.assertIn('line 2', text)
        self.assertIn('line 3', text)
        self.assertNotIn('line 1', text)

    def test_a_corrupt_state_is_a_loss_not_a_first_run(self):
        t = Tree(self)
        with open(t.path('var/jt-alert-digest.state'), 'w') as fh:
            fh.write('{broken')
        t.write(alert(1))
        self.run_digest(t)
        self.assertIn('skipped', self.kinds())
        self.assertIn('line 1', self.body())

    def test_first_run_starts_after_the_last_complete_line(self):
        t = Tree(self)
        t.write(alert(1), partial='{"half')
        self.run_digest(t)
        self.assertEqual(t.state()['pos']['offset'], len(alert(1)) + 1)
        self.assertEqual(self.sent, [])

    def test_rule_mail_is_honoured_unless_a_level_is_set(self):
        t = Tree(self)
        self.run_digest(t)
        t.write(alert(1, level=10, mail=True, rule='100010'), alert(2, level=13, mail=False, rule='100013'))
        self.run_digest(t)
        self.assertIn('rule 100010', self.body())
        self.assertNotIn('rule 100013', self.body())
        t.conf('repeat = 0\ndaily = off\nlevel = 12\n')
        t.write(alert(3, level=10, mail=True, rule='100011'), alert(4, level=13, mail=False, rule='100014'))
        self.run_digest(t)
        self.assertIn('rule 100014', self.body())
        self.assertNotIn('rule 100011', self.body())

    def test_exclusions(self):
        t = Tree(self, conf='repeat = 0\ndaily = off\nexclude_rules = 100002\nexclude_agents = lab1\n')
        self.run_digest(t)
        t.write(alert(1), alert(2, rule='100002'), alert(3, rule='100003', agent='lab1'))
        self.run_digest(t)
        self.assertIn('1 alert at level 12', self.body())

    def test_lock_prevents_an_overlapping_run(self):
        import fcntl
        t = Tree(self)
        self.run_digest(t)
        t.write(alert(1))
        fd = os.open(t.path('var/jt-alert-digest.lock'), os.O_RDWR | os.O_CREAT)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.assertEqual(self.run_digest(t), 0)
        self.assertEqual(self.sent, [])


class TestSettings(DigestCase):

    def test_recipients_come_only_from_global(self):
        t = Tree(self)
        config = self.mod.read_global_config(t.root)
        self.assertEqual(config['email_to'], ['soc@example.com'])
        self.assertEqual(config['level'], 12)
        self.assertEqual((config['node'], config['node_type']), ('node02', 'worker'))

    def test_a_password_is_never_sent_without_tls(self):
        t = Tree(self)
        secret = t.path('etc/jt-packs/smtp.secret')
        with open(secret, 'w') as fh:
            fh.write('pw\n')
        os.chmod(secret, 0o600)
        config = self.mod.read_global_config(t.root)
        for tls in ('none', 'may'):
            _, fatal, _ = self.mod.build_options({'tls': tls, 'smtp_user': 'u', 'smtp_password_file': secret}, config)
            self.assertTrue(any('only sent over TLS' in f for f in fatal), tls)
        options, fatal, _ = self.mod.build_options({'tls': 'required', 'smtp_user': 'u',
                                                    'smtp_password_file': secret}, config)
        self.assertEqual(fatal, [])
        self.assertEqual(options['password'], 'pw')
        os.chmod(secret, 0o644)
        _, fatal, _ = self.mod.build_options({'tls': 'required', 'smtp_user': 'u', 'smtp_password_file': secret}, config)
        self.assertTrue(any('chmod 600' in f for f in fatal))

    def test_defaults_are_what_13_did(self):
        t = Tree(self)
        options, fatal, warnings = self.mod.build_options({}, self.mod.read_global_config(t.root))
        self.assertEqual((options['server'], options['port'], options['tls'], options['user']),
                         ('192.0.2.25', 25, 'none', None))
        self.assertEqual((fatal, warnings), ([], []))

    def test_configuration_errors_are_reported_on_change_not_every_run(self):
        t = Tree(self, conf='repeat = 0\ndaily = off\ntls = sometimes\n')
        for _ in range(3):
            self.run_digest(t)
        self.assertEqual(self.kinds().count('config_error'), 1)
        self.mod.NOW = T0 + 6 * 3600 + 1
        self.run_digest(t)
        self.assertEqual(self.kinds().count('config_error'), 2)

    def test_sendmail_program_receives_the_message_on_stdin(self):
        t = Tree(self)
        program = t.path('fake-sendmail')
        with open(program, 'w') as fh:
            fh.write('#!/bin/sh\necho "$@" > "%s.args"\ncat > "%s.eml"\n' % (program, program))
        os.chmod(program, 0o755)
        options, fatal, _ = self.mod.build_options({'smtp_server': program, 'sendmail_args': '-t -i'},
                                                   self.mod.read_global_config(t.root))
        self.assertEqual(fatal, [])
        message = self.mod.build_message('[Wazuh] x', 'text', '<p>html</p>', options, {'node': 'n'})
        self.originals['deliver'](message, options)
        with open(program + '.eml', 'rb') as fh:
            self.assertIn(b'Subject: [Wazuh] x', fh.read())
        with open(program + '.args') as fh:
            self.assertEqual(fh.read().strip(), '-t -i')


class TestDelivery(DigestCase):

    def test_failures_are_reported_once_then_hourly_and_escalate(self):
        """1.3: 703 identical level 10 alerts a day from one refusing server."""
        t = Tree(self)
        self.run_digest(t)
        t.write(alert(1, when=T0 - 30))
        self.refuse = 'rcpt-450'
        for minute in range(0, 60, 2):
            self.mod.NOW = T0 + minute * 60
            self.run_digest(t)
        self.assertEqual(self.kinds(), ['delivery_failed'])
        self.mod.NOW = T0 + 3601
        self.run_digest(t)
        self.assertEqual(self.kinds(), ['delivery_failed', 'delivery_failed'])
        self.mod.NOW = T0 + 2 * 3600 + 60
        self.run_digest(t)
        self.assertIn('undelivered', self.kinds())
        self.mod.NOW = T0 + 2 * 3600 + 180
        self.run_digest(t)
        self.assertEqual(self.kinds().count('undelivered'), 1)
        self.refuse = None
        self.run_digest(t)
        self.assertEqual(self.kinds()[-1], 'recovered')
        self.assertEqual(self.events[-1]['sent_late'], 1)

    def test_a_crash_is_reported_once_per_hour(self):
        t = Tree(self)
        self.run_digest(t)
        os.unlink(t.path('var/jt-alert-digest.state'))
        os.mkdir(t.path('var/jt-alert-digest.state'))     # cannot be read or replaced
        argv = ['--wazuh-path', t.root]
        stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            codes = [self.mod.main(argv) for _ in range(3)]
        finally:
            sys.stderr = stderr
        self.assertEqual(codes, [3, 3, 3])
        self.assertEqual(self.kinds().count('crashed'), 1)
        self.assertEqual(self.kinds().count('skipped'), 0)

    def test_message_headers(self):
        t = Tree(self)
        options, _, _ = self.mod.build_options({}, self.mod.read_global_config(t.root))
        groups = {('1', 'host\nX-Injected: 1'): {'level': 12, 'descriptions': ['Bad\r\nBcc: x@example.net'],
                                                 'mitre': [], 'count': 1, 'first': stamp(T0), 'last': stamp(T0),
                                                 'samples': []}}
        line = self.mod.subject(groups, 1)
        self.assertNotIn('\n', line)
        message = self.mod.build_message(line, 'caf\u00e9 \u4e2d\u6587', '<p>caf\u00e9</p>', options,
                                         {'node': 'node02'}, 1)
        raw = message.as_bytes()
        parsed = email.message_from_bytes(raw, policy=email.policy.default)
        self.assertTrue(parsed['Message-ID'].endswith('@example.com>'))
        self.assertEqual(parsed['Auto-Submitted'], 'auto-generated')
        self.assertEqual(parsed['X-Wazuh-Node'], 'node02')
        self.assertIsNone(parsed['X-Injected'])
        self.assertIsNone(parsed['Bcc'])
        self.assertEqual(raw.count(b'Content-Transfer-Encoding: quoted-printable'), 2)
        raw.decode('ascii')

    def test_a_real_smtp_exchange_on_loopback(self):
        received = []

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                w = lambda s: self.wfile.write((s + '\r\n').encode())
                w('220 test')
                while True:
                    line = self.rfile.readline().decode().strip()
                    verb = line[:4].upper()
                    if not line or verb == 'QUIT':
                        w('221 bye')
                        return
                    if verb == 'EHLO':
                        w('250 test')
                    elif verb == 'RCPT' and 'refuse' in line:
                        w('450 4.7.1 Client host rejected')
                    elif verb == 'DATA':
                        w('354 go')
                        data = []
                        while True:
                            chunk = self.rfile.readline()
                            if chunk in (b'.\r\n', b''):
                                break
                            data.append(chunk)
                        received.append(b''.join(data))
                        w('250 queued')
                    else:
                        w('250 ok')

        server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        t = Tree(self, smtp='127.0.0.1', conf='repeat = 0\ndaily = off\nsmtp_port = %d\n' % server.server_address[1])
        options, fatal, _ = self.mod.build_options(self.mod.read_site_settings(t.root),
                                                   self.mod.read_global_config(t.root))
        self.assertEqual(fatal, [])
        message = self.mod.build_message('[Wazuh] s', 'text', '<p>h</p>', options, {'node': 'n'})
        self.originals['deliver'](message, options)
        self.assertEqual(len(received), 1)
        options['to'] = ['refuse@example.com']
        with self.assertRaises(self.mod.DeliveryError) as caught:
            self.originals['deliver'](message, options)
        self.assertEqual(caught.exception.kind, 'rcpt-450')

    def test_max_per_hour_holds_without_dropping(self):
        t = Tree(self, conf='repeat = 0\ndaily = off\nmax_per_hour = 1\n')
        self.run_digest(t)
        t.write(alert(1))
        self.run_digest(t)
        t.write(alert(2, rule='100002'))
        self.run_digest(t)
        self.assertEqual(len(self.sent), 1)
        self.mod.NOW = T0 + 3601
        self.run_digest(t)
        self.assertEqual(len(self.sent), 2)
        self.assertIn('rule 100002', self.body())

    def test_cron_log_is_kept_bounded(self):
        t = Tree(self)
        log = t.path('logs/jt-alert-digest.log')
        with open(log, 'w') as fh:
            fh.write(('y' * 99 + '\n') * 20000)
        self.run_digest(t)
        self.assertLessEqual(os.path.getsize(log), self.mod.LOG_CAP // 2 + 100)


class TestNoise(DigestCase):

    def test_repeats_are_held_counted_and_listed(self):
        t = Tree(self, conf='daily = off\n')
        self.run_digest(t)
        t.write(alert(1))
        self.run_digest(t)
        t.write(alert(2), alert(3))
        self.mod.NOW = T0 + 120
        self.run_digest(t)
        self.assertEqual(len(self.sent), 1)
        t.write(alert(4, rule='100009', desc='Other'))
        self.mod.NOW = T0 + 240
        self.run_digest(t)
        self.assertIn('Still ongoing', self.body())
        self.assertIn('rule 100001 on host1: +2', self.body())
        t.write(alert(5, level=14))
        self.mod.NOW = T0 + 360
        self.run_digest(t)
        self.assertEqual(len(self.sent), 3, 'a level rise is never held')

    def test_a_held_count_is_flushed_when_the_hold_runs_out(self):
        t = Tree(self, conf='daily = off\n')
        self.run_digest(t)
        t.write(alert(1))
        self.run_digest(t)
        t.write(alert(2))
        self.mod.NOW = T0 + 300
        self.run_digest(t)
        self.assertEqual(len(self.sent), 1)
        self.mod.NOW = T0 + 3700
        self.run_digest(t)
        self.assertEqual(len(self.sent), 2)
        self.assertTrue(self.sent[-1]['Subject'].startswith('[Wazuh] Still ongoing'))

    def test_new_pairs_are_marked_after_the_first_day(self):
        t = Tree(self)
        self.run_digest(t)
        t.write(alert(1))
        self.run_digest(t)
        self.assertNotIn('NEW', self.sent[-1]['Subject'])
        self.mod.NOW = T0 + 86400 + 60
        t.write(alert(2), alert(3, rule='100002', when=self.mod.NOW - 10))
        self.run_digest(t)
        self.assertTrue(self.sent[-1]['Subject'].startswith('[Wazuh] NEW '))
        self.assertIn('NEW RULE', self.body())

    def test_a_source_address_names_the_agent_it_belongs_to(self):
        # an alert about an internal address guessing logins should say which machine that is
        t = Tree(self, conf='repeat = 0\n')
        self.run_digest(t)
        scanner = json.loads(alert(1, level=3, agent='scanner7', agent_id='031'))
        scanner['agent']['ip'] = '192.0.2.77'
        hit = json.loads(alert(2, level=12, rule='132711', agent='srv-b', agent_id='044',
                               desc='internal address guessing logins'))
        hit['data'] = {'srcip': '192.0.2.77', 'dstuser': 'oxidized'}
        t.write(json.dumps(scanner), json.dumps(hit))
        self.run_digest(t)
        self.assertIn('192.0.2.77 (scanner7)', self.body())
        path = t.path('var/jt-alert-digest.agents')
        self.assertEqual(json.load(open(path)).get('192.0.2.77'), 'scanner7')
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o600')
        # agents registered with "any" and the manager itself are not learnt
        self.mod.AGENTS.clear()
        self.mod.learn_agent(b'{"agent":{"id":"005","name":"web1","ip":"any"}}')
        self.mod.learn_agent(b'{"agent":{"id":"000","name":"manager","ip":"192.0.2.1"}}')
        self.assertEqual(self.mod.AGENTS, {})
        self.assertEqual(self.mod.host_label('198.51.100.9'), '198.51.100.9')

    def test_daily_summary_and_agent_health(self):
        t = Tree(self, conf='repeat = 0\ndaily = %s\n' % time.strftime('%H:%M', time.localtime(T0 + 600)))
        self.run_digest(t)
        # the restart's "started" arrives under a site rule that overrides 503
        # (on a live manager 43 deliberate restarts were listed as stopped)
        t.write(alert(1, level=3, rule='506', agent='win1', agent_id='020', when=T0 - 1800,
                      full_log="ossec: Agent stopped: 'win1->any'."),
                alert(2, level=3, rule='506', agent='lin1', agent_id='021', when=T0 - 1700,
                      full_log="ossec: Agent stopped: 'lin1->any'."),
                alert(3, level=5, rule='100963', agent='lin1', agent_id='021', when=T0 - 1650,
                      full_log="ossec: Agent started: 'lin1->any'."),
                alert(5, level=3, rule='506', agent='new1', agent_id='022', when=T0 - 1600,
                      full_log="ossec: Agent stopped: 'new1->any'."),
                alert(6, level=3, rule='501', agent='new1', agent_id='022', when=T0 - 1590,
                      full_log="ossec: Agent started: 'new1->any'."),
                alert(7, level=3, rule='504', agent='manager1', agent_id='000', when=T0 - 1500,
                      full_log="ossec: Agent disconnected: 'gone1-any'."),
                alert(4))
        self.mod.NOW = T0 + 900
        self.run_digest(t)
        summary = self.sent[-1]
        self.assertTrue(summary['Subject'].startswith('[Wazuh] Daily summary node02'))
        text = self.body(summary)
        self.assertIn('win1 (stopped', text)
        self.assertNotIn('lin1', text)
        self.assertNotIn('new1', text)
        self.assertIn('gone1 (x1)', text)
        self.assertIn('L3: 5', text)
        self.run_digest(t)
        self.assertEqual(sum(1 for m in self.sent if 'Daily summary' in m['Subject']), 1)


class TestContent(DigestCase):

    def test_redaction(self):
        r = self.mod.redact
        cases = [
            ('GET /login?user=a&password=hunter2&x=1', 'hunter2'),
            ('Authorization: Bearer abcdefghijklmnopqrstu', 'abcdefghijklmnopqrstu'),
            ('curl https://bob:s3cretpw@example.com/', 's3cretpw'),
            ('token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl', 'eyJzdWIiOiIxIn0'),
            ('{"client_secret":"zzzSECRETzzz"}', 'zzzSECRETzzz'),
            ('net use \\\\srv\\share Pa55w0rd /user:corp\\bob', 'Pa55w0rd'),
            ('mysql -uroot -pTopSecret1 db', 'TopSecret1'),
            ('sshpass -p hunter3 ssh root@192.0.2.1', 'hunter3'),
            ('ngrok tcp 3389 --authtoken 2abcDEFghiJKLmnoPQRstu', '2abcDEFghiJKLmnoPQRstu'),
            ('$p = ConvertTo-SecureString "Winter2026!" -AsPlainText -Force', 'Winter2026!'),
            ('key AKIAABCDEFGHIJKLMNOP used', 'AKIAABCDEFGHIJKLMNOP'),
            ('Cookie: session=abc123def', 'abc123def'),
        ]
        for text, secret in cases:
            with self.subTest(text=text):
                self.assertNotIn(secret, r(text))
        for harmless in ('sudo: bob : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/ls',
                         'Failed password for root from 192.0.2.1 port 22 ssh2',
                         '?per_page=5&consumer_key=&consumer_secret= HTTP/1.1'):
            with self.subTest(text=harmless):
                self.assertEqual(r(harmless), harmless)

    def test_windows_fields_collapse_doubled_backslashes(self):
        win = {'system': {'providerName': 'Microsoft-Windows-Sysmon', 'eventID': '11',
                          'message': '"File created:\r\nRuleName: x"'},
               'eventdata': {'targetFilename': 'C:\\\\Users\\\\u\\\\AppData\\\\Local\\\\Temp\\\\a.ps1',
                             'image': 'C:\\\\Windows\\\\System32\\\\sftp-server.exe', 'user': 'PC\\\\u'}}
        fields = dict(self.mod.interesting_fields({'data': {'win': win}}))
        self.assertEqual(fields['Event'], 'Sysmon 11, File created')
        self.assertEqual(fields['File'], 'C:\\Users\\u\\AppData\\Local\\Temp\\a.ps1')
        self.assertEqual(fields['User'], 'PC\\u')
        defender = {'system': {'providerName': 'Microsoft-Windows-Windows Defender', 'eventID': '1116'},
                    'eventdata': {'threat Name': 'Trojan:Win32/X', 'path': 'C:\\\\x.exe', 'action Name': 'Quarantine'}}
        fields = dict(self.mod.interesting_fields({'data': {'win': defender}}))
        self.assertEqual((fields['Threat'], fields['Path']), ('Trojan:Win32/X', 'C:\\x.exe'))

    def test_vulnerabilities_are_one_line_per_package(self):
        groups = {}
        for i, cve in enumerate(('CVE-2026-1001', 'CVE-2026-1002', 'CVE-2025-9')):
            a = json.loads(alert(i, level=13, rule='23506', desc='%s affects pkg' % cve,
                                 data={'vulnerability': {'cve': cve, 'score': {'base': '9.8' if i == 0 else '5.0'},
                                                         'package': {'name': 'pkg', 'version': '1.2'}}}))
            self.mod.add_alert(groups, a, a['rule'], 13)
        text = self.mod.render_text(groups, 3, 12, None)
        self.assertIn('Package: pkg 1.2: 3 CVEs, max CVSS 9.8: CVE-2026-1001, CVE-2026-1002, CVE-2025-9', text)
        self.assertIn('Vulnerabilities detected', text)
        self.assertNotIn('CVE-202 ...', text)

    def test_container_images_are_one_line_per_image(self):
        groups = {}
        for i in range(5):
            image = 'registry.example.com/app%d:1.%d' % (i, i)
            record = {'type': 'image', 'image': image, 'containers': 'web%d' % i,
                      'msg': '%s: %d critical (1 fixable), 3 high (2 fixable); first scan' % (image, i + 1)}
            a = json.loads(alert(i, level=10, rule='132803', mail=True,
                                 desc='[WARN] Container image %s has critical vulnerabilities' % image,
                                 data={'container_vuln': record}))
            self.mod.add_alert(groups, a, a['rule'], 10)
        group = list(groups.values())[0]
        self.assertEqual(group['kind'], 'container')
        for render, line, containers in (
                (lambda: self.mod.render_text(groups, 5, 10, None),
                 'registry.example.com/app%d:1.%d: %d critical', '[containers: web4]'),
                (lambda: self.mod.render_html(groups, 5, 10, None),
                 'registry.example.com/app%d:1.%d: %d critical', '[containers: web4]'),
                (lambda: '\n'.join(self.mod.render_zulip(groups, 5, 10, None)),
                 '> **Image** `registry.example.com/app%d:1.%d` %d critical', '[containers: web4]')):
            out = render()
            for i in range(5):
                self.assertIn(line % (i, i, i + 1), out)
            self.assertIn(containers, out)
            self.assertNotIn('more of the same', out)
        self.assertIn('**L10 · Container image has critical vulnerabilities** ×5',
                      '\n'.join(self.mod.render_zulip(groups, 5, 10, None)))
        # a status line of the same scanner is an ordinary alert, not an image
        status = json.loads(alert(9, level=10, rule='132821', mail=True,
                                  data={'container_vuln': {'type': 'status', 'msg': 'docker down'}}))
        self.assertEqual(self.mod.alert_kind(status), 'other')

    def test_zulip_layout_uses_zulip_markdown(self):
        groups = {}
        a = json.loads(alert(1, level=13, rule='100940', desc='Scheduled task modified: /etc/cron.d/x',
                             syscheck={'path': '/etc/cron.d/x', 'event': 'modified', 'perm_after': 'rw-r--r--',
                                       'sha256_after': 'a' * 64, 'changed_attributes': ['md5']}))
        self.mod.add_alert(groups, a, a['rule'], 13)
        b = json.loads(alert(2, level=12, rule='5108', agent='h2', desc='Out of memory'))
        b['data'] = {'srcip': '203.0.113.9', 'dstuser': 'bob'}
        self.mod.add_alert(groups, b, b['rule'], 12)
        c = json.loads(alert(3, level=12, rule='5109', agent='h3', desc='Kernel says something'))
        self.mod.add_alert(groups, c, c['rule'], 12)
        out = '\n'.join(self.mod.render_zulip(groups, 3, 12, 'https://dash.example.com/',
                                              {'node': 'node01'}))
        self.assertTrue(out.startswith('\U0001F6A8 **3 alerts** · 3 rules · hosts '), out[:80])
        self.assertIn('\U0001F7E0 **L13 · Scheduled task modified: /etc/cron.d/x**', out)
        # a bar in the level's colour marks where each card starts
        self.assertIn('\U0001F7E7' * 10 + '\n\U0001F7E0 **L13 · ', out)
        self.assertEqual(self.mod.level_bar(15)[0], '\U0001F7E5')
        self.assertEqual(self.mod.level_bar(10)[0], '\U0001F7E8')
        self.assertIn('> **File** `/etc/cron.d/x` (modified)', out)
        # short values in the table, the raw line collapsed as wrapped text
        self.assertIn('| Source | 203.0.113.9 |', out)
        self.assertIn('| Account | bob |', out)
        self.assertIn('```spoiler Log\nline 2\n```', out)
        # nothing decoded: the line itself is the content and stays visible
        self.assertIn('> line 3', out)
        # Zulip shows _x_ literally; italics are *x*
        self.assertNotRegex(out, r'(^|\s)_[^_\s]')
        self.assertIn('*sent by node01 · jt-alert-digest %s*' % self.mod.VERSION, out)

    def test_zulip_table_cells_stay_narrow_enough_for_a_phone(self):
        # Zulip never wraps a table cell: a long value goes below the table instead
        groups = {}
        a = json.loads(alert(1, level=12, rule='100940', desc='Changed',
                             syscheck={'path': '/etc/cron.d/x', 'event': 'modified', 'perm_after': 'rw-r--r--',
                                       'changed_attributes': ['size', 'permission', 'uid', 'gid', 'user_name',
                                                              'group_name', 'mtime', 'inode', 'md5', 'sha256']}))
        self.mod.add_alert(groups, a, a['rule'], 12)
        out = '\n'.join(self.mod.render_zulip(groups, 1, 12, None, {'node': 'n'}))
        for line in out.split('\n'):
            if line.startswith('| ') and not line.startswith('| Rule |'):
                value = line.split(' | ', 1)[1].rstrip(' |')
                self.assertLessEqual(len(value.replace('`', '').replace('\\', '')), 30, line)
        self.assertIn('> **Changed** size, permission', out)
        self.assertTrue(self.mod.fits_table('Account', 'alice'))
        self.assertFalse(self.mod.fits_table('File', '/var/www/html/wp-content/uploads/x.php'))
        self.assertFalse(self.mod.fits_table('Account', 'a|b'), 'a pipe would end the cell')
        self.assertFalse(self.mod.fits_table('User', '\u4f7f\u7528\u8005' * 6), 'wide characters count double')

    def test_zulip_text_has_no_backslash_escapes(self):
        # Zulip does not honour them: 1.7 showed "sshd\\[4242\\]" in a log
        md = self.mod.md
        self.assertEqual(md('sshd[4242]: oom_score_adj user_name'), 'sshd[4242]: oom_score_adj user_name')
        for text in ('Hi @**all**', 'see [here](http://evil.example/x)', '$$x$$', '~~gone~~',
                     '`code`', '**bold**', '@_**silent**'):
            out = md(text)
            self.assertNotIn('\\', out, text)
            for construct in ('@**', '](', '$$', '~~', '`', '**', '@_'):
                self.assertNotIn(construct, out, text)
        self.assertTrue(md('- item').startswith('\u200b-'))
        self.assertTrue(md('1. item').startswith('\u200b1.'))

    def test_zulip_daily_summary_collapses_a_long_agent_list(self):
        t = 1792400000
        daily = {'since': t - 86400, 'qualifying': 8, 'digests': 6, 'mailed': 5, 'held': 3,
                 'stops': {}, 'disconnects': {}}
        stopped = [('host%d' % i, t - 3600) for i in range(12)]
        out = self.mod.daily_zulip({'node': 'manager1', 'node_type': 'master'}, {'level': 12}, daily, t,
                                   [(13, 5), (10, 458)], [('100941', (4, 13, 'systemd unit changed'))],
                                   stopped, None, [], [])
        self.assertIn('**Agents stopped and not back within 15 minutes** (12)\n```spoiler Show all', out)
        self.assertIn('> L13 5 · L10 458', out)
        self.assertIn('- \U0001F7E0 **L13** · rule 100941 ×4 · systemd unit changed', out)
        failing = self.mod.daily_zulip({'node': 'manager1'}, {'level': 12}, daily, t, [], [], [],
                                       {'since': t - 7200, 'kind': 'rcpt-450', 'attempts': 9, 'pending': 4},
                                       [], [])
        self.assertTrue(failing.startswith('\U0001F7E5'), 'a red bar when delivery is failing')
        self.assertIn('> **Delivery** \u274c failing since', failing)

    def test_a_cut_block_closes_a_spoiler_and_its_code_block(self):
        block = '```spoiler Logs\n~~~text\n' + '\n'.join('x' * 80 for _ in range(200)) + '\n~~~\n```'
        out = self.mod.cut_block(block, 2000)
        lines = out.split('\n')
        self.assertLess(len(out), 2000)
        self.assertEqual(lines[-3:], ['~~~', '```', '*(cut to fit one message)*'])

    def test_headings_are_not_cut_inside_a_token(self):
        p = self.mod.shared_prefix
        self.assertNotIn('202', p(['CVE-2024-1 affects a', 'CVE-2025-2 affects b']))
        self.assertEqual(p(['Remote address: 10.0.0.1', 'Remote address: 10.0.0.2']), 'Remote address ...')
        self.assertEqual(p(['Login failed for alice', 'Login failed for bob']), 'Login failed for ...')

    def test_message_stays_below_the_clipping_size(self):
        groups = {}
        for g in range(40):
            for s in range(3):
                a = json.loads(alert(g * 3 + s, rule=str(120000 + g), agent='h%d' % g))
                a['full_log'] = 'z' * 190 + ' %d' % s
                self.mod.add_alert(groups, a, a['rule'], 12)
        html = self.mod.render_html(groups, 120, 12, None)
        self.assertLess(len(html), 102 * 1024)
        self.assertIn('more groups', html)

    def test_dashboard_links_carry_rule_agent_and_window(self):
        options, _, _ = self.mod.build_options({'dashboard': 'https://dash.example.com/app/wazuh'},
                                               {'smtp_server': 'x', 'email_from': 'a@example.com',
                                                'email_to': ['b@example.com'], 'level': 12})
        group = {'agent_id': '020', 'first': stamp(T0), 'last': stamp(T0 + 60)}
        url = self.mod.group_link(options['link'], options['base'], '92213', group, 'win1')
        self.assertTrue(url.startswith('https://dash.example.com/app/threat-hunting#/overview/'))
        self.assertIn("rule.id:92213", url)
        self.assertIn('agentId=020', url)
        bad = self.mod.group_link(options['link'], options['base'], '1"><x', {'agent_id': '"><'}, 'a')
        self.assertNotIn('"', bad)

    def test_an_empty_ca_store_falls_back_to_the_system_bundle(self):
        # Wazuh's framework python has no CA certificates (v1.16.0 on a live manager).
        import shutil
        import ssl
        where = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, where, True)
        bundle = os.path.join(where, 'bundle.pem')
        source = next((p for p in self.mod.SYSTEM_CA_BUNDLES if os.path.isfile(p)), None)
        if source is None:
            source = ssl.get_default_verify_paths().cafile
        if not source or not os.path.isfile(source):
            self.skipTest('no CA bundle on this machine')
        shutil.copy(source, bundle)
        real = ssl.create_default_context

        def empty(*args, **kwargs):
            context = real(*args, **kwargs)
            if not kwargs.get('cafile') and not (args and args[0]):
                return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            return context
        saved = self.mod.SYSTEM_CA_BUNDLES
        self.mod.ssl.create_default_context = empty
        try:
            self.mod.SYSTEM_CA_BUNDLES = (os.path.join(where, 'missing.pem'), bundle)
            context = self.mod.zulip_context({'verify': True})
            self.assertGreater(context.cert_store_stats()['x509_ca'], 0)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertGreater(self.mod.tls_context({'verify': True}).cert_store_stats()['x509_ca'], 0)
        finally:
            self.mod.ssl.create_default_context = real
            self.mod.SYSTEM_CA_BUNDLES = saved

    def test_the_script_parses_as_python_38(self):
        import ast
        with io.open(SCRIPT, encoding='utf-8') as fh:
            ast.parse(fh.read(), feature_version=(3, 8))


class FakeZulip(object):
    """A stand-in for the Zulip API on 127.0.0.1, started and stopped by each test.

    POST /api/v1/messages answers from `replies` (status, body) in order, then
    success. Every request is recorded with its headers and decoded form.
    """

    KEY = 'k3yABCDEFghijklmnopQRSTuvwxyz012'
    EMAIL = 'alerts-bot@example.com'

    def __init__(self, test):
        self.requests, self.replies = [], []
        self.private, self.subscribed = False, True
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body):
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def handle_any(self, method):
                length = int(self.headers.get('Content-Length') or 0)
                raw = self.rfile.read(length) if length else b''
                path, _, query = self.path.partition('?')
                form = parse_qs(raw.decode('utf-8') if raw else query)
                fake.requests.append({'method': method, 'path': path, 'headers': dict(self.headers),
                                      'form': {k: v[0] for k, v in form.items()}})
                expected = 'Basic ' + base64.b64encode(
                    ('%s:%s' % (fake.EMAIL, fake.KEY)).encode()).decode()
                if self.headers.get('Authorization') != expected:
                    return self.reply(401, {'result': 'error', 'code': 'INVALID_API_KEY',
                                            'msg': 'Invalid API key'})
                if path == '/api/v1/messages' and method == 'POST':
                    if fake.replies:
                        return self.reply(*fake.replies.pop(0))
                    return self.reply(200, {'result': 'success', 'id': len(fake.requests)})
                if path == '/api/v1/users/me':
                    return self.reply(200, {'result': 'success', 'email': fake.EMAIL,
                                            'full_name': 'Alerts', 'is_bot': True})
                if path == '/api/v1/get_stream_id':
                    if form.get('stream', [''])[0] != 'wazuh' or (fake.private and not fake.subscribed):
                        return self.reply(400, {'result': 'error', 'code': 'BAD_REQUEST',
                                                'msg': 'Invalid channel name'})
                    return self.reply(200, {'result': 'success', 'stream_id': 7})
                if path == '/api/v1/users/me/subscriptions':
                    subs = [{'stream_id': 7, 'name': 'wazuh'}] if fake.subscribed else []
                    return self.reply(200, {'result': 'success', 'subscriptions': subs})
                if path == '/api/v1/streams/7':
                    return self.reply(200, {'result': 'success', 'stream': {
                        'stream_id': 7, 'name': 'wazuh', 'invite_only': fake.private}})
                return self.reply(404, {'result': 'error', 'code': 'BAD_REQUEST', 'msg': 'no'})

            def do_GET(self):
                self.handle_any('GET')

            def do_POST(self):
                self.handle_any('POST')

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        test.addCleanup(self.server.server_close)
        test.addCleanup(self.server.shutdown)
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]

    def posts(self):
        return [r for r in self.requests if r['method'] == 'POST']


class TestZulip(DigestCase):

    def setUp(self):
        DigestCase.setUp(self)
        self.zulip = FakeZulip(self)

    def tree(self, extra='', mode=0o600):
        t = Tree(self)
        key = t.path('etc/jt-packs/zulip.key')
        with open(key, 'w') as fh:
            fh.write(FakeZulip.KEY + '\n')
        os.chmod(key, mode)
        t.conf('repeat = 0\ndaily = off\nzulip_url = %s\nzulip_email = %s\nzulip_api_key_file = %s\n'
               'zulip_stream = wazuh\nzulip_topic = 警報\n%s'
               % (self.zulip.url, FakeZulip.EMAIL, key, extra))
        self.run_digest(t)                      # first run: both channels start at the end
        return t

    def zulip_events(self):
        return [e['event'] for e in self.events if e.get('channel') == 'zulip']

    def test_message_shape_auth_and_utf8_topic(self):
        t = self.tree()
        t.write(alert(1), alert(2, rule='100002', level=13))
        self.assertEqual(self.run_digest(t), 0)
        posts = self.zulip.posts()
        self.assertEqual(len(posts), 1)
        form = posts[0]['form']
        self.assertEqual((form['type'], form['to'], form['topic']), ('stream', 'wazuh', '警報'))
        self.assertIn('**L13 · ', form['content'])
        self.assertIn('| Host | host1 |\n|:--|:--|\n| Address | 192.0.2.10 · agent 001 |', form['content'])
        self.assertIn('| Rule | 100002 |', form['content'])
        self.assertIn('line 1', form['content'])
        token = base64.b64encode(('%s:%s' % (FakeZulip.EMAIL, FakeZulip.KEY)).encode()).decode()
        self.assertEqual(posts[0]['headers']['Authorization'], 'Basic ' + token)
        self.assertEqual(len(self.sent), 1, 'mail goes out as well')
        self.run_digest(t)
        self.assertEqual(len(self.zulip.posts()), 1, 'nothing new, nothing posted')

    def test_alert_text_cannot_mention_or_link(self):
        t = self.tree()
        t.write(alert(1, desc='Hi @**all** see [here](http://evil.example/x)', agent='a_b*c'))
        self.run_digest(t)
        content = self.zulip.posts()[0]['form']['content']
        self.assertNotIn('@**all**', content)
        self.assertNotIn('[here](http', content)

    def test_long_digests_are_split_without_cutting_a_group(self):
        t = self.tree()
        lines = []
        for g in range(40):
            for n in range(3):
                a = json.loads(alert(g * 3 + n, rule=str(120000 + g), agent='h%d' % g))
                a['full_log'] = 'z' * 190 + ' %d' % n
                lines.append(json.dumps(a))
        t.write(*lines)
        self.run_digest(t)
        posts = [p['form']['content'] for p in self.zulip.posts()]
        self.assertTrue(1 < len(posts) <= 4, len(posts))
        for i, content in enumerate(posts):
            self.assertLessEqual(len(content), 9000)
            self.assertTrue(content.startswith('*(%d/%d)*' % (i + 1, len(posts))))
            for mark in ('~~~', '```'):
                fences = [l for l in content.split('\n') if l.startswith(mark)]
                self.assertEqual(len(fences) % 2, 0, 'a %s block left open' % mark)
        for g in range(40):
            rule = names_rule(120000 + g)
            self.assertEqual(sum(1 for c in posts if rule.search(c)), 1, rule.pattern)

    def test_zulip_down_does_not_touch_mail(self):
        t = self.tree()
        t.write(alert(1))
        self.zulip.replies = [(503, {'result': 'error', 'msg': 'down'})] * 2
        self.assertEqual(self.run_digest(t), 1)
        self.assertEqual(len(self.sent), 1, 'mail delivered while Zulip is down')
        self.assertEqual(self.zulip_events(), ['delivery_failed'])
        self.assertEqual(self.events[0]['error_class'], 'http-503')
        self.mod.NOW = T0 + 120
        self.run_digest(t)
        self.assertEqual(len(self.sent), 1, 'mail is not sent again')
        self.assertEqual(self.zulip_events(), ['delivery_failed'], 'not reported every run')
        self.mod.NOW = T0 + 240
        self.run_digest(t)                      # replies used up: Zulip answers again
        self.assertEqual(self.zulip_events(), ['delivery_failed', 'recovered'])
        self.assertEqual(sum(1 for p in self.zulip.posts() if 'line 1' in p['form']['content']), 3)
        self.assertEqual(len(self.sent), 1)
        self.run_digest(t)
        self.assertEqual(len(self.zulip.posts()), 3, 'posted once successfully, never again')

    def test_mail_down_does_not_touch_zulip(self):
        t = self.tree()
        t.write(alert(1))
        self.refuse = 'rcpt-450'
        self.run_digest(t)
        self.run_digest(t)
        self.assertEqual(len(self.zulip.posts()), 1, 'posted once, not again while mail fails')
        self.assertEqual([e['event'] for e in self.events if not e.get('channel')], ['delivery_failed'])
        self.refuse = None
        self.run_digest(t)
        self.assertIn('line 1', self.body())
        self.assertEqual(len(self.zulip.posts()), 1)

    def test_a_failure_halfway_through_a_split_post_resumes_without_repeating(self):
        t = self.tree()
        lines = []
        for g in range(30):
            a = json.loads(alert(g, rule=str(130000 + g), agent='h%d' % g))
            a['full_log'] = 'y' * 300
            lines.append(json.dumps(a))
        t.write(*lines)
        self.zulip.replies = [(200, {'result': 'success', 'id': 1}), (502, {'result': 'error', 'msg': 'x'})]
        self.run_digest(t)
        first = [p['form']['content'] for p in self.zulip.posts()]
        self.assertEqual(len(first), 2)
        self.run_digest(t)
        posts = [p['form']['content'] for p in self.zulip.posts()]
        resent = posts[2:]
        self.assertNotIn(first[0], resent, 'the part already posted is not posted again')
        self.assertEqual(resent[0], first[1], 'the failed part is retried as it was')
        for g in range(30):
            ok = [c for c in [first[0]] + resent if names_rule(130000 + g).search(c)]
            self.assertEqual(len(ok), 1)

    def test_401_is_a_configuration_failure_and_5xx_is_not(self):
        t = self.tree()
        t.write(alert(1))
        self.zulip.replies = [(401, {'result': 'error', 'code': 'INVALID_API_KEY', 'msg': 'Invalid API key'})] * 5
        for minute in (0, 2, 4):
            self.mod.NOW = T0 + minute * 60
            self.run_digest(t)
        events = [e for e in self.events if e.get('channel') == 'zulip']
        self.assertEqual([e['event'] for e in events], ['config_error'])
        self.assertEqual(events[0]['error_class'], 'http-401-INVALID_API_KEY')
        self.mod.NOW = T0 + 3 * 3600
        self.run_digest(t)
        self.assertEqual(self.zulip_events(), ['config_error'], 'no two-hour escalation for a refused key')

    def test_key_file_must_be_root_only(self):
        t = self.tree(mode=0o644)
        t.write(alert(1))
        self.run_digest(t)
        self.assertEqual(self.zulip.posts(), [])
        problems = [e['problem'] for e in self.events if e.get('channel') == 'zulip' and e['event'] == 'config_error']
        self.assertTrue(problems and 'chmod 600' in problems[0])
        self.assertEqual(len(self.sent), 1, 'mail is unaffected')

    def test_the_key_appears_nowhere(self):
        t = self.tree()
        t.write(alert(1))
        self.zulip.replies = [(401, {'result': 'error', 'code': 'INVALID_API_KEY',
                                     'msg': 'Invalid API key %s' % FakeZulip.KEY})]
        self.run_digest(t)
        self.run_digest(t)
        out = io.StringIO()
        stdout = sys.stdout
        sys.stdout = out
        try:
            options, _, _ = self.mod.build_options(self.mod.read_site_settings(t.root),
                                                   self.mod.read_global_config(t.root))
            self.mod.check_zulip(options['zulip'], options['zulip_fatal'])
        finally:
            sys.stdout = stdout
        token = base64.b64encode(('%s:%s' % (FakeZulip.EMAIL, FakeZulip.KEY)).encode()).decode()
        with open(t.path('var/jt-alert-digest.state')) as fh:
            state = fh.read()
        for text in (state, json.dumps(self.events), '\n'.join(self.logs), out.getvalue()):
            self.assertNotIn(FakeZulip.KEY, text)
            self.assertNotIn(token, text)

    def test_without_zulip_settings_nothing_changes(self):
        t = Tree(self)
        self.run_digest(t)
        t.write(alert(1))
        self.run_digest(t)
        self.assertNotIn('zulip', t.state())
        self.assertEqual(self.zulip.requests, [])
        self.assertTrue(all('channel' not in e for e in self.events))
        self.assertEqual(len(self.sent), 1)

    def test_an_old_backlog_becomes_a_count(self):
        t = self.tree()
        t.write(alert(1, when=T0 - 30 * 3600), alert(2, when=T0 - 29 * 3600), alert(3, rule='100003'))
        self.run_digest(t)
        content = self.zulip.posts()[0]['form']['content']
        self.assertIn('2 alerts from', content)
        self.assertRegex(content, names_rule(100003))
        self.assertNotIn('line 1', content)
        self.assertIn('skipped', self.zulip_events())
        self.assertIn('3 alerts at level 12', self.body(), 'mail keeps every alert')

    def test_check_reads_and_test_posts_but_neither_mails(self):
        t = self.tree()
        options, _, _ = self.mod.build_options(self.mod.read_site_settings(t.root),
                                               self.mod.read_global_config(t.root))
        stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self.assertEqual(self.mod.check_zulip(options['zulip'], []), 0)
            self.zulip.private, self.zulip.subscribed = True, False
            self.assertEqual(self.mod.check_zulip(options['zulip'], []), 1)
            self.assertEqual(self.run_digest(t, '--test', 'zulip'), 0)
        finally:
            sys.stdout = stdout
        self.assertEqual([r['method'] for r in self.zulip.requests].count('POST'), 1)
        self.assertEqual(self.sent, [])

    def test_daily_summary_goes_to_its_own_topic_and_mail_still_gets_one(self):
        daily = time.strftime('%H:%M', time.localtime(T0 + 600))
        t = Tree(self)
        key = t.path('etc/jt-packs/zulip.key')
        with open(key, 'w') as fh:
            fh.write(FakeZulip.KEY + '\n')
        os.chmod(key, 0o600)
        t.conf('repeat = 0\ndaily = %s\nzulip_url = %s\nzulip_email = %s\nzulip_api_key_file = %s\n'
               'zulip_stream = wazuh\nzulip_topic = 警報\nzulip_summary_topic = summary\n'
               % (daily, self.zulip.url, FakeZulip.EMAIL, key))
        self.run_digest(t)
        self.mod.NOW = T0 + 900
        self.run_digest(t)
        posts = self.zulip.posts()
        self.assertEqual([p['form']['topic'] for p in posts], ['summary'])
        content = posts[0]['form']['content']
        self.assertIn('**Daily summary · node02 (worker)**', content)
        self.assertIn('| Mail | \u2705 working |', content)
        self.assertIn('| Delivery | \u2705 working |', content)
        self.assertNotIn('~~~', content, 'Zulip markdown, not a code block that scrolls sideways')
        self.assertEqual(sum(1 for m in self.sent if 'Daily summary' in m['Subject']), 1)
        self.assertIn('Zulip: working', self.body())
        self.run_digest(t)
        self.assertEqual(len(self.zulip.posts()), 1, 'once a day')

    def test_a_redirect_is_not_followed_with_the_key(self):
        t = self.tree()
        self.zulip.replies = [(302, {'result': 'error'})]
        options, _, _ = self.mod.build_options(self.mod.read_site_settings(t.root),
                                               self.mod.read_global_config(t.root))
        with self.assertRaises(self.mod.DeliveryError) as caught:
            self.mod.zulip_post(options['zulip'], 't', 'c')
        self.assertTrue(caught.exception.permanent)

    def test_plain_http_is_refused_except_to_this_host(self):
        t = Tree(self)
        site = {'zulip_url': 'http://chat.example.com', 'zulip_email': 'b@example.com',
                'zulip_api_key_file': t.path('none'), 'zulip_stream': 'wazuh'}
        options, _, _ = self.mod.build_options(site, self.mod.read_global_config(t.root))
        self.assertTrue(any('https' in f for f in options['zulip_fatal']))
        site['zulip_url'] = 'http://127.0.0.1:8080'
        options, _, _ = self.mod.build_options(site, self.mod.read_global_config(t.root))
        self.assertFalse(any('https' in f for f in options['zulip_fatal']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
