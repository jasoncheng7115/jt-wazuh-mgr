"""jt-nextcloud 1.2.3: jt-nextcloud-names.py, the account names for the alert digest.

The script runs daily as root with an administrator's app password, so what
is checked here is mostly what must not happen: the password in a log, an
event or an error; a half-written or emptied names file; a redirect that
carries the login elsewhere; a settings or password file someone else could
change. A stand-in OCS server on 127.0.0.1 answers as Nextcloud does.
"""

import base64
import http.server
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

sys.dont_write_bytecode = True      # no __pycache__ inside the shipped pack

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'packs', 'jt-nextcloud', 'scripts', 'jt-nextcloud-names.py')
DIGEST = os.path.join(ROOT, 'packs', 'jt-alert-digest', 'scripts', 'jt-alert-digest.py')
PASSWORD = 'Abcde-Fghij-Klmno-Pqrst-Uvwxy'
T0 = time.mktime((2026, 10, 31, 4, 0, 0, 0, 0, -1))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeNextcloud(object):
    """The two OCS endpoints the script uses, with v1's answers."""

    def __init__(self, test, users):
        self.users = users          # id -> (displayname, email); order kept
        self.requests = []
        self.fail = None            # (status, body) for every request
        self.missing = set()        # ids whose detail request answers 404
        hub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body, headers=None):
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def ocs(self, data, code=100, status=200):
                self.reply(status, {'ocs': {'meta': {'status': 'ok' if code == 100 else 'failure',
                                                     'statuscode': code, 'message': ''},
                                            'data': data}})

            def do_GET(self):
                parts = urlsplit(self.path)
                query = {k: v[0] for k, v in parse_qs(parts.query).items()}
                hub.requests.append({'path': parts.path, 'query': query,
                                     'headers': {k.lower(): v for k, v in self.headers.items()}})
                if hub.fail:
                    return self.reply(*hub.fail)
                expected = 'Basic ' + base64.b64encode(('admin:' + PASSWORD).encode()).decode()
                if self.headers.get('Authorization') != expected:
                    return self.ocs([], code=997, status=401)
                if self.headers.get('OCS-APIRequest') != 'true':
                    return self.reply(400, b'CSRF check failed')
                if parts.path == '/ocs/v1.php/cloud/users':
                    ids = list(hub.users)
                    offset, limit = int(query.get('offset', 0)), int(query.get('limit', 50))
                    return self.ocs({'users': ids[offset:offset + limit]})
                prefix = '/ocs/v1.php/cloud/users/'
                if parts.path.startswith(prefix):
                    uid = unquote(parts.path[len(prefix):])
                    if uid not in hub.users or uid in hub.missing:
                        return self.ocs([], code=404, status=200)
                    display, email = hub.users[uid]
                    return self.ocs({'id': uid, 'displayname': display, 'email': email,
                                     'enabled': True})
                return self.reply(404, b'no')

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        test.addCleanup(self.server.server_close)
        test.addCleanup(self.server.shutdown)
        self.base = 'http://127.0.0.1:%d' % self.server.server_address[1]


LDAP = {
    '3094106c-645c-103a-832e-5343dab4befe': ('\u738b\u5c0f\u660e', 'alice@example.com'),
    '5c1d0e2a-1111-103a-832e-5343dab4befe': ('Bob Chen', ''),
    '7e2f3a4b-2222-103a-832e-5343dab4befe': ('', 'carol@example.com'),
    'admin': ('admin', 'admin@example.com'),           # local: its id is its name
    'dave': ('Dave', ''),                              # differs only in case
    '9a8b7c6d-3333-103a-832e-5343dab4befe': ('Eve\nInjected: line\u202e', 'eve@example.com'),
    'odd:id': ('Odd', ''),                             # the map cannot hold a colon in an id
}


class NamesScript(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mod = load(SCRIPT, 'jt_nextcloud_names')

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='jtnc-')
        self.addCleanup(shutil.rmtree, self.root, True)
        for d in ('etc/jt-packs', 'var', 'queue/sockets'):
            os.makedirs(self.path(d))
        self.events = []
        self.addCleanup(setattr, self.mod, 'send', self.mod.send)
        self.mod.send = lambda queue, event: self.events.append(event)
        self.addCleanup(setattr, self.mod, 'PAGE', self.mod.PAGE)
        self.mod.PAGE = 2                     # so that seven users need four pages
        self.addCleanup(setattr, self.mod, 'NOW', None)
        self.mod.NOW = T0
        self.cloud = FakeNextcloud(self, dict(LDAP))

    def path(self, rel):
        return os.path.join(self.root, rel)

    def configure(self, url=None, extra='', password=PASSWORD, mode=0o600):
        pw = self.path('etc/jt-packs/jt-nextcloud-app-password')
        with open(pw, 'w') as fh:
            fh.write(password + '\n')
        os.chmod(pw, mode)
        with open(self.path('etc/jt-packs/jt-nextcloud.conf'), 'w') as fh:
            fh.write('url = %s\nuser = admin\napp_password_file = %s\n%s'
                     % (url or self.cloud.base, pw, extra))
        return pw

    def run_script(self, *args):
        out = io.StringIO()
        stdout, sys.stdout = sys.stdout, out
        try:
            code = self.mod.main(['--wazuh-path', self.root] + list(args))
        finally:
            sys.stdout = stdout
        self.output = getattr(self, 'output', '') + out.getvalue()
        return code

    @property
    def names_path(self):
        return self.path('etc/jt-packs/jt-alert-digest-names.d/nextcloud')

    def state(self):
        with open(self.path('var/jt-nextcloud-names.state'), encoding='utf-8') as fh:
            return json.load(fh)

    def names(self):
        with open(self.names_path, encoding='utf-8') as fh:
            return [l.rstrip('\n') for l in fh if not l.startswith('#')]


class TestWrite(NamesScript):

    def test_writes_the_names_of_accounts_whose_id_is_not_their_name(self):
        self.configure()
        self.assertEqual(self.run_script(), 0)
        self.assertEqual(self.names(), [
            '3094106c-645c-103a-832e-5343dab4befe: \u738b\u5c0f\u660e (alice@example.com)',
            '5c1d0e2a-1111-103a-832e-5343dab4befe: Bob Chen',
            '7e2f3a4b-2222-103a-832e-5343dab4befe: carol@example.com',
            '9a8b7c6d-3333-103a-832e-5343dab4befe: Eve Injected: line (eve@example.com)',
        ])
        self.assertEqual(self.events, [])
        # the request shape: every page in turn, OCS header, JSON
        lists = [r for r in self.cloud.requests if r['path'] == '/ocs/v1.php/cloud/users']
        self.assertEqual([(r['query']['offset'], r['query']['limit']) for r in lists],
                         [('0', '2'), ('2', '2'), ('4', '2'), ('6', '2')])
        for r in self.cloud.requests:
            self.assertEqual(r['headers']['ocs-apirequest'], 'true')
            self.assertEqual(r['query']['format'], 'json')
        self.assertIn('/ocs/v1.php/cloud/users/odd%3Aid', [r['path'] for r in self.cloud.requests],
                      'an id is quoted into the path')
        # root only, written whole: no temporary file left beside it
        self.assertEqual(os.stat(self.names_path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(self.names_path)).st_mode & 0o777, 0o700)
        self.assertEqual(os.listdir(os.path.dirname(self.names_path)), ['nextcloud'])
        state = self.state()
        self.assertEqual((state['last_success'], state['entries'], state['users']), (T0, 4, 7))

    def test_the_digest_reads_what_the_script_writes(self):
        self.configure()
        self.run_script()
        digest = load(DIGEST, 'jt_alert_digest_for_names')
        problems = digest.load_names({}, self.root)
        self.assertEqual(problems, [])
        self.assertEqual(digest.NAMES['3094106c-645c-103a-832e-5343dab4befe'],
                         '\u738b\u5c0f\u660e (alice@example.com)')
        self.assertEqual(digest.name_value('3094106c-645c-103a-832e-5343dab4befe'),
                         '\u738b\u5c0f\u660e (alice@example.com) (3094106c\u2026)')
        self.assertEqual(len(digest.NAMES), 4)

    def test_not_configured_does_nothing(self):
        self.assertEqual(self.run_script(), 0)
        self.assertEqual(self.cloud.requests, [])
        self.assertEqual(self.events, [])
        self.assertFalse(os.path.exists(self.names_path))
        self.assertEqual(self.run_script('--once'), 0)
        self.assertIn('not configured', self.output)

    def test_check_and_dry_run_write_nothing(self):
        self.configure()
        self.assertEqual(self.run_script('--check'), 0)
        self.assertIn('result: Nextcloud accepted the login and lists users', self.output)
        self.assertEqual(self.run_script('--dry-run'), 0)
        self.assertIn('7 users in Nextcloud, 4 whose id differs from their name', self.output)
        self.assertFalse(os.path.exists(self.names_path))
        self.assertFalse(os.path.exists(self.path('var/jt-nextcloud-names.state')))
        self.assertEqual(self.events, [])


class TestFailure(NamesScript):

    def test_a_failed_run_keeps_the_file_and_reports_then_reports_staleness(self):
        self.configure()
        self.run_script()
        before = self.names()
        self.cloud.fail = (503, b'maintenance')
        self.mod.NOW = T0 + 86400
        self.assertEqual(self.run_script(), 1)
        self.assertEqual(self.names(), before)
        self.assertEqual([e['event'] for e in self.events], ['failed'])
        self.assertIn('HTTP 503', self.events[0]['detail'])
        self.assertEqual(self.events[0]['age_days'], 1)
        self.mod.NOW = T0 + 3 * 86400 + 60
        self.run_script()
        self.assertEqual(self.events[-1]['event'], 'stale')
        self.assertEqual(self.events[-1]['age_days'], 3)
        self.cloud.fail = None
        self.assertEqual(self.run_script(), 0)
        self.assertIn('working again', self.output)
        self.assertNotIn('first_failure', self.state())

    def test_a_much_shorter_answer_keeps_the_previous_file(self):
        self.configure()
        os.makedirs(os.path.dirname(self.names_path), 0o700)
        with open(self.names_path, 'w') as fh:
            fh.write(''.join('%08d-0000-0000-0000-000000000000: Person %d\n' % (i, i) for i in range(40)))
        self.assertEqual(self.run_script(), 1)
        self.assertEqual(len(self.names()), 40)
        self.assertIn('returned 4 names where the file has 40', self.events[0]['detail'])
        self.assertEqual(self.run_script('--force'), 0)
        self.assertEqual(len(self.names()), 4)

    def test_users_gone_while_reading_are_skipped(self):
        self.configure()
        self.cloud.missing = {'5c1d0e2a-1111-103a-832e-5343dab4befe'}
        self.assertEqual(self.run_script(), 0)
        self.assertEqual(len(self.names()), 3)
        self.assertIn('1 gone while reading', self.output)

    def test_refused_login_and_non_admin(self):
        self.configure(password='Wrong-Wrong-Wrong-Wrong-Wrong')
        self.assertEqual(self.run_script(), 1)
        self.assertIn('the login or app password was refused', self.events[-1]['detail'])
        self.cloud.fail = (200, {'ocs': {'meta': {'statuscode': 403, 'message': 'x'}, 'data': []}})
        self.configure()
        self.run_script()
        self.assertIn('must be an administrator', self.events[-1]['detail'])
        self.assertFalse(os.path.exists(self.names_path))

    def test_a_redirect_is_not_followed(self):
        self.configure()
        self.cloud.fail = (302, b'moved')
        self.assertEqual(self.run_script(), 1)
        self.assertEqual(len(self.cloud.requests), 1)
        self.assertIn('HTTP 302', self.events[0]['detail'])


class TestSecrets(NamesScript):

    def test_the_app_password_appears_nowhere(self):
        self.configure()
        # a server that quotes the login back, as a misbehaving proxy might
        token = base64.b64encode(('admin:' + PASSWORD).encode()).decode()
        self.cloud.fail = (500, ('bad %s / Basic %s' % (PASSWORD, token)).encode())
        for args in ((), ('--once',), ('--check',), ('--dry-run',)):
            self.run_script(*args)
        texts = (self.output, json.dumps(self.events), json.dumps(self.state()))
        for text in texts:
            self.assertNotIn(PASSWORD, text)
            self.assertNotIn(token, text)
        self.assertTrue(self.events)

    def test_password_and_settings_files_must_be_safe(self):
        cases = [
            ('password readable by others', lambda pw: os.chmod(pw, 0o644), 'chmod 600'),
            ('password through a link', lambda pw: (os.rename(pw, pw + '.real'), os.symlink(pw + '.real', pw)),
             'symbolic link'),
            ('password not root', lambda pw: os.chown(pw, 65534, 65534), 'must belong to root'),
            ('settings writable by others',
             lambda pw: os.chmod(self.path('etc/jt-packs/jt-nextcloud.conf'), 0o666), 'chmod 644 or 600'),
        ]
        for label, spoil, words in cases:
            with self.subTest(case=label):
                self.events, self.cloud.requests = [], []
                spoil(self.configure())
                self.assertEqual(self.run_script(), 1)
                self.assertIn(words, self.events[0]['detail'])
                self.assertEqual(self.cloud.requests, [], 'nothing was sent with that password')
                for p in (self.path('etc/jt-packs/jt-nextcloud-app-password.real'),
                          self.path('etc/jt-packs/jt-nextcloud-app-password')):
                    if os.path.lexists(p):
                        os.unlink(p)
                os.chmod(self.path('etc/jt-packs/jt-nextcloud.conf'), 0o600)

    def test_plain_http_is_refused_except_to_this_host(self):
        self.configure(url='http://cloud.example.com')
        self.assertEqual(self.run_script(), 1)
        self.assertIn('url must be the https:// address', self.events[0]['detail'])
        self.configure(url='https://user:pw@cloud.example.com')
        self.run_script()
        self.assertIn('url must be the https:// address', self.events[-1]['detail'])


class TestEntries(NamesScript):

    def test_entry_rules(self):
        entry = self.mod.entry
        self.assertIsNone(entry('admin', 'admin', 'admin@example.com'))
        self.assertIsNone(entry('Dave', 'dave', ''))
        self.assertIsNone(entry('x', '', ''))
        self.assertIsNone(entry('a:b', 'Name', ''))
        self.assertIsNone(entry('#x', 'Name', ''))
        self.assertEqual(entry('u1', 'Name', 'NAME'), 'u1: Name')
        self.assertEqual(entry('u1', '', 'a@example.com'), 'u1: a@example.com')
        self.assertEqual(entry('u1', 'A\r\nB\u200b', ''), 'u1: A B')
        self.assertLessEqual(len(entry('u1', 'x' * 400, '')), len('u1: ') + self.mod.NAME_MAX)


if __name__ == '__main__':
    unittest.main(verbosity=2)
