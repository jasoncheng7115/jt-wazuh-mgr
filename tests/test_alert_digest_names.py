"""jt-alert-digest 1.14: the account names map.

Nextcloud on an LDAP directory names users by the entry's UUID, and Windows
sometimes names an account only by its SID. The map turns those ids into the
person in every channel, and must do nothing else: groups, holds and the alert
data stay as they were, only exact ids are replaced (never part of a word),
a name from the directory cannot inject markup or a mention, an unsafe file
is refused, and without a map every message is byte for byte what 1.13.1
sent.
"""

import io
import json
import os
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_alert_digest import T0, Tree, alert  # noqa: E402
from test_alert_digest_channels import ALL, PREFIX, ChannelCase  # noqa: E402

U = '3094106c-645c-103a-832e-5343dab4befe'
U2 = 'a1b2c3d4-0000-1111-2222-333344445555'
SID = 'S-1-5-21-1111111111-2222222222-3333333333-1104'
NAME = '\u738b\u5c0f\u660e (alice@example.com)'   # Wang Xiaoming, in Chinese
SHOWN_U = '3094106c\u2026'
SHOWN_SID = '\u2026-1104'


def nextcloud(n, user=U, desc=None, **extra):
    return alert(n, rule='131710', agent='cloud1', agent_id='022',
                 desc=desc or ('Nextcloud: %s logged in from 203.0.113.5' % user),
                 data={'srcip': '203.0.113.5', 'dstuser': user},
                 full_log='jt-nextcloud: {"user":"%s","remoteAddr":"203.0.113.5"}' % user, **extra)


def member_added(n, sid=SID):
    return alert(n, rule='60154', agent='dc1', agent_id='005', desc='Administrators group changed',
                 data={'win': {'system': {'providerName': 'Microsoft-Windows-Security-Auditing',
                                          'eventID': '4732',
                                          'message': '"A member was added to a security-enabled '
                                                     'local group."'},
                               'eventdata': {'memberSid': sid, 'memberName': '-',
                                             'targetUserName': 'Administrators',
                                             'subjectUserName': 'operator'}}})


class NamesCase(ChannelCase):

    def setUp(self):
        ChannelCase.setUp(self)
        self.mod.NAMES.clear()
        self.addCleanup(self.mod.NAMES.clear)

    def names(self, tree, body, rel='etc/jt-packs/jt-alert-digest-names', mode=0o600):
        path = tree.path(rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with io.open(path, 'w', encoding='utf-8') as fh:
            fh.write(body)
        os.chmod(path, mode)
        return path

    def mail_text(self):
        message = self.sent[-1]
        return (message.get_body(('plain',)).get_content(), message.get_body(('html',)).get_content(),
                str(message['Subject']))

    def captured(self, tree, *args):
        out = io.StringIO()
        stdout, sys.stdout = sys.stdout, out
        try:
            code = self.run_digest(tree, *args)
        finally:
            sys.stdout = stdout
        return code, out.getvalue()

    def check(self, tree):
        return self.captured(tree, '--check')[1]

    def add_setting(self, tree, line):
        with io.open(tree.path('etc/jt-packs/jt-alert-digest.conf'), encoding='utf-8') as fh:
            tree.conf(fh.read() + line + '\n')


class TestShownByName(NamesCase):

    def test_a_uuid_and_a_sid_are_shown_by_name_in_every_channel(self):
        t = self.tree()
        self.names(t, '# from the directory\n%s: %s\n%s: Bob Admin\n' % (U, NAME, SID))
        t.write(nextcloud(1), member_added(2))
        self.assertEqual(self.run_digest(t), 0)

        text, html, _ = self.mail_text()
        for body in (text, html):
            self.assertIn('%s (%s)' % (NAME, SHOWN_U), body)        # the Account row
            self.assertIn('Nextcloud: %s (%s) logged in' % (NAME, SHOWN_U), body)   # the title
            self.assertIn('Bob Admin (%s)' % SHOWN_SID, body)       # the Member row (SID only)
        self.assertIn('Account: %s (%s)' % (NAME, SHOWN_U), text)
        self.assertIn('Member: Bob Admin (%s)' % SHOWN_SID, text)
        self.assertIn('"user":"%s"' % U, text, 'the raw log keeps the whole id')

        for name in ALL:
            request = self.hub.posts(PREFIX[name])[0]
            if name == 'webhook':
                doc = request['json']
                groups = {g['rule_id']: g for g in doc['groups']}
                nc = groups['131710']
                self.assertIn(U, nc['title'], 'the webhook keeps the value')
                self.assertEqual(nc['account_names'], {U: NAME})
                row = [r for r in nc['samples'][0] if r['label'] == 'Account'][0]
                self.assertEqual(row, {'label': 'Account', 'value': U, 'account_name': NAME})
                member = [r for r in groups['60154']['samples'][0] if r['label'] == 'Member'][0]
                self.assertEqual(member, {'label': 'Member', 'value': SID, 'account_name': 'Bob Admin'})
                continue
            seen = self.text_of(name, request)
            if name == 'teams':
                seen = json.dumps(request['json'], ensure_ascii=False)
            with self.subTest(channel=name):
                self.assertIn('\u738b\u5c0f\u660e', seen)
                self.assertIn(SHOWN_U, seen)
                self.assertIn('Bob Admin', seen)
                self.assertIn('1104', seen)
                self.assertNotIn('Account: ' + U, seen.replace('**', '').replace('*', ''))

    def test_zulip_too(self):
        t = Tree(self, conf='repeat = 0\ndaily = off\nzulip_url = %s\nzulip_email = bot@example.com\n'
                            'zulip_api_key_file = %s\nzulip_stream = wazuh\n'
                 % (self.hub.base, '{key}'))
        key = self.secret(t, 'zulip.key', 'abcdefgh12345678')
        with open(t.path('etc/jt-packs/jt-alert-digest.conf')) as fh:
            conf = fh.read().replace('{key}', key)
        t.conf(conf)
        self.names(t, '%s: %s\n%s: Bob Admin\n' % (U, NAME, SID))
        posted = []
        self.addCleanup(setattr, self.mod, 'zulip_post', self.mod.zulip_post)
        self.mod.zulip_post = lambda z, topic, content: posted.append(content)
        self.run_digest(t)
        t.write(nextcloud(1), member_added(2))
        self.run_digest(t)
        body = '\n'.join(posted)
        self.assertIn('%s (%s)' % (NAME, SHOWN_U), body)
        self.assertIn('Bob Admin (%s)' % SHOWN_SID, body)
        self.assertIn(U, body, 'the raw log, collapsed, keeps the id')

    def test_domain_account_and_sysmon_user_shapes(self):
        mod = self.mod
        mod.NAMES.update({SID: 'Bob Admin', 'jdoe': 'John Doe', U: NAME})
        self.assertEqual(mod.name_value('CONTOSO\\' + SID), 'CONTOSO\\Bob Admin (%s)' % SHOWN_SID)
        self.assertEqual(mod.name_value('CONTOSO\\jdoe (High)'), 'CONTOSO\\John Doe (jdoe) (High)')
        self.assertEqual(mod.name_value(U.upper()), '%s (%s)' % (NAME, SHOWN_U), 'UUIDs in any case')
        found = {}
        self.assertEqual(mod.name_tokens('user %s, then %s.' % (U, SID), found),
                         'user %s (%s), then Bob Admin (%s).' % (NAME, SHOWN_U, SHOWN_SID))
        self.assertEqual(found, {U: NAME, SID: 'Bob Admin'})

    def test_grouping_holds_and_state_do_not_change(self):
        def run(with_names):
            self.sent = []
            t = Tree(self, conf='daily = off\n')       # the default 60-minute hold
            if with_names:
                self.names(t, '%s: %s\n%s: Bob Admin\n' % (U, NAME, SID))
            self.run_digest(t)
            t.write(nextcloud(1), nextcloud(2, user=U2), member_added(3))
            self.run_digest(t)
            self.mod.NOW = T0 + 120
            t.write(nextcloud(4), member_added(5))
            self.run_digest(t)
            self.mod.NOW = T0
            state = t.state()
            return (sorted(state['mailed']), sorted(state['held']),
                    [e['heading'] for e in state['held'].values()],
                    sorted(state['seen']['pairs']), [str(m['X-Wazuh-Alerts']) for m in self.sent])
        plain, named = run(False), run(True)
        self.assertEqual(plain, named)
        self.assertTrue(any(U in h for h in named[2]), 'the state keeps the raw description')


class TestExactMatchesOnly(NamesCase):

    def test_a_substring_is_never_replaced(self):
        mod = self.mod
        mod.NAMES.update({U: NAME, SID: 'Bob Admin', 'alice': 'Alice Chen'})
        for text in ('x%s' % U, '%s-2' % U, '%s0' % U, 'id_%s' % U, '%s5' % SID, '%s-7' % SID,
                     'malice', 'alice2', 'S-1-5-21-1111111111-2222222222-3333333333'):
            with self.subTest(text=text):
                self.assertEqual(mod.name_tokens(text), text)
                self.assertEqual(mod.name_value(text), text)
        # a plain account name is only ever matched as the whole value of an account field
        self.assertEqual(mod.name_tokens('alice logged in'), 'alice logged in')
        self.assertEqual(mod.name_value('alice'), 'Alice Chen (alice)')
        # and a value that is not an account is left alone even when it is a key
        rows = mod.account_rows([('File', '/srv/%s/x' % U), ('Log', U)], {})
        self.assertEqual([r[2] for r in rows], ['/srv/%s/x' % U, U])

    def test_in_a_real_digest(self):
        t = Tree(self)
        self.names(t, '%s: %s\nalice: Alice Chen\n' % (U, NAME))
        self.run_digest(t)
        t.write(nextcloud(1, user='malice', desc='Nextcloud: x%s and malice logged in' % U),
                alert(2, rule='100002', desc='Thing on file-%s.txt' % U))
        self.run_digest(t)
        text, html, subject = self.mail_text()
        for body in (text, html, subject):
            self.assertNotIn('\u738b\u5c0f\u660e', body)
            self.assertNotIn('Alice Chen', body)
        self.assertIn('Account: malice', text)
        self.assertIn('x%s and malice' % U, text)


class TestHostileNames(NamesCase):

    # within the 120 characters a name keeps
    HOSTILE = ('<script>x</script> @everyone @here <!channel> <@U123> [click](http://evil.example/x) '
               '<a href="http://evil.example">x</a> **b**\n# h\u202e\u200b')

    def test_a_name_cannot_inject_markup_or_mention(self):
        t = self.tree()
        self.names(t, '%s: %s\n' % (U, self.HOSTILE.replace('\n', ' ')))
        t.write(nextcloud(1))
        self.run_digest(t)
        text, html, subject = self.mail_text()
        self.assertNotIn('<script>', html)
        self.assertNotIn('<a href="http://evil', html)
        self.assertIn('&lt;script&gt;', html)
        for body in (text, html, subject):
            self.assertNotIn('\u202e', body)
        for name in ALL:
            request = self.hub.posts(PREFIX[name])[0]
            seen = self.text_of(name, request)
            if name == 'webhook':
                # raw by design and documented as untrusted, but cleaned of control characters
                self.assertEqual(request['json']['groups'][0]['account_names'][U],
                                 self.mod.clean_name(self.HOSTILE.replace('\n', ' ')))
                self.assertNotIn('\u202e', json.dumps(request['json'], ensure_ascii=False))
                continue
            with self.subTest(channel=name):
                self.assertNotIn('\u202e', seen)
                if name == 'line':
                    continue        # plain text: LINE interprets nothing and cannot mention
                for word in ('@everyone', '@here', '@channel'):
                    self.assertNotIn(word, seen)
                if name not in ('telegram', 'slack'):
                    self.assertNotIn('[click](http', seen)
                if name == 'slack':
                    for construct in ('<!channel>', '<@U123>', '<http'):
                        self.assertNotIn(construct, seen)
                if name == 'telegram':
                    self.assertNotIn('<a href="http://evil', seen)
                    self.assertNotIn('<script>', seen)
                if name == 'mattermost':
                    self.assertNotIn('<', seen)
        self.assertEqual(self.hub.posts('/discord')[0]['json']['allowed_mentions'], {'parse': []})

    def test_names_are_cleaned_of_line_breaks_and_formatting_characters(self):
        clean = self.mod.clean_name
        self.assertEqual(clean('Alice\r\n> quoted\x00\u202eevil\u200b'), 'Alice > quoted evil')
        self.assertLessEqual(len(clean('x' * 500)), self.mod.NAME_MAX)
        names = {}
        entries, ignored = self.mod.parse_names('a: line one\nb:\n: c\nno colon\n\x01k: v\nd: d\n', names)
        self.assertEqual(names, {'a': 'line one'})
        self.assertEqual((entries, ignored), (1, 4), 'd: d maps an id to itself and is dropped silently')


class TestFileSafety(NamesCase):

    def test_an_unsafe_names_file_is_refused(self):
        cases = {
            'group-writable': lambda t, p: os.chmod(p, 0o664),
            'world-writable': lambda t, p: os.chmod(p, 0o646),
            'not root': lambda t, p: os.chown(p, 65534, 65534),
            'symbolic link': lambda t, p: (os.rename(p, p + '.real'), os.symlink(p + '.real', p)),
        }
        for label, spoil in cases.items():
            with self.subTest(case=label):
                self.events, self.sent = [], []
                t = Tree(self, smtp='/bin/true')
                path = self.names(t, '%s: %s\n' % (U, NAME))
                spoil(t, path)
                out = self.check(t)
                self.assertIn('account names: REFUSED names file %s' % path, out)
                self.assertIn('account names: none (no names file could be read)', out)
                self.assertEqual(self.mod.NAMES, {})
                self.run_digest(t)
                t.write(nextcloud(1))
                self.run_digest(t)
                text, _, _ = self.mail_text()
                self.assertNotIn('\u738b\u5c0f\u660e', text)
                self.assertIn('Account: ' + U, text)

    def test_a_directory_others_can_write_is_refused_and_its_files_unread(self):
        t = Tree(self, smtp='/bin/true')
        self.names(t, '%s: %s\n' % (U, NAME), rel='etc/jt-packs/jt-alert-digest-names.d/nextcloud')
        os.chmod(t.path('etc/jt-packs/jt-alert-digest-names.d'), 0o777)
        out = self.check(t)
        self.assertIn('names directory %s must belong to root' % t.path('etc/jt-packs/jt-alert-digest-names.d'), out)
        self.assertEqual(self.mod.NAMES, {})

    def test_a_refused_file_is_listed_in_the_daily_summary(self):
        t = Tree(self, smtp='/bin/true', conf='repeat = 0\ndaily = 08:00\n')
        os.chmod(self.names(t, '%s: %s\n' % (U, NAME)), 0o666)
        self.run_digest(t)
        self.mod.NOW = T0 + 86400
        self.run_digest(t)
        daily = [m for m in self.sent if 'Daily' in str(m['Subject']) or 'daily' in str(m['Subject'])]
        self.assertTrue(daily)
        self.assertIn('writable by root only', daily[-1].get_body(('plain',)).get_content())


class TestReport(NamesCase):

    def test_check_reports_files_entries_and_refusals(self):
        t = Tree(self, smtp='/bin/true')
        main = self.names(t, '%s: %s\nbroken line\n' % (U, NAME))
        d = 'etc/jt-packs/jt-alert-digest-names.d/'
        self.names(t, '%s: Bob Admin\n' % SID, rel=d + 'ad')
        self.names(t, '%s: Later Wins\n' % U.upper(), rel=d + 'nextcloud')
        self.names(t, '%s: Hidden\n' % U2, rel=d + '.nextcloud.tmp')
        self.names(t, '%s: Leftover\n' % U2, rel=d + 'old~')
        bad = self.names(t, 'x: y\n', rel=d + 'zz', mode=0o622)
        out = self.check(t)
        line = [l for l in out.splitlines() if l.startswith('  account names: ')][0]
        self.assertIn('2 entries from %s (1), %s (1), %s (1)'
                      % (main, t.path(d + 'ad'), t.path(d + 'nextcloud')), line)
        self.assertIn('1 lines ignored', line)
        self.assertIn('REFUSED names file %s' % bad, out)
        self.assertEqual(self.mod.NAMES, {U: 'Later Wins', SID: 'Bob Admin'})

    def test_names_file_setting_lists_paths_or_turns_the_map_off(self):
        t = Tree(self, smtp='/bin/true')
        a = self.names(t, '%s: From A\n' % U, rel='srv/a')
        b = self.names(t, '%s: From B\n' % SID, rel='srv/b')
        t.conf('repeat = 0\ndaily = off\nnames_file = %s, %s %s\n' % (a, b, t.path('srv/missing')))
        out = self.check(t)
        self.assertEqual(self.mod.NAMES, {U: 'From A', SID: 'From B'})
        self.assertIn('REFUSED names_file %s cannot be read' % t.path('srv/missing'), out)
        self.assertNotIn('unknown setting', out)
        t.conf('repeat = 0\ndaily = off\nnames_file = off\n')
        self.names(t, '%s: Default\n' % U)
        out = self.check(t)
        self.assertIn('account names: off', out)
        self.assertEqual(self.mod.NAMES, {})

    def test_no_names_file_is_reported_plainly(self):
        out = self.check(Tree(self, smtp='/bin/true'))
        self.assertIn('account names: none (no names file)', out)


class TestWithoutAMap(NamesCase):
    """1.13.1's output, byte for byte: checked once against the 1.13.1 script
    when 1.14 was made; here, no map, an off switch and a map that knows none
    of the ids all give the same messages on every channel."""

    def outputs(self, setup):
        self.sent, self.hub.requests = [], []
        t = self.tree()
        setup(t)
        t.write(nextcloud(1), member_added(2),
                alert(3, rule='100003', data={'srcuser': U, 'dstuser': SID}, desc='Thing for %s' % U))
        self.run_digest(t)
        mail = [(m['Subject'], m.get_body(('plain',)).get_content(), m.get_body(('html',)).get_content())
                for m in self.sent]
        posts = []
        for name in ALL:
            for r in self.hub.posts(PREFIX[name]):
                body = r['json']
                if isinstance(body, dict):
                    body = dict(body)
                    body.pop('sent_at', None)
                posts.append((name, json.dumps(body, ensure_ascii=False, sort_keys=True)))
        return mail, posts

    def test_no_map_off_or_unrelated_keys_change_nothing(self):
        base = self.outputs(lambda t: None)
        self.assertTrue(base[0] and len(base[1]) == len(ALL))
        off = self.outputs(lambda t: self.add_setting(t, 'names_file = off'))
        unrelated = self.outputs(lambda t: self.names(t, '%s: Somebody Else\nbob: Bob\n' % U2))
        self.assertEqual(base, off)
        self.assertEqual(base, unrelated)

    def test_without_a_map_rows_are_passed_through_untouched(self):
        fields = [('Account', U), ('User', SID), ('Log', U)]
        rows = self.mod.account_rows(fields, {'data': {'srcuser': U}})
        self.assertEqual(rows, [(l, v, v, {}) for l, v in fields])
        self.assertEqual(self.mod.name_tokens('a %s b' % U), 'a %s b' % U)


if __name__ == '__main__':
    unittest.main(verbosity=2)
