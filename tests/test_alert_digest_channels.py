"""jt-alert-digest 1.13: Teams, Telegram, Slack, Discord, Mattermost, webhook, LINE.

Every channel posts to one stand-in server on 127.0.0.1 that this file starts
and stops; it answers each platform the way the real one does (202 for a
Teams workflow, "ok" for Slack, {"ok": true} for Telegram, ...) unless a test
queues other answers. What is checked for every channel: the request has the
platform's shape, alert text cannot mention anyone or disguise a link, a
channel that fails never touches mail or the other channels, credentials
appear nowhere, and a message too big for one post is split without losing
or cutting a group.
"""

import hashlib
import hmac
import http.server
import io
import json
import os
import sys
import threading
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_alert_digest import DigestCase, T0, Tree, alert  # noqa: E402

TG_TOKEN = '123456789:AAHfakeTelegramTokenABCDEFGHIJKLMNOPQ'
LINE_TOKEN = 'LINEfakeChannelAccessTokenAbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/='
LINE_TO = 'C' + '0123456789abcdef' * 2
HMAC_KEY = 'hmac-key-0123456789abcdef'
BEARER = 'bearer-token-0123456789'
ALL = ('teams', 'telegram', 'slack', 'discord', 'mattermost', 'webhook', 'line')
EVIL = ('Hi @everyone @here <!channel> <@U123> [click](http://evil.example/x) '
        '<a href="http://evil.example">x</a> **bold** `code` /start')


class FakeHub(object):
    """One server answering for every platform, by path."""

    def __init__(self, test):
        self.requests = []
        self.replies = {}       # path prefix -> [(status, body)]
        hub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body):
                raw = body if isinstance(body, bytes) else (
                    body.encode() if isinstance(body, str) else json.dumps(body).encode())
                self.send_response(status)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def handle_any(self, method):
                length = int(self.headers.get('Content-Length') or 0)
                raw = self.rfile.read(length) if length else b''
                try:
                    data = json.loads(raw.decode()) if raw else None
                except ValueError:
                    data = None
                hub.requests.append({'method': method, 'path': self.path,
                                     'headers': {k.lower(): v for k, v in self.headers.items()},
                                     'raw': raw, 'json': data})
                for prefix, queue in hub.replies.items():
                    if self.path.startswith(prefix) and queue:
                        return self.reply(*queue.pop(0))
                path = self.path
                if path.startswith('/teams'):
                    return self.reply(202, b'')
                if path.startswith('/bot'):
                    if not path.startswith('/bot%s/' % TG_TOKEN):
                        return self.reply(401, {'ok': False, 'error_code': 401,
                                                'description': 'Unauthorized'})
                    method_name = path.rsplit('/', 1)[1]
                    result = {'getMe': {'username': 'jtbot'},
                              'getChat': {'title': 'SOC', 'type': 'supergroup'}}.get(method_name,
                                                                                    {'message_id': 1})
                    return self.reply(200, {'ok': True, 'result': result})
                if path.startswith('/slack'):
                    if data == {}:
                        return self.reply(400, 'no_text')
                    return self.reply(200, 'ok')
                if path.startswith('/discord'):
                    if method == 'GET':
                        return self.reply(200, {'name': 'alerts', 'channel_id': '99'})
                    return self.reply(200, {'id': '1'})
                if path.startswith('/mm'):
                    return self.reply(200, 'ok')
                if path.startswith('/hook'):
                    return self.reply(200, b'')
                if path.startswith('/v2/bot'):
                    if self.headers.get('Authorization') != 'Bearer ' + LINE_TOKEN:
                        return self.reply(401, {'message': 'Authentication failed'})
                    if path == '/v2/bot/info':
                        return self.reply(200, {'displayName': 'Wazuh bot'})
                    if path.startswith('/v2/bot/group/'):
                        return self.reply(200, {'groupName': 'SOC'})
                    return self.reply(200, {})
                return self.reply(404, b'no')

            def do_GET(self):
                self.handle_any('GET')

            def do_POST(self):
                self.handle_any('POST')

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        test.addCleanup(self.server.server_close)
        test.addCleanup(self.server.shutdown)
        self.base = 'http://127.0.0.1:%d' % self.server.server_address[1]

    def posts(self, prefix):
        return [r for r in self.requests if r['method'] == 'POST' and r['path'].startswith(prefix)
                and r['json'] != {}]


PREFIX = {'teams': '/teams', 'telegram': '/bot%s/sendMessage' % TG_TOKEN, 'slack': '/slack', 'discord': '/discord',
          'mattermost': '/mm', 'webhook': '/hook', 'line': '/v2/bot/message/push'}


class ChannelCase(DigestCase):

    def setUp(self):
        DigestCase.setUp(self)
        self.hub = FakeHub(self)

    def secret(self, tree, name, value, mode=0o600):
        path = tree.path('etc/jt-packs/%s' % name)
        with open(path, 'w') as fh:
            fh.write(value + '\n')
        os.chmod(path, mode)
        return path

    def settings(self, tree, names=ALL, extra=''):
        base = self.hub.base
        lines = ['repeat = 0', 'daily = off']
        for name in names:
            if name in ('teams', 'slack', 'discord', 'mattermost'):
                path = {'teams': '/teams/workflows/abc?api-version=1&sig=SIGSECRET123',
                        'slack': '/slack/services/T0/B0/SLACKSECRET123',
                        'discord': '/discord/api/webhooks/1/DISCORDSECRET123',
                        'mattermost': '/mm/hooks/MMSECRET12345'}[name]
                lines.append('%s_url_file = %s' % (name, self.secret(tree, name + '.url', base + path)))
            elif name == 'telegram':
                lines += ['telegram_token_file = %s' % self.secret(tree, 'tg.token', TG_TOKEN),
                          'telegram_chat_id = -1001234567890', 'telegram_api = ' + base]
            elif name == 'webhook':
                lines += ['webhook_url = %s/hook/in' % base,
                          'webhook_hmac_key_file = %s' % self.secret(tree, 'hook.key', HMAC_KEY),
                          'webhook_bearer_file = %s' % self.secret(tree, 'hook.bearer', BEARER)]
            elif name == 'line':
                lines += ['line_token_file = %s' % self.secret(tree, 'line.token', LINE_TOKEN),
                          'line_to = ' + LINE_TO, 'line_api = ' + base]
        tree.conf('\n'.join(lines) + '\n' + extra)

    def tree(self, names=ALL, extra=''):
        t = Tree(self)
        self.settings(t, names, extra)
        self.run_digest(t)              # first run: every channel starts at the end
        return t

    def events_of(self, name):
        return [e['event'] for e in self.events if e.get('channel') == name]

    def options(self, tree):
        return self.mod.build_options(self.mod.read_site_settings(tree.root),
                                      self.mod.read_global_config(tree.root))[0]

    def text_of(self, name, request):
        """Everything a reader of that channel sees, as one string."""
        data = request['json']
        if name == 'telegram':
            return data['text']
        if name == 'mattermost':
            return data['text']
        if name == 'line':
            return '\n'.join(m['text'] for m in data['messages'])
        if name == 'slack':
            # what Slack parses as mrkdwn: the fallback text and every mrkdwn object
            # (a header is plain_text, shown exactly as written)
            found = [data['text']]

            def walk(node):
                if isinstance(node, dict):
                    if node.get('type') == 'mrkdwn':
                        found.append(node['text'])
                    for value in node.values():
                        walk(value)
                elif isinstance(node, list):
                    for value in node:
                        walk(value)
            walk(data['blocks'])
            return '\n'.join(found)
        return json.dumps(data, ensure_ascii=False)


class TestShapes(ChannelCase):

    def test_every_channel_posts_its_platforms_shape(self):
        t = self.tree()
        t.write(alert(1, level=12), alert(2, rule='100002', level=14, agent='web1'))
        self.assertEqual(self.run_digest(t), 0)
        self.assertEqual(len(self.sent), 1, 'mail goes out as well')

        teams = self.hub.posts('/teams')[0]['json']
        card = teams['attachments'][0]
        self.assertEqual(card['contentType'], 'application/vnd.microsoft.card.adaptive')
        body = card['content']['body']
        self.assertEqual(card['content']['type'], 'AdaptiveCard')
        styles = [e.get('style') for e in body if e.get('type') == 'Container']
        self.assertEqual(styles, ['attention', 'warning'], 'L14 first, tinted by level')

        tg = self.hub.posts(PREFIX['telegram'])[0]
        self.assertTrue(tg['path'].endswith('/sendMessage'))
        self.assertEqual(tg['json']['chat_id'], -1001234567890)
        self.assertEqual(tg['json']['parse_mode'], 'HTML')
        self.assertIn('<b>L14 \u00b7 Thing on item 2</b>', tg['json']['text'])
        self.assertIn('<blockquote expandable>line 1</blockquote>', tg['json']['text'])

        slack = self.hub.posts('/slack')[0]['json']
        self.assertIn('2 alerts', slack['text'])
        headers = [b['text']['text'] for b in slack['blocks'] if b['type'] == 'header']
        self.assertEqual(len(headers), 2)
        self.assertTrue(headers[0].startswith('\U0001F534 L14'))

        discord = self.hub.posts('/discord')[0]
        self.assertTrue(discord['path'].endswith('?wait=true'))
        self.assertEqual(discord['json']['allowed_mentions'], {'parse': []})
        self.assertEqual([e['color'] for e in discord['json']['embeds'] if 'color' in e], [0x991B1B, 0xC2410C])
        self.assertIn('**2 alerts \u00b7 2 rules', discord['json']['content'])

        mm = self.hub.posts('/mm')[0]['json']
        self.assertIn('**L14 \u00b7 Thing on item 2**', mm['text'])
        self.assertIn('> line 2', mm['text'])

        hook = self.hub.posts('/hook')[0]
        doc = hook['json']
        self.assertEqual((doc['schema'], doc['kind'], doc['total']), ('jt-alert-digest/1', 'digest', 2))
        self.assertEqual([g['rule_id'] for g in doc['groups']], ['100002', '100001'])
        self.assertEqual(doc['groups'][0]['agent']['name'], 'web1')

        line = self.hub.posts('/v2/bot/message/push')
        self.assertEqual(len(line), 1, 'one request a run: LINE counts messages per request')
        self.assertEqual(line[0]['json']['to'], LINE_TO)
        self.assertTrue(line[0]['headers'].get('x-line-retry-key'))
        self.assertIn('L14 \u00b7 Thing on item 2', self.text_of('line', line[0]))

        self.run_digest(t)
        for name in ALL:
            self.assertEqual(len(self.hub.posts(PREFIX[name])), 1, '%s: nothing new, nothing posted' % name)

    def test_webhook_signature_bearer_and_delivery_id(self):
        t = self.tree(['webhook'])
        t.write(alert(1))
        self.run_digest(t)
        request = self.hub.posts('/hook')[0]
        headers = request['headers']
        expected = hmac.new(HMAC_KEY.encode(), headers['x-jt-timestamp'].encode() + b'.' + request['raw'],
                            hashlib.sha256).hexdigest()
        self.assertEqual(headers['x-jt-signature'], 'sha256=' + expected)
        self.assertEqual(headers['authorization'], 'Bearer ' + BEARER)
        self.assertEqual(headers['x-jt-event'], 'digest')
        self.assertRegex(headers['x-jt-delivery'], r'^[0-9a-f-]{36}$')
        sample = request['json']['groups'][0]['samples'][0]
        self.assertIn({'label': 'Log', 'value': 'line 1'}, sample)

    def test_a_retry_carries_the_same_delivery_id_and_line_retry_key(self):
        t = self.tree(['webhook', 'line'])
        t.write(alert(1))
        self.hub.replies = {'/hook': [(503, b'busy')], '/v2/bot/message/push': [(500, {'message': 'x'})]}
        self.run_digest(t)
        self.mod.NOW = T0 + 120
        self.run_digest(t)
        hooks = self.hub.posts('/hook')
        self.assertEqual(len(hooks), 2)
        self.assertEqual(hooks[0]['headers']['x-jt-delivery'], hooks[1]['headers']['x-jt-delivery'])
        self.assertEqual(hooks[0]['raw'], hooks[1]['raw'], 'the same document, resent')
        pushes = self.hub.posts('/v2/bot/message/push')
        self.assertEqual(pushes[0]['headers']['x-line-retry-key'], pushes[1]['headers']['x-line-retry-key'])
        self.assertEqual(self.events_of('line'), ['delivery_failed', 'recovered'])

    def test_line_409_for_a_retry_key_is_success(self):
        t = self.tree(['line'])
        t.write(alert(1))
        self.hub.replies = {'/v2/bot/message/push': [(409, {'message': 'The retry key is already accepted'})]}
        self.assertEqual(self.run_digest(t), 0)
        self.assertEqual(self.events_of('line'), [])
        self.assertNotIn('outbox', t.state()['line'])


class TestInjection(ChannelCase):

    def test_alert_text_cannot_mention_or_disguise_a_link(self):
        t = self.tree()
        t.write(alert(1, desc=EVIL, agent='@channel'))
        self.run_digest(t)
        for name in ALL:
            request = self.hub.posts(PREFIX[name])[0]
            seen = self.text_of(name, request)
            if name == 'webhook':
                # raw data by design, for a program; documented as untrusted
                self.assertEqual(request['json']['groups'][0]['title'], EVIL)
                continue
            if name == 'line':
                continue        # plain text: LINE interprets nothing and cannot mention
            # what each platform would act on: a mention, a disguised link, live markup
            for word in ('@everyone', '@here', '@channel'):
                self.assertNotIn(word, seen, '%s: %s' % (name, word))
            if name not in ('telegram', 'slack'):   # neither has [text](url) links
                self.assertNotIn('[click](http', seen, name)
            if name == 'slack':
                for construct in ('<!channel>', '<@U123>', '<http'):
                    self.assertNotIn(construct, seen)
            if name == 'discord':
                self.assertNotIn('<@U123>', seen)
            if name == 'telegram':
                self.assertNotIn('<a href="http://evil', seen)
                self.assertIn('&lt;a href=', seen)
        self.assertEqual(self.hub.posts('/discord')[0]['json']['allowed_mentions'], {'parse': []})
        self.assertNotIn('/start', self.hub.posts(PREFIX['telegram'])[0]['json']['text'], 'a tappable bot command')

    def test_escapers(self):
        mod = self.mod
        self.assertEqual(mod.tg('a <b> & @bob /cmd'), 'a &lt;b&gt; &amp; @\u200bbob /\u200bcmd')
        self.assertEqual(mod.sl('<!here> a*b `c` ~d~ &'), '&lt;!here&gt; a\u2217b \u02cbc\u02cb \u223cd\u223c &amp;')
        self.assertEqual(mod.dc('**x** [a](b) <@1> @everyone'),
                         '\\*\\*x\\*\\* \\[a\\]\\(b\\) \\<@\u200b1\\> @\u200beveryone')
        self.assertNotIn('](', mod.ms('[a](http://x)'))
        self.assertNotIn('{{', mod.ms('{{DATE(2026-01-01T00:00:00Z)}}'))
        self.assertEqual(mod.mm('@all'), '@\u200ball')


class TestIndependence(ChannelCase):

    def test_one_channel_down_touches_neither_mail_nor_the_others(self):
        t = self.tree()
        t.write(alert(1))
        self.hub.replies = {'/slack': [(503, 'service_unavailable')] * 2}
        self.assertEqual(self.run_digest(t), 1)
        self.assertEqual(len(self.sent), 1)
        for name in ALL:
            if name != 'slack':
                self.assertEqual(len(self.hub.posts(PREFIX[name])), 1, name)
        self.assertEqual(self.events_of('slack'), ['delivery_failed'])
        self.assertEqual([e['error_class'] for e in self.events if e.get('channel') == 'slack'], ['http-503-service_unavailable'])
        self.mod.NOW = T0 + 120
        self.run_digest(t)
        self.assertEqual(self.events_of('slack'), ['delivery_failed'], 'not reported every run')
        self.mod.NOW = T0 + 240
        self.run_digest(t)
        self.assertEqual(self.events_of('slack'), ['delivery_failed', 'recovered'])
        self.assertEqual(len(self.hub.posts('/slack')), 3)
        for name in ALL:
            if name != 'slack':
                self.assertEqual(len(self.hub.posts(PREFIX[name])), 1, '%s posted once only' % name)
        self.assertEqual(len(self.sent), 1)

    def test_a_crash_in_one_channel_is_reported_for_that_channel(self):
        t = self.tree(['discord', 'mattermost'])
        t.write(alert(1))
        original = self.mod.DiscordChannel.group
        self.mod.DiscordChannel.group = lambda self, v: 1 / 0
        try:
            self.assertEqual(self.run_digest(t), 3)
        finally:
            self.mod.DiscordChannel.group = original
        self.assertEqual(self.events_of('discord'), ['crashed'])
        self.assertEqual(len(self.hub.posts('/mm')), 1)
        self.assertEqual(len(self.sent), 1)
        self.run_digest(t)
        self.assertEqual(len(self.hub.posts('/discord')), 1, 'posted after the fix, nothing lost')

    def test_refused_credentials_are_a_configuration_failure(self):
        t = self.tree(['telegram', 'discord'])
        t.write(alert(1))
        self.hub.replies = {'/bot': [(401, {'ok': False, 'error_code': 401, 'description': 'Unauthorized'})] * 9,
                            '/discord': [(404, {'message': 'Unknown Webhook', 'code': 10015})] * 9}
        for minute in (0, 2, 4):
            self.mod.NOW = T0 + minute * 60
            self.run_digest(t)
        self.assertEqual(self.events_of('telegram'), ['config_error'])
        self.assertEqual(self.events_of('discord'), ['config_error'])
        kinds = {e['channel']: e['error_class'] for e in self.events if e.get('channel')}
        self.assertEqual(kinds, {'telegram': 'http-401', 'discord': 'http-404-10015'})

    def test_a_malformed_message_is_dropped_after_three_tries_not_retried_forever(self):
        t = self.tree(['discord'])
        t.write(alert(1))
        bad = (400, {'message': 'Invalid Form Body', 'code': 50035})
        self.hub.replies = {'/discord': [bad] * 3}
        for minute in (0, 2, 4):
            self.mod.NOW = T0 + minute * 60
            self.run_digest(t)
        self.assertIn('skipped', self.events_of('discord'))
        reason = [e['reason'] for e in self.events if e.get('channel') == 'discord' and e['event'] == 'skipped'][0]
        self.assertIn('malformed', reason)
        self.assertNotIn('outbox', t.state()['discord'])
        t.write(alert(2, rule='100002'))
        self.mod.NOW = T0 + 360
        self.run_digest(t)
        self.assertEqual(len(self.hub.posts('/discord')), 4, 'the channel carries on')

    def test_telegram_falls_back_to_plain_text_when_markup_is_refused(self):
        t = self.tree(['telegram'])
        t.write(alert(1))
        self.hub.replies = {'/bot': [(400, {'ok': False, 'error_code': 400,
                                            'description': "Bad Request: can't parse entities: x"})]}
        self.assertEqual(self.run_digest(t), 0)
        posts = self.hub.posts(PREFIX['telegram'])
        self.assertEqual(len(posts), 2)
        self.assertNotIn('parse_mode', posts[1]['json'])
        self.assertNotIn('<b>', posts[1]['json']['text'])
        self.assertIn('L12 \u00b7 Thing on item 1', posts[1]['json']['text'])


class TestSecrets(ChannelCase):

    def test_secret_files_must_be_root_only_and_not_links(self):
        t = Tree(self)
        self.settings(t, ['slack', 'telegram'])
        os.chmod(t.path('etc/jt-packs/slack.url'), 0o644)
        target = t.path('etc/jt-packs/tg.token')
        os.rename(target, target + '.real')
        os.symlink(target + '.real', target)
        options = self.options(t)
        fatal = {c.name: c.fatal for c in options['channels']}
        self.assertTrue(any('chmod 600' in p for p in fatal['slack']))
        self.assertTrue(any('symbolic link' in p for p in fatal['telegram']))
        self.run_digest(t)
        t.write(alert(1))
        self.run_digest(t)
        self.assertEqual(self.hub.posts('/slack') + self.hub.posts(PREFIX['telegram']), [])
        self.assertEqual(sorted(e['channel'] for e in self.events if e['event'] == 'config_error'),
                         ['slack', 'telegram'])
        self.assertEqual(len(self.sent), 1, 'mail is unaffected')

    def test_credentials_appear_nowhere(self):
        t = self.tree()
        t.write(alert(1))
        # each server quotes its own credential back, as a misbehaving proxy might
        self.hub.replies = {
            '/slack': [(500, 'bad SLACKSECRET123')],
            '/discord': [(500, {'message': 'bad /discord/api/webhooks/1/DISCORDSECRET123'})],
            '/teams': [(500, {'error': {'code': 'X', 'message': 'bad sig=SIGSECRET123'}})],
            '/bot': [(500, {'ok': False, 'description': 'bad ' + TG_TOKEN})],
            '/v2/bot/message/push': [(500, {'message': 'bad Bearer ' + LINE_TOKEN})],
            '/mm': [(500, {'message': 'bad MMSECRET12345'})],
            '/hook': [(500, 'bad %s %s' % (BEARER, HMAC_KEY))]}
        self.run_digest(t)
        out = io.StringIO()
        stdout, sys.stdout = sys.stdout, out
        try:
            self.run_digest(t, '--check')
            self.run_digest(t, '--dry-run')
        finally:
            sys.stdout = stdout
        with open(t.path('var/jt-alert-digest.state')) as fh:
            state = fh.read()
        texts = (state, json.dumps(self.events, ensure_ascii=False), '\n'.join(self.logs), out.getvalue())
        for secret in (TG_TOKEN, LINE_TOKEN, HMAC_KEY, BEARER, 'SLACKSECRET123', 'DISCORDSECRET123',
                       'SIGSECRET123', 'MMSECRET12345'):
            for text in texts:
                self.assertNotIn(secret, text)
        self.assertEqual(len([e for e in self.events if e['event'] == 'delivery_failed']), 7)

    def test_plain_http_is_refused_except_to_this_host(self):
        t = Tree(self)
        self.settings(t, ['webhook', 'telegram'])
        site = self.mod.read_site_settings(t.root)
        site['webhook_url'] = 'http://soar.example.com/in'
        site['telegram_api'] = 'http://api.telegram.org'
        options = self.mod.build_options(site, self.mod.read_global_config(t.root))[0]
        for ch in options['channels']:
            self.assertTrue(any('https' in p for p in ch.fatal), ch.name)


class TestLayout(ChannelCase):

    def many(self, t, groups=40):
        lines = []
        for g in range(groups):
            for n in range(3):
                a = json.loads(alert(g * 3 + n, rule=str(120000 + g), agent='h%d' % g))
                a['full_log'] = 'z' * 190 + ' %d' % n
                a['data'] = {'srcip': '203.0.113.%d' % g, 'dstuser': 'user%d' % g}
                lines.append(json.dumps(a))
        t.write(*lines)

    def test_long_digests_are_split_within_each_platforms_limits(self):
        t = self.tree()
        self.many(t)
        self.run_digest(t)
        for name in ALL:
            if name == 'webhook':
                continue
            posts = self.hub.posts(PREFIX[name])
            texts = [self.text_of(name, p) for p in posts]
            for g in range(40):
                found = sum(1 for text in texts if str(120000 + g) in text)
                self.assertEqual(found, 1, '%s: rule %d in %d messages' % (name, 120000 + g, found))
        for p in self.hub.posts(PREFIX['telegram']):
            self.assertLessEqual(len(p['json']['text'].encode('utf-16-le')) // 2, 4096)
            self.assertEqual(p['json']['text'].count('<blockquote'), p['json']['text'].count('</blockquote>'))
        for p in self.hub.posts('/slack'):
            self.assertLessEqual(len(p['json']['blocks']), 50)
            for b in p['json']['blocks']:
                if b['type'] == 'section' and 'text' in b:
                    self.assertLessEqual(len(b['text']['text']), 3000)
        for p in self.hub.posts('/discord'):
            embeds = p['json']['embeds']
            self.assertLessEqual(len(embeds), 10)
            self.assertLessEqual(sum(self.mod.embed_size(e) for e in embeds), 6000)
            for e in embeds:
                for f in e.get('fields', []):
                    self.assertLessEqual(len(f['value']), 1024)
        for p in self.hub.posts('/teams'):
            self.assertLessEqual(len(p['raw']), 28000)
        for p in self.hub.posts('/v2/bot/message/push'):
            self.assertLessEqual(len(p['json']['messages']), 5)
            for m in p['json']['messages']:
                self.assertLessEqual(len(m['text'].encode('utf-16-le')) // 2, 5000)
        self.assertEqual(len(self.hub.posts('/v2/bot/message/push')), 1, 'LINE: one request')
        doc = self.hub.posts('/hook')[0]['json']
        self.assertEqual(len(doc['groups']), 40)

    def test_per_channel_level(self):
        t = self.tree(['telegram', 'slack'], extra='telegram_level = 14\n')
        t.write(alert(1, level=12), alert(2, rule='100002', level=14))
        self.run_digest(t)
        tg = self.hub.posts(PREFIX['telegram'])[0]['json']['text']
        self.assertIn('100002', tg)
        self.assertNotIn('100001', tg)
        slack = json.dumps(self.hub.posts('/slack')[0]['json'])
        self.assertIn('100001', slack)
        self.assertIn('rule 100001', self.body())

    def test_daily_summary_per_channel_and_off_switch(self):
        daily = __import__('time').strftime('%H:%M', __import__('time').localtime(T0 + 600))
        t = Tree(self)
        self.settings(t, ['teams', 'mattermost'], extra='mattermost_daily = off\n')
        with open(t.path('etc/jt-packs/jt-alert-digest.conf')) as fh:
            t.conf(fh.read().replace('\ndaily = off', '\ndaily = ' + daily))
        self.run_digest(t)
        self.mod.NOW = T0 + 900
        self.run_digest(t)
        teams = self.hub.posts('/teams')
        self.assertEqual(len(teams), 1)
        text = json.dumps(teams[0]['json'], ensure_ascii=False)
        self.assertIn('Daily summary \u00b7 node02 (worker)', text)
        self.assertIn('"title": "Mail"', text)
        self.assertIn('"title": "Mattermost"', text)
        self.assertEqual(self.hub.posts('/mm'), [], 'mattermost_daily = off')
        self.assertIn('Microsoft Teams: working', self.body())
        self.run_digest(t)
        self.assertEqual(len(self.hub.posts('/teams')), 1, 'once a day')

    def test_check_and_test(self):
        t = self.tree()
        out = io.StringIO()
        stdout, sys.stdout = sys.stdout, out
        try:
            self.run_digest(t, '--check')      # the mail part fails here: no SMTP server
            for name in ALL:
                self.assertEqual(self.run_digest(t, '--test', name), 0, name)
        finally:
            sys.stdout = stdout
        text = out.getvalue()
        self.assertIn('telegram auth: accepted as @jtbot', text)
        self.assertIn('discord webhook: alerts, channel id 99', text)
        self.assertIn('slack result: the webhook exists', text)
        self.assertIn('line target: SOC', text)
        for name in ALL:
            posts = self.hub.posts(PREFIX[name])
            self.assertEqual(len(posts), 1, name)
            self.assertIn('test', self.text_of(name, posts[0]).lower(), name)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.hub.posts('/hook')[0]['headers']['x-jt-event'], 'test')

    def test_without_settings_nothing_changes(self):
        t = Tree(self)
        self.run_digest(t)
        t.write(alert(1))
        self.run_digest(t)
        self.assertEqual(self.hub.requests, [])
        self.assertEqual(sorted(k for k in t.state() if k in ALL), [])

    def test_a_typo_is_a_warning_and_a_half_configuration_is_reported(self):
        t = Tree(self)
        t.conf('repeat = 0\ndaily = off\ntelegram_chatid = 1\nslack_level = 12\n')
        options, fatal, warnings = self.mod.build_options(self.mod.read_site_settings(t.root),
                                                          self.mod.read_global_config(t.root))
        self.assertTrue(any("'telegram_chatid'" in w for w in warnings))
        slack = [c for c in options['channels'] if c.name == 'slack'][0]
        self.assertTrue(any('slack_url_file is not set' in p for p in slack.fatal))


if __name__ == '__main__':
    unittest.main(verbosity=2)
