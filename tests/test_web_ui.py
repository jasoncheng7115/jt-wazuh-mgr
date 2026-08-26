#!/usr/bin/env python3
"""Test suite for the JT Wazuh Manager web UI.

Runs entirely offline: the Wazuh API layer is mocked and the ruleset directories
are faked, so no Wazuh manager is required.

    python3 -m unittest discover -s tests -v
    python3 tests/test_web_ui.py

Flask/requests must be importable. On a host without them, point PYTHONPATH at a
directory holding the wheels from offline_packages/.
"""

import builtins
import io
import os
import re
import subprocess
import sys
import textwrap
import time
import unittest
from contextlib import contextmanager

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import lib.web_ui as web_ui  # noqa: E402


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

BUILTIN_RULES = {
    '0915-win-powershell_rules.xml': '''<group name="windows,powershell,">
  <rule id="91801" level="0">
    <if_sid>60009</if_sid>
    <field name="win.system.channel" type="pcre2">Powershell/Operational</field>
    <description>Group of Windows rules for the Powershell/Operational channel.</description>
  </rule>
  <rule id="91837" level="4">
    <if_sid>91801</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(IEX|Invoke-Expression)</field>
    <options>no_full_log</options>
    <description>Powershell executed Invoke-Expression.</description>
  </rule>
</group>
''',
    # Mirrors a real defect: Wazuh 4.14.7 ships a rule file whose pcre2 regex
    # contains \\< and \\>, which ElementTree refuses to parse.
    'malformed_rules.xml': '''<group name="broken,">
  <rule id="91003" level="12">
    <regex type="pcre2">Set-.+Url.+\\<\\w+.*\\>.*?VirtualDirectory</regex>
    <description>MS Exchange proxylogon exploitation.</description>
  </rule>
</group>
''',
}

CUSTOM_RULES = {
    'local_rules.xml': '''<group name="local,">
  <rule id="100500" level="10">
    <decoded_as>json</decoded_as>
    <field name="alert.signature">sqlmap</field>
    <description>Custom SQL injection tool detected.</description>
  </rule>
</group>
''',
}

BUILTIN_DIR = '/var/ossec/ruleset/rules/'
CUSTOM_DIR = '/var/ossec/etc/rules/'


@contextmanager
def fake_ruleset(builtin=None, custom=None):
    """Serve a synthetic ruleset from the two hard-coded rule directories."""
    builtin = BUILTIN_RULES if builtin is None else builtin
    custom = CUSTOM_RULES if custom is None else custom
    real_open, real_listdir, real_isdir = builtins.open, os.listdir, os.path.isdir

    def fake_open(path, *a, **kw):
        p, base = str(path), os.path.basename(str(path))
        if p.startswith(BUILTIN_DIR) and base in builtin:
            return io.StringIO(builtin[base])
        if p.startswith(CUSTOM_DIR) and base in custom:
            return io.StringIO(custom[base])
        return real_open(path, *a, **kw)

    def fake_listdir(path):
        p = str(path)
        if p == BUILTIN_DIR:
            return list(builtin)
        if p == CUSTOM_DIR:
            return list(custom)
        return real_listdir(path)

    def fake_isdir(path):
        return True if str(path) in (BUILTIN_DIR, CUSTOM_DIR) else real_isdir(path)

    builtins.open, os.listdir, os.path.isdir = fake_open, fake_listdir, fake_isdir
    try:
        yield
    finally:
        builtins.open, os.listdir, os.path.isdir = real_open, real_listdir, real_isdir


class WebUITestCase(unittest.TestCase):
    """Base: an app whose Wazuh API calls are mocked and whose session is logged in."""

    api_reply = {
        'error': 0,
        'data': {'affected_items': [
            {'id': '001', 'name': 'agent-1', 'ip': '10.0.0.1', 'status': 'active',
             'os': {'name': 'Ubuntu', 'version': '22.04'}, 'version': 'Wazuh v4.14.7',
             'group': ['default'], 'node_name': 'node01', 'group_config_status': 'synced'},
        ], 'total_affected_items': 1},
    }

    def setUp(self):
        self.api_calls = []

        def fake_request(_self, method, endpoint, data=None, params=None):
            self.api_calls.append((method, endpoint, params))
            return self.api_reply

        self._real_request = web_ui.WazuhAPISession.request
        web_ui.WazuhAPISession.request = fake_request

        self.app = web_ui.create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess['api_session'] = {
                'host': 'localhost', 'port': 55000, 'username': 'tester',
                'token': 'fake-token', 'session_exp': int(time.time()) + 3600,
            }

    def tearDown(self):
        web_ui.WazuhAPISession.request = self._real_request


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

class TestAuthentication(WebUITestCase):

    def test_endpoints_require_login(self):
        anon = web_ui.create_app().test_client()
        for method, path in [('get', '/api/agents'), ('get', '/api/groups'),
                             ('get', '/api/nodes'), ('get', '/api/rules'),
                             ('get', '/api/rules/search?q=x'), ('get', '/api/users'),
                             ('post', '/api/agents/restart'), ('delete', '/api/agents')]:
            with self.subTest(path=path):
                self.assertEqual(getattr(anon, method)(path).status_code, 401)

    def test_expired_session_is_rejected(self):
        with self.client.session_transaction() as sess:
            # replace the whole dict: Flask does not notice nested mutations
            sess['api_session'] = dict(sess['api_session'], session_exp=int(time.time()) - 1)
        resp = self.client.get('/api/agents')
        self.assertEqual(resp.status_code, 401)
        self.assertTrue(resp.get_json().get('session_expired'))

    def test_login_page_renders(self):
        self.assertEqual(web_ui.create_app().test_client().get('/login').status_code, 200)


# --------------------------------------------------------------------------
# Security headers, CSRF, supply chain
# --------------------------------------------------------------------------

class TestSecurityHardening(WebUITestCase):

    def test_security_headers_are_set(self):
        resp = self.client.get('/login')
        expected = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
        }
        for header, value in expected.items():
            with self.subTest(header=header):
                self.assertEqual(resp.headers.get(header), value)
        self.assertIn('Permissions-Policy', resp.headers)

    def test_csp_locks_down_the_page(self):
        csp = self.client.get('/login').headers.get('Content-Security-Policy', '')
        for directive in ["default-src 'self'", "object-src 'none'",
                          "frame-ancestors 'none'", "form-action 'self'",
                          "connect-src 'self'", "base-uri 'self'"]:
            with self.subTest(directive=directive):
                self.assertIn(directive, csp)

    def test_no_response_header_leaks_the_wsgi_version(self):
        headers = self.client.get('/login').headers
        self.assertNotIn('Werkzeug', str(headers))
        self.assertNotIn('Python/3', str(headers))

    def test_wsgi_handler_version_is_overridden(self):
        """werkzeug writes its own Server header below Flask; after_request
        cannot reach it, so the handler class must be patched."""
        self.assertTrue(web_ui.harden_wsgi_server())
        from werkzeug.serving import WSGIRequestHandler
        self.assertEqual(WSGIRequestHandler.server_version, 'jt-wazuh-mgr')
        self.assertEqual(WSGIRequestHandler.sys_version, '')
        self.assertNotIn('Werkzeug', WSGIRequestHandler.server_version)

    def test_login_form_carries_a_csrf_token(self):
        body = self.client.get('/login').get_data(as_text=True)
        self.assertIn('name="csrf_token"', body)
        self.assertNotIn('name="csrf_token" value=""', body)

    def test_login_post_without_a_csrf_token_is_rejected(self):
        client = web_ui.create_app().test_client()
        client.get('/login')
        resp = client.post('/login', data={'username': 'x', 'password': 'y',
                                           'host': 'localhost', 'port': '55000'})
        self.assertEqual(resp.status_code, 400)

    def test_login_post_with_a_wrong_csrf_token_is_rejected(self):
        client = web_ui.create_app().test_client()
        client.get('/login')
        resp = client.post('/login', data={'csrf_token': 'not-the-token', 'username': 'x',
                                           'password': 'y', 'host': 'localhost', 'port': '55000'})
        self.assertEqual(resp.status_code, 400)

    def test_login_does_not_reflect_unescaped_input(self):
        """host/port/username are echoed back into value="" attributes."""
        body = self.client.get('/login').get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]*)"', body).group(1)
        payload = '"><script>alert(1)</script><x y="'
        resp = self.client.post('/login', data={
            'csrf_token': token, 'username': payload, 'host': payload,
            'port': payload, 'password': 'x'})
        body = resp.get_data(as_text=True)
        self.assertNotIn('<script>alert(1)</script>', body)
        self.assertIn('&lt;script&gt;', body)

    def test_page_uses_nothing_the_csp_would_block(self):
        tpl = web_ui.HTML_TEMPLATE
        for pattern, what in [(r'\beval\(', 'eval()'), (r'new Function\(', 'new Function()'),
                              (r'href="javascript:', 'javascript: URI'),
                              (r'new Worker\(', 'Worker'), (r'new WebSocket\(', 'WebSocket')]:
            with self.subTest(what=what):
                self.assertEqual(re.findall(pattern, tpl), [],
                                 '%s is blocked by the CSP' % what)
        remote = {u for u in re.findall(r'(?:src|href)="(https?://[^"]+)"', tpl)
                  if u.endswith(('.js', '.css'))}
        for url in remote:
            with self.subTest(url=url):
                self.assertTrue(url.startswith('https://cdnjs.cloudflare.com/'),
                                'CSP only allows cdnjs for scripts/styles')

    def test_session_cookie_flags(self):
        app = web_ui.create_app()
        self.assertTrue(app.config['SESSION_COOKIE_HTTPONLY'])
        self.assertEqual(app.config['SESSION_COOKIE_SAMESITE'], 'Lax')

    def test_third_party_scripts_pin_a_subresource_integrity_hash(self):
        """A CDN asset without SRI is an unverified dependency in a privileged UI."""
        tags = re.findall(r'<(?:script|link)[^>]*(?:src|href)="(https?://[^"]+)"[^>]*>',
                          web_ui.HTML_TEMPLATE)
        remote_assets = [t for t in tags if t.endswith(('.js', '.css'))]
        self.assertTrue(remote_assets, 'expected the CodeMirror assets to be present')
        for tag_match in re.finditer(r'<(?:script|link)[^>]*(https?://[^"]+\.(?:js|css))[^>]*>',
                                     web_ui.HTML_TEMPLATE):
            with self.subTest(asset=tag_match.group(1)):
                self.assertIn('integrity="sha384-', tag_match.group(0))
                self.assertIn('crossorigin="anonymous"', tag_match.group(0))


# --------------------------------------------------------------------------
# Request body handling  (regression: werkzeug BadRequest surfaced as 500)
# --------------------------------------------------------------------------

class TestRequestBodyHandling(WebUITestCase):

    def test_missing_body_never_returns_500(self):
        for method, path in [('delete', '/api/groups/testgrp'), ('delete', '/api/agents'),
                             ('post', '/api/groups'), ('post', '/api/agents/restart'),
                             ('post', '/api/agents/reconnect'), ('post', '/api/agents/upgrade'),
                             ('post', '/api/groups/rename'), ('post', '/api/users')]:
            with self.subTest(path=path):
                self.assertNotEqual(getattr(self.client, method)(path).status_code, 500)

    def test_non_json_content_type_is_tolerated(self):
        resp = self.client.delete('/api/groups/testgrp', data='', content_type='text/plain')
        self.assertEqual(resp.status_code, 200)

    def test_malformed_json_is_tolerated(self):
        resp = self.client.delete('/api/groups/testgrp', data='{oops',
                                  content_type='application/json')
        self.assertEqual(resp.status_code, 200)


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------

class TestInputValidation(WebUITestCase):

    BULK = [('delete', '/api/agents'), ('post', '/api/agents/restart'),
            ('post', '/api/agents/reconnect'), ('post', '/api/agents/upgrade')]

    def test_bulk_actions_require_agent_ids(self):
        for method, path in self.BULK:
            for payload in (None, {}, {'agent_ids': []}, {'agent_ids': '001'}):
                with self.subTest(path=path, payload=payload):
                    kw = {} if payload is None else {'json': payload}
                    self.assertEqual(getattr(self.client, method)(path, **kw).status_code, 400)
        self.assertEqual(self.api_calls, [], 'a rejected request must not reach the Wazuh API')

    def test_bulk_actions_reject_malformed_agent_ids(self):
        for bad in ['../../etc/passwd', '1; rm -rf /', 'abc', '', '1234567', '$(id)']:
            with self.subTest(agent_id=bad):
                resp = self.client.post('/api/agents/restart', json={'agent_ids': [bad]})
                self.assertEqual(resp.status_code, 400)
        self.assertEqual(self.api_calls, [])

    def test_valid_agent_ids_are_accepted(self):
        resp = self.client.post('/api/agents/restart', json={'agent_ids': ['001', '002']})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.api_calls[0][:2], ('PUT', '/agents/restart'))

    def test_group_creation_validates_the_name(self):
        for payload, code in [({}, 400), ({'name': ''}, 400), ({'name': 'bad;name'}, 400),
                              ({'name': '../escape'}, 400), ({'name': 'web_servers'}, 200)]:
            with self.subTest(payload=payload):
                self.assertEqual(self.client.post('/api/groups', json=payload).status_code, code)

    def test_group_deletion_validates_the_name(self):
        self.assertEqual(self.client.delete('/api/groups/bad;name').status_code, 400)

    def test_validator_helpers(self):
        self.assertTrue(web_ui.validate_agent_id('001'))
        self.assertFalse(web_ui.validate_agent_id('1;id'))
        self.assertTrue(web_ui.validate_group_name('web-servers.1'))
        self.assertFalse(web_ui.validate_group_name('a/b'))
        self.assertTrue(web_ui.validate_path('/var/ossec/etc/ossec.conf'))
        self.assertFalse(web_ui.validate_path('/var/ossec/etc/../../etc/shadow'))
        self.assertFalse(web_ui.validate_path('/etc/passwd'))
        self.assertFalse(web_ui.validate_path('/var/ossec/etc/x;id'))


# --------------------------------------------------------------------------
# Rules: listing, parse errors, hierarchy
# --------------------------------------------------------------------------

class TestRules(WebUITestCase):

    def test_rules_list_reports_unparseable_files(self):
        with fake_ruleset():
            data = self.client.get('/api/rules').get_json()
        self.assertEqual(data['total'], 3, 'rules from the readable files must still load')
        self.assertEqual([e['file'] for e in data['parse_errors']], ['malformed_rules.xml'])
        self.assertIn('not well-formed', data['parse_errors'][0]['error'])

    def test_rules_list_has_no_parse_errors_for_a_clean_ruleset(self):
        with fake_ruleset(builtin={'ok.xml': BUILTIN_RULES['0915-win-powershell_rules.xml']}):
            data = self.client.get('/api/rules').get_json()
        self.assertEqual(data['parse_errors'], [])

    def test_hierarchy_resolves_parent_and_child(self):
        with fake_ruleset():
            resp = self.client.get('/api/rules/hierarchy?rule_id=91801')
        data = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data['hierarchy'][0]['id'], '91801')
        self.assertEqual(data['hierarchy'][0]['children'][0]['id'], '91837')

    def test_hierarchy_rejects_bad_input(self):
        self.assertEqual(self.client.get('/api/rules/hierarchy').status_code, 400)
        self.assertEqual(self.client.get('/api/rules/hierarchy?rule_id=abc').status_code, 400)
        with fake_ruleset():
            self.assertEqual(self.client.get('/api/rules/hierarchy?rule_id=999999').status_code, 404)

    def test_deep_chain_does_not_exhaust_the_stack(self):
        """Regression: find_children() used to recurse without a depth limit."""
        depth = sys.getrecursionlimit() * 2
        rules = ['<group name="deep,">']
        for i in range(depth):
            parent = '<if_sid>%d</if_sid>' % (i - 1) if i else ''
            rules.append('<rule id="%d" level="1">%s<description>r%d</description></rule>'
                         % (i, parent, i))
        rules.append('</group>')
        with fake_ruleset(builtin={'deep.xml': '\n'.join(rules)}, custom={}):
            resp = self.client.get('/api/rules/hierarchy?rule_id=0')
        self.assertEqual(resp.status_code, 200, 'a long if_sid chain must not raise RecursionError')


# --------------------------------------------------------------------------
# Rules: full-content keyword search
# --------------------------------------------------------------------------

class TestRuleContentSearch(WebUITestCase):

    def search(self, query):
        with fake_ruleset():
            resp = self.client.get('/api/rules/search?' + query)
        return resp, resp.get_json()

    def test_matches_text_outside_the_description(self):
        _, data = self.search('q=scriptBlockText')
        self.assertEqual(data['total'], 1)
        self.assertEqual(data['rules'][0]['id'], '91837')
        self.assertIn('scriptBlockText', data['rules'][0]['snippet'])
        self.assertEqual(data['rules'][0]['matched'], ['scriptblocktext'])

    def test_multiple_keywords_default_to_and(self):
        self.assertEqual(self.search('q=powershell+invoke-expression')[1]['total'], 1)
        self.assertEqual(self.search('q=powershell+sqlmap')[1]['total'], 0)

    def test_match_any_returns_the_union(self):
        _, data = self.search('q=powershell+sqlmap&match=any')
        self.assertEqual(data['match'], 'any')
        self.assertEqual(data['total'], 3)

    def test_search_is_case_insensitive(self):
        _, data = self.search('q=SQLMAP')
        self.assertEqual(data['total'], 1)
        self.assertTrue(data['rules'][0]['is_custom'])

    def test_finds_rules_the_xml_parser_cannot_read(self):
        """Content search greps raw text, so it sees rules missing from /api/rules."""
        _, data = self.search('q=proxylogon')
        self.assertEqual(data['total'], 1)
        self.assertEqual(data['rules'][0]['file'], 'malformed_rules.xml')

    def test_rejects_empty_or_oversized_queries(self):
        self.assertEqual(self.search('q=')[0].status_code, 400)
        self.assertEqual(self.search('')[0].status_code, 400)
        self.assertEqual(self.search('q=' + 'x' * 600)[0].status_code, 400)

    def test_keyword_count_is_capped(self):
        _, data = self.search('q=' + '+'.join('k%d' % i for i in range(40)) + '&match=any')
        self.assertEqual(len(data['keywords']), 10)

    def test_query_is_never_used_as_a_path(self):
        """The keywords must not influence which files are read."""
        _, data = self.search('q=' + '../../../../etc/passwd')
        self.assertEqual(data['total'], 0)
        self.assertNotIn('error', data)


# --------------------------------------------------------------------------
# Config safety, custom WPK upgrade, agent runtime config
# --------------------------------------------------------------------------

class TestConfigSafety(WebUITestCase):

    def setUp(self):
        super().setUp()
        self.seen = []
        outer = self

        def fake_request(_self, method, endpoint, data=None, params=None):
            outer.seen.append((method, endpoint, params))
            if endpoint == '/cluster/local/info':
                return {'error': 0, 'data': {'affected_items': [{'node': 'master-node'}]}}
            if endpoint.endswith('/configuration/validation'):
                return {'error': 0, 'data': {'affected_items': [{'status': 'OK'}],
                                             'failed_items': []}}
            return {'error': 0, 'data': {'affected_items': ['master-node'], 'failed_items': []}}

        web_ui.WazuhAPISession.request = fake_request

    def test_validation_targets_the_right_endpoint(self):
        self.assertTrue(self.client.get('/api/nodes/master-node/config/validate').get_json()['valid'])
        self.assertIn(('GET', '/manager/configuration/validation', None), self.seen)
        self.seen.clear()
        self.client.get('/api/nodes/worker-1/config/validate')
        self.assertIn(('GET', '/cluster/worker-1/configuration/validation', None), self.seen)

    def test_validation_reports_failures(self):
        def failing(_self, method, endpoint, data=None, params=None):
            if endpoint == '/cluster/local/info':
                return {'error': 0, 'data': {'affected_items': [{'node': 'master-node'}]}}
            return {'error': 0, 'data': {'affected_items': [],
                                         'failed_items': [{'error': {'message': 'bad XML at line 3'}}]}}
        web_ui.WazuhAPISession.request = failing
        data = self.client.get('/api/nodes/master-node/config/validate').get_json()
        self.assertFalse(data['valid'])
        self.assertIn('bad XML at line 3', data['details'])

    def test_ruleset_reload_targets_the_right_node(self):
        self.assertEqual(self.client.put('/api/nodes/master-node/reload-ruleset').status_code, 200)
        self.assertIn(('PUT', '/manager/analysisd/reload', None), self.seen)
        self.seen.clear()
        self.client.put('/api/nodes/worker-1/reload-ruleset')
        self.assertIn(('PUT', '/cluster/analysisd/reload', {'nodes_list': 'worker-1'}), self.seen)

    def test_node_endpoints_validate_the_node_name(self):
        self.assertEqual(self.client.get('/api/nodes/bad;name/config/validate').status_code, 400)
        self.assertEqual(self.client.put('/api/nodes/bad;name/reload-ruleset').status_code, 400)


class TestCustomWpkUpgrade(WebUITestCase):

    api_reply = {'error': 0, 'data': {'affected_items': ['001'], 'failed_items': []}}

    def upgrade(self, **payload):
        return self.client.post('/api/agents/upgrade-custom', json=payload)

    def test_queues_an_upgrade_from_a_local_wpk(self):
        resp = self.upgrade(agent_ids=['001'], file_path='wazuh_agent_v4.14.7_linux_amd64.deb.wpk')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['success_count'], 1)
        method, endpoint, params = self.api_calls[0]
        self.assertEqual((method, endpoint), ('PUT', '/agents/upgrade_custom'))
        self.assertEqual(params['file_path'],
                         'var/upgrade/wazuh_agent_v4.14.7_linux_amd64.deb.wpk')

    def test_rejects_anything_that_is_not_a_wpk_name(self):
        for bad in ['', 'x.sh', '/var/ossec/etc/ossec.conf', 'a b.wpk', '.wpk']:
            with self.subTest(file_path=bad):
                self.assertEqual(self.upgrade(agent_ids=['001'], file_path=bad).status_code, 400)

    def test_path_is_rebuilt_so_traversal_cannot_escape(self):
        resp = self.upgrade(agent_ids=['001'], file_path='../../../../etc/evil.wpk')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.api_calls[0][2]['file_path'], 'var/upgrade/evil.wpk')

    def test_still_validates_agent_ids(self):
        self.assertEqual(self.upgrade(file_path='a.wpk').status_code, 400)
        self.assertEqual(self.upgrade(agent_ids=['1;id'], file_path='a.wpk').status_code, 400)


class TestAgentRuntimeConfig(WebUITestCase):

    api_reply = {'error': 0, 'data': {'client': {'server': [{'address': '10.0.0.1'}]}}}

    def test_reads_the_running_config(self):
        resp = self.client.get('/api/agents/001/runtime-config?component=agent&configuration=client')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('client', resp.get_json()['config'])
        self.assertEqual(self.api_calls[0][1], '/agents/001/config/agent/client')

    def test_rejects_injected_component_or_configuration(self):
        for query in ['component=../etc', 'configuration=../../x', 'component=A" ',
                      'component=' + 'a' * 40]:
            with self.subTest(query=query):
                self.assertEqual(
                    self.client.get('/api/agents/001/runtime-config?' + query).status_code, 400)

    def test_agent_key_requires_a_valid_id(self):
        self.assertEqual(self.client.get('/api/agents/abc/key').status_code, 400)


# --------------------------------------------------------------------------
# Logtest, decoders, CDB lists
# --------------------------------------------------------------------------

class TestLogtest(WebUITestCase):

    api_reply = {'error': 0, 'data': {
        'token': 'abc123',
        'messages': ['INFO: Session initialized'],
        'output': {'rule': {'id': '5715', 'level': 3, 'description': 'sshd auth success'},
                   'decoder': {'name': 'sshd'}}}}

    def test_reports_the_matching_rule(self):
        resp = self.client.post('/api/logtest', json={'event': 'sshd: Accepted password',
                                                      'log_format': 'syslog'})
        data = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data['output']['rule']['id'], '5715')
        self.assertTrue(data['alert'])
        self.assertEqual(data['token'], 'abc123')

    def test_rejects_bad_input(self):
        for payload, why in [({}, 'no event'), ({'event': '   '}, 'blank event'),
                             ({'event': 'x', 'log_format': 'made-up'}, 'unknown format'),
                             ({'event': 'x', 'token': '../etc'}, 'bad token'),
                             ({'event': 'x' * 20001}, 'oversized')]:
            with self.subTest(why=why):
                self.assertEqual(self.client.post('/api/logtest', json=payload).status_code, 400)

    def test_session_token_is_validated_on_delete(self):
        self.assertEqual(self.client.delete('/api/logtest/session/abc123').status_code, 200)
        self.assertEqual(self.client.delete('/api/logtest/session/bad-token').status_code, 400)


class TestDecoders(WebUITestCase):

    api_reply = {'error': 0, 'data': {'affected_items': [
        {'name': 'sshd', 'filename': '0095-sshd_decoders.xml', 'relative_dirname': 'ruleset/decoders'},
        {'name': 'mine', 'filename': 'local_decoder.xml', 'relative_dirname': 'etc/decoders'},
    ], 'total_affected_items': 2}}

    def test_flags_custom_decoders_by_relative_path(self):
        decoders = self.client.get('/api/decoders').get_json()['decoders']
        self.assertFalse(decoders[0]['is_custom'])
        self.assertTrue(decoders[1]['is_custom'])

    def test_search_is_forwarded(self):
        self.client.get('/api/decoders?search=sshd')
        self.assertEqual(self.api_calls[0][2].get('search'), 'sshd')

    def test_file_name_is_restricted(self):
        for bad in ['../../etc/passwd', 'x.sh', '', 'a/b.xml']:
            with self.subTest(filename=bad):
                self.assertEqual(
                    self.client.get('/api/decoders/file?filename=' + bad).status_code, 400)


class TestCdbLists(WebUITestCase):

    api_reply = {'error': 0, 'data': {
        'affected_items': [{'filename': 'blacklist', 'relative_dirname': 'etc/lists'}],
        'failed_items': []}}

    def setUp(self):
        super().setUp()
        self.raw_calls = []
        outer = self

        def fake_raw(_self, method, endpoint, body=None, params=None,
                     content_type='application/octet-stream'):
            outer.raw_calls.append((method, endpoint, body, params))
            return (True, 'key1:value1\n') if method == 'GET' else (True, '')

        self._real_raw = web_ui.WazuhAPISession.request_raw
        web_ui.WazuhAPISession.request_raw = fake_raw

    def tearDown(self):
        web_ui.WazuhAPISession.request_raw = self._real_raw
        super().tearDown()

    def test_lists_are_flagged_custom(self):
        self.assertTrue(self.client.get('/api/lists').get_json()['lists'][0]['is_custom'])

    def test_read_returns_plain_text(self):
        data = self.client.get('/api/lists/file?filename=blacklist').get_json()
        self.assertIn('key1:value1', data['content'])
        self.assertEqual(self.raw_calls[0][3], {'raw': 'true'})

    def test_save_sends_a_raw_body_and_asks_for_a_reload(self):
        resp = self.client.put('/api/lists/file', json={'filename': 'blacklist', 'content': 'a:1'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn('Reload', resp.get_json()['message'])
        method, endpoint, body, params = self.raw_calls[0]
        self.assertEqual((method, endpoint), ('PUT', '/lists/files/blacklist'))
        self.assertEqual(body, 'a:1')
        self.assertEqual(params, {'overwrite': 'true'})

    def test_names_are_restricted(self):
        for bad in ['../etc/passwd', 'a/b', '', 'x' * 200, 'a b']:
            with self.subTest(name=bad):
                self.assertEqual(
                    self.client.get('/api/lists/file?filename=' + bad).status_code, 400)
                self.assertEqual(
                    self.client.delete('/api/lists/file?filename=' + bad).status_code, 400)

    def test_save_requires_content(self):
        self.assertEqual(self.client.put('/api/lists/file', json={'filename': 'x'}).status_code, 400)

    def test_oversized_list_is_rejected(self):
        resp = self.client.put('/api/lists/file',
                               json={'filename': 'x', 'content': 'a' * (5 * 1024 * 1024 + 1)})
        self.assertEqual(resp.status_code, 400)


# --------------------------------------------------------------------------
# Cross-agent inventory search
# --------------------------------------------------------------------------

class TestInventorySearch(WebUITestCase):

    AGENTS = [
        {'id': '000', 'name': 'manager'},
        {'id': '001', 'name': 'web1'},
        {'id': '002', 'name': 'db1'},
    ]
    PACKAGES = {
        '001': [{'name': 'openssl', 'version': '3.0.2'}],
        '002': [{'name': 'openssl', 'version': '1.1.1'}],
    }

    def setUp(self):
        super().setUp()
        outer = self

        def fake_request(_self, method, endpoint, data=None, params=None):
            outer.api_calls.append((method, endpoint, params))
            if endpoint == '/agents':
                return {'error': 0, 'data': {'affected_items': [
                    {'id': a['id'], 'name': a['name'], 'status': 'active',
                     'os': {'name': 'Ubuntu', 'version': '22.04'},
                     'version': 'Wazuh v4.14.7', 'group': ['default']}
                    for a in outer.AGENTS]}}
            for agent_id, items in outer.PACKAGES.items():
                if endpoint == '/syscollector/%s/packages' % agent_id:
                    return {'error': 0, 'data': {'affected_items': items}}
            return {'error': 0, 'data': {'affected_items': []}}

        web_ui.WazuhAPISession.request = fake_request

    def test_finds_the_same_package_across_agents(self):
        data = self.client.get('/api/inventory/search?type=packages&q=openssl').get_json()
        self.assertEqual(data['total'], 2)
        self.assertEqual(data['agents_matched'], 2)
        self.assertEqual({r['version'] for r in data['rows']}, {'3.0.2', '1.1.1'})
        self.assertTrue(all('agent_name' in r for r in data['rows']))

    def test_the_manager_itself_is_skipped(self):
        data = self.client.get('/api/inventory/search?type=packages').get_json()
        self.assertNotIn('000', {r['agent_id'] for r in data['rows']})

    def test_scope_can_be_narrowed_to_specific_agents(self):
        data = self.client.get('/api/inventory/search?type=packages&agents=001').get_json()
        self.assertEqual(data['agents_queried'], 1)
        self.assertEqual(data['total'], 1)

    def test_query_is_forwarded_as_a_search(self):
        self.client.get('/api/inventory/search?type=packages&q=openssl')
        syscollector = [p for _, e, p in self.api_calls if 'syscollector' in e]
        self.assertTrue(syscollector)
        self.assertTrue(all(p.get('search') == 'openssl' for p in syscollector))

    def test_rejects_bad_input(self):
        self.assertEqual(self.client.get('/api/inventory/search?type=evil').status_code, 400)
        self.assertEqual(self.client.get('/api/inventory/search?q=' + 'x' * 200).status_code, 400)
        self.assertEqual(self.client.get('/api/inventory/search?agents=1;id').status_code, 400)

    def test_agent_errors_do_not_fail_the_whole_search(self):
        def flaky(_self, method, endpoint, data=None, params=None):
            if endpoint == '/agents':
                return {'error': 0, 'data': {'affected_items': [
                    {'id': '001', 'name': 'web1', 'status': 'active', 'os': {}, 'group': []},
                    {'id': '002', 'name': 'db1', 'status': 'active', 'os': {}, 'group': []}]}}
            if endpoint.endswith('/002/packages'):
                raise RuntimeError('agent unreachable')
            return {'error': 0, 'data': {'affected_items': [{'name': 'openssl'}]}}
        web_ui.WazuhAPISession.request = flaky
        data = self.client.get('/api/inventory/search?type=packages').get_json()
        self.assertEqual(data['total'], 1)
        self.assertEqual([f['agent_id'] for f in data['agents_failed']], ['002'])

    def test_types_endpoint_lists_columns(self):
        types = self.client.get('/api/inventory/types').get_json()['types']
        self.assertIn('packages', types)
        self.assertIn('name', types['packages']['columns'])


# --------------------------------------------------------------------------
# Daemon health, group files, active response, pre-registration
# --------------------------------------------------------------------------

class TestBatchDEndpoints(WebUITestCase):

    api_reply = {'error': 0, 'data': {'affected_items': [], 'failed_items': []}}

    def test_daemon_stats_pick_the_right_endpoint(self):
        def fake(_self, method, endpoint, data=None, params=None):
            self.api_calls.append((method, endpoint, params))
            if endpoint == '/cluster/local/info':
                return {'error': 0, 'data': {'affected_items': [{'node': 'master-node'}]}}
            return {'error': 0, 'data': {'affected_items': [{'name': 'wazuh-analysisd'}],
                                         'failed_items': []}}
        web_ui.WazuhAPISession.request = fake
        self.assertEqual(self.client.get('/api/nodes/master-node/daemon-stats').status_code, 200)
        self.assertTrue(any(e == '/manager/daemons/stats' for _, e, _ in self.api_calls))
        self.api_calls.clear()
        self.client.get('/api/nodes/worker-1/daemon-stats')
        self.assertTrue(any(e == '/cluster/worker-1/daemons/stats' for _, e, _ in self.api_calls))

    def test_daemon_stats_validate_the_node(self):
        self.assertEqual(self.client.get('/api/nodes/bad;name/daemon-stats').status_code, 400)

    def test_group_file_names_are_restricted(self):
        self.assertEqual(self.client.get('/api/groups/bad;name/files').status_code, 400)
        self.assertEqual(self.client.get('/api/groups/default/files/..%2F..%2Fetc%2Fpasswd').status_code, 400)

    def test_active_response_validates_the_command(self):
        for bad in ['', 'rm -rf /', 'a;b', 'x' * 100, '$(id)']:
            with self.subTest(command=bad):
                resp = self.client.post('/api/active-response',
                                        json={'agent_ids': ['001'], 'command': bad})
                self.assertEqual(resp.status_code, 400)
        self.assertEqual(self.api_calls, [])

    def test_active_response_validates_arguments(self):
        resp = self.client.post('/api/active-response',
                                json={'agent_ids': ['001'], 'command': 'firewall-drop',
                                      'arguments': ['1.2.3.4; rm -rf /']})
        self.assertEqual(resp.status_code, 400)

    def test_active_response_sends_command_and_agents(self):
        resp = self.client.post('/api/active-response',
                                json={'agent_ids': ['001', '002'], 'command': 'firewall-drop',
                                      'arguments': ['1.2.3.4']})
        self.assertEqual(resp.status_code, 200)
        method, endpoint, params = self.api_calls[0]
        self.assertEqual((method, endpoint), ('PUT', '/active-response'))
        self.assertEqual(params['agents_list'], '001,002')

    def test_active_response_dry_run_sends_nothing(self):
        resp = self.client.post('/api/active-response',
                                json={'agent_ids': ['001'], 'command': 'restart-wazuh',
                                      'dry_run': True})
        self.assertTrue(resp.get_json()['dry_run'])
        self.assertEqual(self.api_calls, [])

    def test_registration_validates_names(self):
        for payload in [{}, {'names': []}, {'names': ['bad name']}, {'names': ['a/b']},
                        {'names': ['x' * 200]}, {'names': ['ok'] * 101}]:
            with self.subTest(payload=str(payload)[:40]):
                self.assertEqual(
                    self.client.post('/api/agents/register', json=payload).status_code, 400)

    def test_registration_returns_ids_and_keys(self):
        def fake(_self, method, endpoint, data=None, params=None):
            self.api_calls.append((method, endpoint, params))
            return {'error': 0, 'data': {'affected_items': [
                {'id': '099', 'key': 'KEYDATA', 'name': params['agent_name']}]}}
        web_ui.WazuhAPISession.request = fake
        data = self.client.post('/api/agents/register', json={'names': ['web-01']}).get_json()
        self.assertEqual(data['created'][0]['id'], '099')
        self.assertEqual(data['created'][0]['key'], 'KEYDATA')
        self.assertEqual(self.api_calls[0][1], '/agents/insert/quick')


# --------------------------------------------------------------------------
# Front-end assets embedded in the template
# --------------------------------------------------------------------------

class TestFrontend(unittest.TestCase):

    # The template uses optional chaining, so an old node cannot parse it even
    # though every current browser can.
    MIN_NODE_MAJOR = 14

    @classmethod
    def setUpClass(cls):
        cls.tpl = web_ui.HTML_TEMPLATE
        cls.have_node = False
        cls.node_reason = 'node not available'
        try:
            probe = subprocess.run(['node', '--version'], capture_output=True, text=True)
        except (OSError, FileNotFoundError):
            return
        if probe.returncode == 0:
            try:
                major = int(probe.stdout.strip().lstrip('v').split('.')[0])
            except ValueError:
                major = 0
            if major >= cls.MIN_NODE_MAJOR:
                cls.have_node = True
            else:
                cls.node_reason = ('node %s is too old to parse the template (need >= %d)'
                                   % (probe.stdout.strip(), cls.MIN_NODE_MAJOR))

    def _js(self):
        blocks = re.findall(r'<script[^>]*>(.*?)</script>', self.tpl, re.S)
        js = '\n;\n'.join(b for b in blocks if b.strip())
        js = re.sub(r'\{%.*?%\}', '', js, flags=re.S)
        return re.sub(r'\{\{.*?\}\}', '0', js, flags=re.S)

    def test_javascript_parses(self):
        if not self.have_node:
            self.skipTest(self.node_reason)
        import tempfile
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False, encoding='utf-8') as fh:
            fh.write(self._js())
            path = fh.name
        try:
            result = subprocess.run(['node', '--check', path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.unlink(path)

    def test_version_comparator_is_numeric(self):
        """4.14.7 must rank above 4.9.0 -- a string compare gets this backwards."""
        if not self.have_node:
            self.skipTest(self.node_reason)
        start = self.tpl.index('        function parseVersion(ver) {')
        end = self.tpl.index('        // Format agent version with color coding')
        cases = [('4.14.7', '4.9.0', 1), ('4.9.0', '4.14.7', -1),
                 ('Wazuh v4.14.7', '4.14.7', 0), ('Wazuh v4.13.1', '4.14.7', -1),
                 ('v4.14.7', '4.14.7', 0), ('4.14.10', '4.14.9', 1),
                 ('4.14', '4.14.7', -1), ('-', '4.14.7', -1)]
        script = self.tpl[start:end] + '\n' + '\n'.join(
            'if (compareVersions(%r, %r) !== %d) { console.log("FAIL %s vs %s"); process.exit(1); }'
            % (a, b, want, a, b) for a, b, want in cases)
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_version_helpers_are_defined_once(self):
        for name in ('function parseVersion', 'function compareVersions'):
            self.assertEqual(self.tpl.count(name), 1,
                             '%s must not be shadowed by a duplicate definition' % name)

    def test_rules_hierarchy_view_can_scroll(self):
        """Regression: the view had no sizing, so its content was clipped."""
        m = re.search(r'<div id="rulesHierarchyView"([^>]*)>', self.tpl)
        self.assertIsNotNone(m)
        style = m.group(1)
        for prop in ('flex:1', 'min-height:0', 'display:flex', 'overflow:hidden'):
            self.assertIn(prop, style.replace(' ', ''))

    def test_every_tab_panel_has_a_scroll_container(self):
        panels = ['agents-panel', 'groups-panel', 'nodes-panel', 'rules-panel',
                  'stats-panel', 'users-panel', 'logs-panel']
        positions = sorted((self.tpl.index('id="%s"' % p), p) for p in panels)
        for idx, (pos, name) in enumerate(positions):
            end = positions[idx + 1][0] if idx + 1 < len(positions) else pos + 20000
            body = self.tpl[pos:end]
            scrollable = ('table-container' in body or 'rules-content' in body
                          or 'stats-content' in body or 'log-container' in body
                          or re.search(r'overflow[-a-z]*\s*:\s*(auto|scroll)', body))
            self.assertTrue(scrollable, '%s has no scrollable container' % name)


# --------------------------------------------------------------------------
# Translations
# --------------------------------------------------------------------------

class TestI18n(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with io.open(os.path.join(root, 'lib', 'i18n_engine.js'), encoding='utf-8') as fh:
            cls.engine = fh.read()
        cls.dict_block = cls._block(cls.engine, 'var I18N =')
        cls.pattern_block = cls._block(cls.engine, 'var I18N_PATTERNS =')

    @staticmethod
    def _block(src, marker):
        i = src.index(marker)
        j = src.index('{', i)
        depth, k = 0, j
        for k in range(j, len(src)):
            if src[k] == '{':
                depth += 1
            elif src[k] == '}':
                depth -= 1
                if depth == 0:
                    break
        return src[j:k + 1]

    def test_engine_is_embedded_in_the_template(self):
        with io.open(web_ui.__file__, encoding='utf-8') as fh:
            self.assertIn('BEGIN i18n auto-embed', fh.read())
        self.assertIn('jtwzSetLang', web_ui.HTML_TEMPLATE)
        self.assertIn('jtwzSetLang', web_ui.LOGIN_TEMPLATE)

    def test_embedded_copy_matches_the_source(self):
        """tools/build_i18n.py must have been re-run after editing the engine."""
        marker = "var I18N_PATTERNS = {"
        self.assertIn(marker, web_ui.HTML_TEMPLATE)
        sample = self.dict_block[:2000]
        self.assertIn(sample, web_ui.HTML_TEMPLATE,
                      'lib/web_ui.py is stale -- run: python3 tools/build_i18n.py')

    def test_no_duplicate_keys_with_conflicting_values(self):
        values = {}
        for m in re.finditer(r"^\s*'((?:[^'\\]|\\.)*)':\s*'((?:[^'\\]|\\.)*)',?\s*$",
                             self.dict_block, re.M):
            values.setdefault(m.group(1), []).append(m.group(2))
        conflicting = {k: v for k, v in values.items() if len(set(v)) > 1}
        self.assertEqual(conflicting, {},
                         'a later duplicate key silently overrides the earlier one')

    def test_product_name_is_not_translated(self):
        self.assertNotIn("'JT Wazuh Manager':", self.dict_block)

    def test_key_strings_have_translations(self):
        for key in ['Agents', 'Groups', 'Nodes', 'Rules', 'Statistics', 'Logs',
                    'Upgrade Agents', 'Upgrade to manager version', 'Updated',
                    'Exit Selection', 'Add Agents to Group', 'Clean Queue DB Results']:
            with self.subTest(key=key):
                self.assertIn("'%s':" % key, self.dict_block)


if __name__ == '__main__':
    unittest.main(verbosity=2)
