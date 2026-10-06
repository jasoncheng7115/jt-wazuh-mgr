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
import json
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

    def test_hierarchy_search_by_file_name(self):
        """A non-numeric query is a file name fragment, not a bad rule ID.

        Reviewing a pack means asking what a file contains, which the rule-ID
        lookup cannot answer.
        """
        with fake_ruleset():
            resp = self.client.get('/api/rules/hierarchy?rule_id=local_rules')
        data = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data['mode'], 'file')
        self.assertEqual(data['matched_files'], ['local_rules.xml'])
        self.assertEqual(data['hierarchy'][0]['id'], 'local_rules.xml')
        self.assertTrue(data['hierarchy'][0]['is_file'])
        self.assertIn('100500', data['all_rules'])

    def test_hierarchy_file_search_accepts_the_extension_and_ignores_case(self):
        for query in ('local_rules.xml', 'LOCAL_RULES', 'cal_rul'):
            with self.subTest(query=query):
                with fake_ruleset():
                    data = self.client.get(
                        '/api/rules/hierarchy?rule_id=' + query).get_json()
                self.assertEqual(data.get('matched_files'), ['local_rules.xml'])

    def test_hierarchy_file_search_nests_children_under_their_parent(self):
        rules = ('<group name="t,">'
                 '<rule id="700100" level="0"><description>base</description></rule>'
                 '<rule id="700101" level="5"><if_sid>700100</if_sid>'
                 '<description>child</description></rule></group>')
        with fake_ruleset(builtin={}, custom={'nest_rules.xml': rules}):
            data = self.client.get('/api/rules/hierarchy?rule_id=nest').get_json()
        file_node = data['hierarchy'][0]
        self.assertEqual([r['id'] for r in file_node['children']], ['700100'])
        self.assertEqual([r['id'] for r in file_node['children'][0]['children']], ['700101'])

    def test_hierarchy_file_search_rejects_path_like_input(self):
        for bad in ('../../etc/passwd', 'a/b', 'x' * 65, 'rule;name'):
            with self.subTest(query=bad):
                with fake_ruleset():
                    resp = self.client.get(
                        '/api/rules/hierarchy?rule_id=' + bad)
                self.assertEqual(resp.status_code, 400)

    def test_hierarchy_file_search_reports_no_match(self):
        with fake_ruleset():
            resp = self.client.get('/api/rules/hierarchy?rule_id=no-such-file')
        self.assertEqual(resp.status_code, 404)
        self.assertIn('No rule file matches', resp.get_json()['error'])

    def test_hierarchy_resolves_parent_and_child(self):
        with fake_ruleset():
            resp = self.client.get('/api/rules/hierarchy?rule_id=91801')
        data = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data['hierarchy'][0]['id'], '91801')
        self.assertEqual(data['hierarchy'][0]['children'][0]['id'], '91837')

    def test_hierarchy_rejects_bad_input(self):
        self.assertEqual(self.client.get('/api/rules/hierarchy').status_code, 400)
        with fake_ruleset():
            # A plain word is now a file-name query, so it is valid input that
            # simply matches nothing -- 404, not 400. Only input that could not
            # be a file name at all is refused outright.
            self.assertEqual(
                self.client.get('/api/rules/hierarchy?rule_id=abc').status_code, 404)
            self.assertEqual(
                self.client.get('/api/rules/hierarchy?rule_id=a/b').status_code, 400)
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
# Cluster-wide ruleset reload
# --------------------------------------------------------------------------

class TestClusterRulesetReload(WebUITestCase):
    """Rule files sync to workers, but each node's analysisd keeps its own
    in-memory ruleset until reloaded -- a fix can look live while the node that
    processes those agents still runs the old rules."""

    def _api(self, clustered=True, failed=None):
        outer = self

        def fake(_self, method, endpoint, data=None, params=None):
            outer.api_calls.append((method, endpoint, params))
            if endpoint == '/cluster/status':
                return {'data': {'enabled': 'yes' if clustered else 'no',
                                 'running': 'yes' if clustered else 'no'}}
            return {'error': 0, 'data': {
                'affected_items': [{'name': 'master-node', 'warnings': []},
                                   {'name': 'worker-1', 'warnings': ['rule 100170 ignored']}],
                'failed_items': failed or []}}
        web_ui.WazuhAPISession.request = fake

    def test_clustered_reload_hits_every_node(self):
        self._api(clustered=True)
        data = self.client.post('/api/cluster/reload-ruleset').get_json()
        self.assertEqual(data['scope'], 'cluster')
        self.assertEqual(data['ok_count'], 2)
        self.assertEqual({n['node'] for n in data['nodes']}, {'master-node', 'worker-1'})
        # no nodes_list -> the API reloads every node
        self.assertIn(('PUT', '/cluster/analysisd/reload', None), self.api_calls)

    def test_standalone_manager_uses_the_manager_endpoint(self):
        self._api(clustered=False)
        data = self.client.post('/api/cluster/reload-ruleset').get_json()
        self.assertEqual(data['scope'], 'manager')
        self.assertIn(('PUT', '/manager/analysisd/reload', None), self.api_calls)
        self.assertNotIn(('PUT', '/cluster/analysisd/reload', None), self.api_calls)

    def test_warnings_are_surfaced_per_node(self):
        self._api(clustered=True)
        data = self.client.post('/api/cluster/reload-ruleset').get_json()
        worker = [n for n in data['nodes'] if n['node'] == 'worker-1'][0]
        self.assertEqual(worker['warnings'], ['rule 100170 ignored'])

    def test_failed_nodes_are_reported(self):
        self._api(clustered=True,
                  failed=[{'id': ['worker-2'], 'error': {'message': 'socket unavailable'}}])
        data = self.client.post('/api/cluster/reload-ruleset').get_json()
        self.assertEqual(data['fail_count'], 1)
        self.assertIn('worker-2: socket unavailable', data['errors'])
        self.assertFalse([n for n in data['nodes'] if n['node'] == 'worker-2'][0]['ok'])

    def test_requires_authentication(self):
        anon = web_ui.create_app().test_client()
        self.assertEqual(anon.post('/api/cluster/reload-ruleset').status_code, 401)


# --------------------------------------------------------------------------
# Node configuration drift
# --------------------------------------------------------------------------

class TestNodeConfigDiff(WebUITestCase):
    """The cluster syncs rules and lists but NOT ossec.conf, so a worker can be
    missing a <list> declaration and silently ignore every rule that uses it."""

    MASTER_CONF = """<ossec_config>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/jason_tools_blacklist</list>
    <list>etc/lists/malware_hash</list>
  </ruleset>
  <wodle name="osquery"><disabled>no</disabled></wodle>
  <syscheck><directories>/etc</directories></syscheck>
</ossec_config>"""
    WORKER_CONF = """<ossec_config>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <list>etc/lists/audit-keys</list>
  </ruleset>
  <wodle name="osquery"><disabled>yes</disabled></wodle>
  <syscheck><directories>/etc</directories><directories>/opt</directories></syscheck>
</ossec_config>"""

    def setUp(self):
        super().setUp()
        outer = self

        def fake(_self, method, endpoint, data=None, params=None):
            outer.api_calls.append((method, endpoint, params))
            if endpoint == '/cluster/nodes':
                return {'data': {'affected_items': [
                    {'name': 'master-node', 'type': 'master', 'ip': '10.0.0.1', 'version': '4.14.7'},
                    {'name': 'worker-1', 'type': 'worker', 'ip': '10.0.0.2', 'version': '4.14.7'}]}}
            return {'error': 0, 'data': {}}

        def fake_raw(_self, method, endpoint, body=None, params=None,
                     content_type='application/octet-stream'):
            if '/cluster/master-node/configuration' in endpoint:
                return True, outer.MASTER_CONF
            if '/cluster/worker-1/configuration' in endpoint:
                return True, outer.WORKER_CONF
            return False, 'not found'

        web_ui.WazuhAPISession.request = fake
        self._real_raw = web_ui.WazuhAPISession.request_raw
        web_ui.WazuhAPISession.request_raw = fake_raw

    def tearDown(self):
        web_ui.WazuhAPISession.request_raw = self._real_raw
        super().tearDown()

    def diff(self):
        return self.client.get('/api/nodes/config-diff').get_json()

    def test_master_is_the_reference(self):
        self.assertEqual(self.diff()['reference'], 'master-node')

    def test_missing_list_declaration_is_reported(self):
        ruleset = [d for d in self.diff()['differences'] if d['section'] == 'ruleset']
        self.assertEqual(len(ruleset), 1)
        missing = ruleset[0]['missing_on_node']
        self.assertIn('list: etc/lists/jason_tools_blacklist', missing)
        self.assertIn('list: etc/lists/malware_hash', missing)
        self.assertEqual(ruleset[0]['node'], 'worker-1')

    def test_disabled_module_is_reported(self):
        wodle = [d for d in self.diff()['differences'] if d['section'] == 'wodle']
        self.assertTrue(wodle)
        self.assertIn('osquery: disabled=yes', wodle[0]['extra_on_node'])
        self.assertIn('osquery: disabled=no', wodle[0]['missing_on_node'])

    def test_extra_item_on_the_worker_is_reported(self):
        syscheck = [d for d in self.diff()['differences'] if d['section'] == 'syscheck']
        self.assertTrue(syscheck)
        self.assertIn('directories: /opt', syscheck[0]['extra_on_node'])

    def test_identical_nodes_report_no_difference(self):
        original = TestNodeConfigDiff.WORKER_CONF
        TestNodeConfigDiff.WORKER_CONF = self.MASTER_CONF
        try:
            data = self.diff()
            self.assertEqual(data['diff_count'], 0)
            self.assertEqual(data['differences'], [])
        finally:
            TestNodeConfigDiff.WORKER_CONF = original

    def test_unreadable_node_is_reported_not_fatal(self):
        def raw(_self, method, endpoint, body=None, params=None,
                content_type='application/octet-stream'):
            if 'master-node' in endpoint:
                return True, self.MASTER_CONF
            return False, 'permission denied'
        web_ui.WazuhAPISession.request_raw = raw
        data = self.diff()
        self.assertIn('worker-1', data['errors'])
        self.assertEqual(data['diff_count'], 0)

    def test_requires_authentication(self):
        anon = web_ui.create_app().test_client()
        self.assertEqual(anon.get('/api/nodes/config-diff').status_code, 401)


# --------------------------------------------------------------------------
# Rule packs (install / uninstall)
# --------------------------------------------------------------------------

class PackFixture(WebUITestCase):
    """A throwaway Wazuh tree and a session, shared by the pack test classes."""

    ANALYSISD_OK = '#!/bin/sh\necho "loaded"\nexit 0\n'
    ANALYSISD_BAD = '#!/bin/sh\necho "ERROR: bad rule"\nexit 0\n'

    def setUp(self):
        super().setUp()
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix='jtpack-')
        for sub in ('etc/rules', 'etc/lists', 'etc/decoders', 'bin'):
            os.makedirs(os.path.join(self.tmp, sub), exist_ok=True)
        with io.open(os.path.join(self.tmp, 'etc/ossec.conf'), 'w', encoding='utf-8') as fh:
            fh.write('<ossec_config>\n  <ruleset>\n'
                     '    <list>etc/lists/audit-keys</list>\n'
                     '  </ruleset>\n</ossec_config>\n')
        self._write_analysisd(self.ANALYSISD_OK)

        # Scheduled updaters go to a scratch cron.d, never the real /etc/cron.d
        # of the machine running the suite.
        self._cron_dir = os.path.join(self.tmp, 'cron.d')
        os.makedirs(self._cron_dir)
        self.addCleanup(setattr, web_ui, 'PACK_CRON_DIR', web_ui.PACK_CRON_DIR)
        web_ui.PACK_CRON_DIR = self._cron_dir

        # A single-node cluster. Without this the shared API fixture answers
        # /cluster/nodes with the agent list, and declaring a CDB list would try
        # to reach nodes named after agents. Cluster behaviour has its own tests
        # in test_ui_operations.py.
        self._real_get_nodes = web_ui.WazuhAPISession.get_nodes
        web_ui.WazuhAPISession.get_nodes = lambda _self: [
            {'name': 'node01', 'type': 'master', 'ip': '127.0.0.1'}]
        self.addCleanup(setattr, web_ui.WazuhAPISession, 'get_nodes', self._real_get_nodes)

        # wrap the real config so only wazuh_path is redirected; restore even if
        # setUp fails partway, otherwise the override leaks into every other test
        self._real_get_config = web_ui.get_config
        self.addCleanup(setattr, web_ui, 'get_config', self._real_get_config)
        real_config = self._real_get_config()
        tmp_path = self.tmp

        class FakeConfig:
            wazuh_path = tmp_path

            def __getattr__(self, name):
                return getattr(real_config, name)

        web_ui.get_config = lambda *a, **k: FakeConfig()
        # the app was built with the real config; rebuild so routes see the fake one
        self.app = web_ui.create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess['api_session'] = {'host': 'h', 'port': 1, 'username': 'tester',
                                   'token': 't', 'session_exp': int(time.time()) + 3600}

    def _write_analysisd(self, body):
        path = os.path.join(self.tmp, 'bin', 'wazuh-analysisd')
        with io.open(path, 'w', encoding='utf-8') as fh:
            fh.write(body)
        os.chmod(path, 0o755)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)
        super().tearDown()

    def conf(self):
        with io.open(os.path.join(self.tmp, 'etc/ossec.conf'), encoding='utf-8') as fh:
            return fh.read()



class TestRulePacks(PackFixture):
    """Packs write into the manager, so the install path must be all-or-nothing."""

    def test_catalogue_lists_packs_as_not_installed(self):
        data = self.client.get('/api/packs').get_json()
        self.assertGreaterEqual(data['total'], 1)
        self.assertTrue(all(not p['installed'] for p in data['packs']))

    def test_install_copies_files_and_declares_lists(self):
        resp = self.client.post('/api/packs/jt-portable-detect/install')
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.assertTrue(os.path.isfile(
            os.path.join(self.tmp, 'etc/rules/zz-906100-jt_portable_rules.xml')))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, 'etc/lists/jt-approved-portable')))
        self.assertIn('<list>etc/lists/jt-approved-portable</list>', self.conf())
        listing = self.client.get('/api/packs').get_json()['packs']
        self.assertTrue([p for p in listing if p['id'] == 'jt-portable-detect'][0]['installed'])

    def _two_node_cluster(self, peer_reachable):
        """A master plus one worker whose configuration may or may not be writable."""
        web_ui.WazuhAPISession.get_nodes = lambda _self: [
            {'name': 'node01', 'type': 'master', 'ip': '127.0.0.1'},
            {'name': 'node02', 'type': 'worker', 'ip': '10.0.1.11'}]
        stored = {}
        # The worker's own copy, captured before the install edits the local one.
        # Reading self.conf() lazily would hand the peer the master's already
        # modified file, and the declaration would look like it was in place.
        baseline = self.conf()

        def fake_raw(_self, method, endpoint, body=None, params=None,
                     content_type='application/octet-stream'):
            node = endpoint.split('/')[2]
            if method == 'GET':
                if not peer_reachable:
                    return False, 'node is down'
                return True, stored.get(node, baseline)
            if not peer_reachable:
                return False, 'node is down'
            stored[node] = body
            return True, 'ok'

        real = web_ui.WazuhAPISession.request_raw
        web_ui.WazuhAPISession.request_raw = fake_raw
        self.addCleanup(setattr, web_ui.WazuhAPISession, 'request_raw', real)
        # SSH is not configured in this fixture, so the fallback is unavailable
        # too -- which is the situation an operator without SSH keys is in.
        return stored

    def test_install_aborts_when_a_worker_cannot_be_declared(self):
        """A pack whose list is undeclared on a worker is ignored there, silently."""
        self._two_node_cluster(peer_reachable=False)
        resp = self.client.post('/api/packs/jt-portable-detect/install', json={})
        self.assertEqual(resp.status_code, 400, resp.get_data(as_text=True))
        body = resp.get_json()
        self.assertTrue(body.get('rolled_back'))
        self.assertIn('node02', body['error'])
        self.assertIn('local_only', body['error'], 'the way forward is not stated')
        # nothing left behind
        self.assertNotIn('<list>etc/lists/jt-approved-portable</list>', self.conf())
        self.assertFalse(os.path.isfile(
            os.path.join(self.tmp, 'etc/rules/zz-906100-jt_portable_rules.xml')))

    def test_local_only_installs_but_records_which_nodes_are_short(self):
        self._two_node_cluster(peer_reachable=False)
        resp = self.client.post('/api/packs/jt-portable-detect/install',
                                json={'local_only': True})
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.assertIn('<list>etc/lists/jt-approved-portable</list>', self.conf())
        detail = self.client.get('/api/packs/jt-portable-detect').get_json()
        self.assertEqual(detail['undeclared_nodes'], ['node02'],
                         'the incomplete install is not visible afterwards')
        self.assertIn('node02', resp.get_json()['message'])

    def test_a_reachable_worker_is_declared_too(self):
        stored = self._two_node_cluster(peer_reachable=True)
        resp = self.client.post('/api/packs/jt-portable-detect/install', json={})
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.assertIn('node02', stored, 'the worker was never written to')
        self.assertIn('<list>etc/lists/jt-approved-portable</list>', stored['node02'])
        detail = self.client.get('/api/packs/jt-portable-detect').get_json()
        self.assertEqual(detail['undeclared_nodes'], [])

    def test_agent_group_carries_the_files_the_agent_needs(self):
        """An auditd rules file is no use sitting on the manager.

        Files listed under agent_group.files ride along in the group
        directory, which the cluster distributes to every assigned agent.
        """
        resp = self.client.post('/api/packs/jt-portable-detect/install', json={})
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        gdir = os.path.join(self.tmp, 'etc', 'shared', 'portable-detect')
        self.assertTrue(os.path.isfile(os.path.join(gdir, 'agent.conf')))
        self.assertTrue(os.path.isfile(os.path.join(gdir, 'jt-portable.rules')),
                        'the auditd rules file never reached the agent group')
        with io.open(os.path.join(gdir, 'jt-portable.rules'), encoding='utf-8') as fh:
            body = fh.read()
        self.assertIn('jt_portable_tmpexec', body,
                      'the shipped audit rules do not set the key the rules match on')

    def test_removing_the_pack_leaves_the_agent_group_and_says_so(self):
        """The group is deliberately left behind, and the operator is told.

        Agents may already be assigned to it. Pulling its configuration out
        from under them would stop collection they still depend on, so the
        removal reports what it left rather than deciding for them.
        """
        self.client.post('/api/packs/jt-portable-detect/install', json={})
        gdir = os.path.join(self.tmp, 'etc', 'shared', 'portable-detect')
        self.assertTrue(os.path.isfile(os.path.join(gdir, 'jt-portable.rules')))
        resp = self.client.delete('/api/packs/jt-portable-detect')
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.assertTrue(os.path.isfile(os.path.join(gdir, 'agent.conf')),
                        'the agent group config was pulled from under assigned agents')
        self.assertTrue(os.path.isfile(os.path.join(gdir, 'jt-portable.rules')))
        self.assertIn('portable-detect', resp.get_json().get('message', ''),
                      'the removal did not say which group it left behind')

    def test_an_unsafe_agent_group_file_name_is_refused(self):
        view = self.app.view_functions['install_pack']
        while hasattr(view, '__wrapped__'):
            view = view.__wrapped__
        install = None
        for name, cell in zip(view.__code__.co_freevars, view.__closure__ or ()):
            if name == '_install_agent_group':
                install = cell.cell_contents
        self.assertIsNotNone(install, '_install_agent_group is no longer reachable')
        for bad in ('../../etc/passwd', 'a/b', '..', 'x' * 80):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    install(os.path.join(self.tmp, 'nopack'),
                            {'agent_group': {'name': 'g', 'config': 'agent.conf',
                                             'files': [bad]}},
                            self.tmp, [])

    def test_install_rolls_back_when_the_ruleset_stops_validating(self):
        self._write_analysisd(self.ANALYSISD_BAD)
        resp = self.client.post('/api/packs/jt-portable-detect/install')
        self.assertEqual(resp.status_code, 400)
        self.assertTrue(resp.get_json()['rolled_back'])
        self.assertFalse(os.path.isfile(
            os.path.join(self.tmp, 'etc/rules/zz-906100-jt_portable_rules.xml')))
        self.assertNotIn('jt-approved-portable', self.conf())
        self.assertFalse([p for p in self.client.get('/api/packs').get_json()['packs']
                          if p['id'] == 'jt-portable-detect'][0]['installed'])

    def test_uninstall_removes_files_and_declaration(self):
        self.client.post('/api/packs/jt-portable-detect/install')
        resp = self.client.delete('/api/packs/jt-portable-detect')
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(os.path.isfile(
            os.path.join(self.tmp, 'etc/rules/zz-906100-jt_portable_rules.xml')))
        self.assertNotIn('jt-approved-portable', self.conf())
        self.assertFalse([p for p in self.client.get('/api/packs').get_json()['packs']
                          if p['id'] == 'jt-portable-detect'][0]['installed'])

    def test_uninstall_refuses_to_discard_local_edits(self):
        self.client.post('/api/packs/jt-portable-detect/install')
        target = os.path.join(self.tmp, 'etc/lists/jt-approved-portable')
        with io.open(target, 'a', encoding='utf-8') as fh:
            fh.write('MyTool.exe:approved\n')
        resp = self.client.delete('/api/packs/jt-portable-detect')
        self.assertEqual(resp.status_code, 409)
        self.assertIn('etc/lists/jt-approved-portable', resp.get_json()['modified'])
        self.assertTrue(os.path.isfile(target))
        forced = self.client.delete('/api/packs/jt-portable-detect', json={'force': True})
        self.assertEqual(forced.status_code, 200)

    def test_conflicting_rule_ids_block_the_install(self):
        with io.open(os.path.join(self.tmp, 'etc/rules/other.xml'), 'w', encoding='utf-8') as fh:
            fh.write('<group name="x,"><rule id="906100" level="3">'
                     '<description>squatter</description></rule></group>')
        resp = self.client.post('/api/packs/jt-portable-detect/install')
        self.assertEqual(resp.status_code, 409)
        self.assertIn('906100', resp.get_json()['conflicts'])
        forced = self.client.post('/api/packs/jt-portable-detect/install', json={'force': True})
        self.assertEqual(forced.status_code, 200)

    def _fake_pack(self, pack_id, manifest, files=None):
        """Build a throwaway pack under the real catalogue directory."""
        import shutil
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pdir = os.path.join(root, 'packs', pack_id)
        self.addCleanup(shutil.rmtree, pdir, True)
        for sub in ('rules', 'scripts', 'agent'):
            os.makedirs(os.path.join(pdir, sub), exist_ok=True)
        for rel, body in (files or {}).items():
            path = os.path.join(pdir, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with io.open(path, 'w', encoding='utf-8') as fh:
                fh.write(body)
        import hashlib
        for group, sub in (('files', None), ('scripts', 'scripts')):
            for entry in manifest.get(group) or []:
                d = sub or {'rule': 'rules', 'list': 'lists',
                            'decoder': 'decoders'}[entry['type']]
                path = os.path.join(pdir, d, entry['name'])
                with io.open(path, 'rb') as fh:
                    entry['sha256'] = hashlib.sha256(fh.read()).hexdigest()
        with io.open(os.path.join(pdir, 'manifest.json'), 'w', encoding='utf-8') as fh:
            json.dump(manifest, fh)
        return pdir

    RULE_XML = ('<group name="t,"><rule id="139500" level="3">'
                '<description>t</description></rule></group>\n')
    SCRIPT_BODY = '#!/usr/bin/env python3\nprint("updater")\n'

    def _script_manifest(self, cron='17 */6 * * *'):
        return {
            'id': 'jt-testscript', 'name': 'T', 'name_zh': 'T', 'version': '1.0',
            'summary': 's', 'summary_zh': 's', 'notes': [], 'notes_zh': [],
            'author': 'a', 'license': 'Apache-2.0', 'rule_id_range': '139500-139599',
            'files': [{'type': 'rule', 'name': 'r.xml', 'dest': 'etc/rules/r.xml'}],
            'scripts': [{'name': 'upd.py', 'dest': 'etc/jt-packs/bin/upd.py',
                         'cron': cron, 'args': '--wazuh-path {wazuh_path}'}],
        }

    def test_install_writes_the_script_and_schedules_it(self):
        """A pack whose rules read a CDB list is inert until something fills it."""
        self._fake_pack('jt-testscript', self._script_manifest(),
                        {'rules/r.xml': self.RULE_XML, 'scripts/upd.py': self.SCRIPT_BODY})
        resp = self.client.post('/api/packs/jt-testscript/install')
        data = resp.get_json()
        self.assertEqual(resp.status_code, 200, data)
        script = os.path.join(self.tmp, 'etc/jt-packs/bin/upd.py')
        self.assertTrue(os.path.isfile(script))
        self.assertEqual(oct(os.stat(script).st_mode & 0o777), '0o750')
        self.assertEqual(len(data.get('scheduled') or []), 1)
        self.assertIn('17 */6 * * *', data['message'])
        # the schedule landed in the fixture, not in the host's /etc/cron.d
        self.assertTrue(os.path.isfile(os.path.join(self._cron_dir, 'jt-jt-testscript')))
        self.assertFalse(os.path.exists('/etc/cron.d/jt-jt-testscript'))

    def test_uninstall_removes_the_script(self):
        self._fake_pack('jt-testscript', self._script_manifest(),
                        {'rules/r.xml': self.RULE_XML, 'scripts/upd.py': self.SCRIPT_BODY})
        self.client.post('/api/packs/jt-testscript/install')
        script = os.path.join(self.tmp, 'etc/jt-packs/bin/upd.py')
        self.assertTrue(os.path.isfile(script))
        resp = self.client.delete('/api/packs/jt-testscript')
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertFalse(os.path.isfile(script),
                         'a cron entry pointing at a deleted script would fail forever')

    def test_a_malformed_cron_schedule_is_refused_and_rolled_back(self):
        self._fake_pack('jt-testscript', self._script_manifest(cron='17 */6 * * * ; rm -rf /'),
                        {'rules/r.xml': self.RULE_XML, 'scripts/upd.py': self.SCRIPT_BODY})
        resp = self.client.post('/api/packs/jt-testscript/install')
        self.assertEqual(resp.status_code, 400)
        self.assertTrue(resp.get_json().get('rolled_back'))
        self.assertFalse(os.path.isfile(os.path.join(self.tmp, 'etc/rules/r.xml')),
                         'a refused install must not leave its rule file behind')

    def test_existing_agent_group_config_is_never_overwritten(self):
        """Someone else's group config may hold settings this pack knows nothing of."""
        manifest = self._script_manifest()
        del manifest['scripts']
        manifest['agent_group'] = {'name': 'testgrp', 'config': 'agent.conf'}
        self._fake_pack('jt-testscript', manifest,
                        {'rules/r.xml': self.RULE_XML,
                         'agent/agent.conf': '<agent_config><!-- from pack --></agent_config>\n'})
        gdir = os.path.join(self.tmp, 'etc/shared/testgrp')
        os.makedirs(gdir, exist_ok=True)
        with io.open(os.path.join(gdir, 'agent.conf'), 'w', encoding='utf-8') as fh:
            fh.write('<agent_config><!-- pre-existing --></agent_config>\n')
        resp = self.client.post('/api/packs/jt-testscript/install')
        self.assertEqual(resp.status_code, 200, resp.get_json())
        with io.open(os.path.join(gdir, 'agent.conf'), encoding='utf-8') as fh:
            self.assertIn('pre-existing', fh.read())
        self.assertTrue((resp.get_json().get('agent_group') or {}).get('already_present'))

    def test_agent_group_is_created_when_absent(self):
        manifest = self._script_manifest()
        del manifest['scripts']
        manifest['agent_group'] = {'name': 'newgrp', 'config': 'agent.conf'}
        self._fake_pack('jt-testscript', manifest,
                        {'rules/r.xml': self.RULE_XML,
                         'agent/agent.conf': '<agent_config><!-- from pack --></agent_config>\n'})
        resp = self.client.post('/api/packs/jt-testscript/install')
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, 'etc/shared/newgrp/agent.conf')))
        self.assertIn('assign agents', resp.get_json()['message'])

    def test_uninstalling_something_not_installed_is_404(self):
        self.assertEqual(self.client.delete('/api/packs/jt-ioc').status_code, 404)

    def test_unknown_pack_is_rejected(self):
        self.assertEqual(self.client.post('/api/packs/nope/install').status_code, 404)
        self.assertEqual(self.client.get('/api/packs/nope').status_code, 404)

    def test_pack_ids_cannot_escape_the_catalogue(self):
        for bad in ['..', '../../etc', 'a b']:
            with self.subTest(pack=bad):
                self.assertIn(self.client.get('/api/packs/' + bad).status_code, (400, 404, 301, 308))

    def test_requires_authentication(self):
        anon = web_ui.create_app().test_client()
        self.assertEqual(anon.get('/api/packs').status_code, 401)
        self.assertEqual(anon.post('/api/packs/jt-ioc/install').status_code, 401)
        self.assertEqual(anon.delete('/api/packs/jt-ioc').status_code, 401)


# --------------------------------------------------------------------------
# Front-end assets embedded in the template
# --------------------------------------------------------------------------

class TestPackDeployment(PackFixture):
    """The deployment guide and the 'already there, no record' state (1.10.0)."""

    def _copy_pack_files_by_hand(self, pack_id):
        import shutil
        m = json.load(open(os.path.join(web_ui.__file__.rsplit('/lib/', 1)[0], 'packs', pack_id,
                                        'manifest.json'), encoding='utf-8'))
        pdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(web_ui.__file__))),
                            'packs', pack_id)
        for e in m['files']:
            sub = {'rule': 'rules', 'list': 'lists'}.get(e['type'], 'decoders')
            shutil.copy(os.path.join(pdir, sub, e['name']), os.path.join(self.tmp, e['dest']))

    def test_hand_copied_pack_is_reported_untracked_not_in_conflict_with_itself(self):
        """Our own manager ran all eight packs; the catalogue said none was installed and the
        detail page listed each pack's own rule IDs as conflicts."""
        self._copy_pack_files_by_hand('jt-portable-detect')
        packs = {p['id']: p for p in self.client.get('/api/packs').get_json()['packs']}
        p = packs['jt-portable-detect']
        self.assertFalse(p['installed'])
        self.assertTrue(p['untracked'])
        self.assertTrue(p['untracked_identical'])
        d = self.client.get('/api/packs/jt-portable-detect').get_json()
        self.assertEqual(d['conflicts'], [])
        self.assertEqual(d['presence']['identical'], d['presence']['total'])
        # and installing over the hand-copied files is not refused as a conflict
        resp = self.client.post('/api/packs/jt-portable-detect/install')
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))

    def test_rules_in_another_file_still_conflict(self):
        with io.open(os.path.join(self.tmp, 'etc/rules/local_rules.xml'), 'w', encoding='utf-8') as fh:
            fh.write('<group name="x,"><rule id="906101" level="3"><description>mine</description></rule></group>')
        d = self.client.get('/api/packs/jt-portable-detect').get_json()
        self.assertIn({'rule': '906101', 'file': 'local_rules.xml'}, d['conflicts'])

    def test_detail_carries_the_setup_guide_and_agent_files(self):
        d = self.client.get('/api/packs/jt-portable-detect').get_json()
        self.assertTrue(d['setup'])
        self.assertIn('sysmon-jt-portable.xml', d['agent_files'])

    def test_agent_file_can_be_viewed_and_downloaded(self):
        r = self.client.get('/api/packs/jt-portable-detect/file?path=agent/sysmon-jt-portable.xml')
        self.assertEqual(r.status_code, 200)
        self.assertIn('FileExecutableDetected', r.get_json()['content'])
        r = self.client.get('/api/packs/jt-portable-detect/file?path=agent/jt-portable.rules&download=1')
        self.assertEqual(r.status_code, 200)
        self.assertIn('attachment', r.headers.get('Content-Disposition', ''))
        self.assertIn('jt_portable_tmpexec', r.get_data(as_text=True))

    def test_file_endpoint_refuses_anything_outside_the_pack_folders(self):
        for bad in ('manifest.json', '../jt-ioc/manifest.json', 'agent/../manifest.json',
                    '/etc/passwd', 'agent/.hidden', 'secrets/agent.conf', 'agent/a/b',
                    'agent/' + 'x' * 200, ''):
            r = self.client.get('/api/packs/jt-portable-detect/file?path=' + bad)
            self.assertEqual(r.status_code, 400, bad)
        r = self.client.get('/api/packs/jt-portable-detect/file?path=agent/missing.xml')
        self.assertEqual(r.status_code, 404)
        r = self.client.get('/api/packs/no-such-pack/file?path=agent/agent.conf')
        self.assertEqual(r.status_code, 404)


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

    def test_template_has_no_backspace_characters(self):
        """A JS regex written as /\\b.../ inside the non-raw template reaches the
        browser as a backspace, not a word boundary. That silently broke the JSON
        and alert-log highlighters until 1.10.0."""
        for name in ('HTML_TEMPLATE', 'LOGIN_TEMPLATE'):
            self.assertNotIn('\x08', getattr(web_ui, name), name)

    def test_json_highlighter_marks_literals(self):
        if not self.have_node:
            self.skipTest(self.node_reason)
        start = self.tpl.index('function highlightJson(json) {')
        end = self.tpl.index('\n        }', self.tpl.index('return json.replace(', start)) + 10
        script = ('const escapeHtml = s => String(s);\n' + self.tpl[start:end] + '\n'
                  'const out = highlightJson(JSON.stringify({a: true, b: null, c: -1.5, d: String.fromCharCode(120, 34, 121)}));\n'
                  'for (const cls of ["json-key", "json-boolean", "json-null", "json-number", "json-string"])\n'
                  '  if (!out.includes(cls)) { console.log("missing " + cls + " in " + out); process.exit(1); }\n')
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class TestPythonCompatibility(unittest.TestCase):
    """The managers this runs on move between Python versions with the OS."""

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _sources(self):
        for top in ('.', 'lib', 'tools', 'tests', 'packs'):
            base = os.path.join(self.ROOT, top)
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [d for d in dirnames if d not in ('.vendor', 'vendor', '__pycache__', 'github', 'node_modules')]
                for f in filenames:
                    if f.endswith('.py'):
                        yield os.path.join(dirpath, f)
                if top == '.':
                    break

    def test_sources_compile_with_warnings_as_errors(self):
        """Python 3.12 warns on an unknown escape such as '\\d' in a normal string
        and a later release makes it a SyntaxError -- the service would then not
        start at all after an OS upgrade."""
        import warnings
        for path in self._sources():
            with open(path, encoding='utf-8') as fh:
                src = fh.read()
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                try:
                    compile(src, path, 'exec')
                except SyntaxError as exc:
                    self.fail('%s: %s' % (os.path.relpath(path, self.ROOT), exc))

    def test_installer_does_not_pip_into_the_system(self):
        """PEP 668 refuses that on Ubuntu 24.04 / Debian 12, and packages pip put
        under one Python version are gone after the OS moves to the next."""
        with open(os.path.join(self.ROOT, 'install.sh'), encoding='utf-8') as fh:
            body = fh.read()
        self.assertNotRegex(body, r'(?m)^\s*pip3? install')
        self.assertIn('--target "$INSTALL_DIR/vendor.new"', body)

    def test_entry_points_load_the_vendor_directory(self):
        for name in ('wazuh_agent_mgr.py', 'create_api_user.py'):
            with open(os.path.join(self.ROOT, name), encoding='utf-8') as fh:
                self.assertIn("'vendor')", fh.read(), name)


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

    @classmethod
    def _lang_blocks(cls, block):
        """Split the I18N object into one sub-block per language.

        Duplicate-key checks have to be per language: 'Agents' appears once in
        each language with a different value, which is correct, while twice in
        the same language with different values is the bug being looked for.
        """
        out = {}
        for m in re.finditer(r"^\s{4}'([\w-]+)':\s*\{", block, re.M):
            out[m.group(1)] = cls._block(block[m.start():], "'%s':" % m.group(1))
        return out

    def test_no_duplicate_keys_with_conflicting_values(self):
        for lang, sub in self._lang_blocks(self.dict_block).items():
            values = {}
            for m in re.finditer(r"^\s*'((?:[^'\\]|\\.)*)':\s*'((?:[^'\\]|\\.)*)',?\s*$",
                                 sub, re.M):
                values.setdefault(m.group(1), []).append(m.group(2))
            conflicting = {k: v for k, v in values.items() if len(set(v)) > 1}
            with self.subTest(lang=lang):
                self.assertEqual(conflicting, {},
                                 'a later duplicate key silently overrides the earlier one')

    def test_every_language_translates_the_same_keys(self):
        """A key present in one language and missing from another shows through
        as untranslated English in the middle of a translated page."""
        blocks = self._lang_blocks(self.dict_block)
        self.assertGreaterEqual(len(blocks), 2, 'expected more than one language')
        keys = {}
        for lang, sub in blocks.items():
            keys[lang] = set(re.findall(r"^\s*'((?:[^'\\]|\\.)*)':\s*'", sub, re.M))
        reference = max(keys, key=lambda k: len(keys[k]))
        for lang in keys:
            if lang == reference:
                continue
            missing = keys[reference] - keys[lang]
            with self.subTest(lang=lang):
                self.assertEqual(sorted(missing)[:10], [],
                                 '%s is missing keys that %s has' % (lang, reference))

    def test_patterns_are_not_double_escaped(self):
        """A regex literal written with \\d matches a backslash then 'd'.

        Seven patterns were written that way and could never match anything;
        they were found only when a third language was added and the block was
        read line by line. Nothing else catches it -- the file parses, the rule
        loads, and the string simply stays in English.
        """
        offenders = []
        for line in self.pattern_block.splitlines():
            m = re.match(r"\s*\[/(.+?)/[a-z]*,", line)
            if m and '\\\\' in m.group(1):
                offenders.append(m.group(1)[:70])
        self.assertEqual(offenders, [],
                         'double-escaped regex literal: these can never match')

    def test_product_name_is_not_translated(self):
        self.assertNotIn("'JT Wazuh Manager':", self.dict_block)

    def test_key_strings_have_translations(self):
        for key in ['Agents', 'Groups', 'Nodes', 'Rules', 'Statistics', 'Logs',
                    'Upgrade Agents', 'Upgrade to manager version', 'Updated',
                    'Exit Selection', 'Add Agents to Group', 'Clean Queue DB Results']:
            with self.subTest(key=key):
                self.assertIn("'%s':" % key, self.dict_block)


class TestShippedPacks(unittest.TestCase):
    """Validate the real packs/ catalogue, not a fixture.

    The manifest carries a sha256 per file; editing a rule without refreshing it
    makes uninstall think the file was locally edited and refuse to remove it.
    """

    @classmethod
    def setUpClass(cls):
        import glob, json
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.packs_dir = os.path.join(root, 'packs')
        cls.packs = []
        for mf in sorted(glob.glob(os.path.join(cls.packs_dir, '*', 'manifest.json'))):
            with io.open(mf, encoding='utf-8') as fh:
                cls.packs.append((os.path.dirname(mf), json.load(fh)))
        if not cls.packs:
            raise unittest.SkipTest('no packs/ catalogue in this checkout')

    SUBDIR = {'rule': 'rules', 'list': 'lists', 'decoder': 'decoders'}

    def test_every_manifest_file_exists_and_matches_its_hash(self):
        import hashlib
        for pdir, m in self.packs:
            for entry in m.get('files', []):
                path = os.path.join(pdir, self.SUBDIR[entry['type']], entry['name'])
                with self.subTest(pack=m['id'], file=entry['name']):
                    self.assertTrue(os.path.isfile(path), 'missing %s' % path)
                    with io.open(path, 'rb') as fh:
                        digest = hashlib.sha256(fh.read()).hexdigest()
                    self.assertEqual(digest, entry.get('sha256'),
                                     'stale sha256 for %s; refresh the manifest' % entry['name'])

    # mirrors _validate_dest() in web_ui.create_app(), which is nested and not
    # importable; stated here as the contract every shipped manifest must meet
    ALLOWED_ROOTS = ('etc/rules/', 'etc/lists/', 'etc/decoders/')

    def test_destinations_stay_inside_the_ruleset_directories(self):
        for _, m in self.packs:
            for entry in m.get('files', []):
                dest = entry.get('dest', '')
                with self.subTest(pack=m['id'], dest=dest):
                    self.assertTrue(dest, 'missing dest')
                    self.assertNotIn('..', dest)
                    self.assertFalse(dest.startswith('/'))
                    self.assertTrue(any(dest.startswith(r) for r in self.ALLOWED_ROOTS),
                                    'dest outside the ruleset dirs: %r' % dest)
                    self.assertRegex(dest, r'^[A-Za-z0-9._/-]+$')
                    expected = self.SUBDIR[entry['type']].replace('rules', 'rules')
                    self.assertTrue(dest.startswith('etc/%s/' % expected),
                                    'type %r should install under etc/%s/'
                                    % (entry['type'], expected))

    def test_rule_xml_parses_and_ids_are_unique_across_packs(self):
        import xml.etree.ElementTree as ET
        seen = {}
        for pdir, m in self.packs:
            for entry in m.get('files', []):
                if entry['type'] != 'rule':
                    continue
                path = os.path.join(pdir, 'rules', entry['name'])
                with io.open(path, encoding='utf-8') as fh:
                    body = fh.read()
                with self.subTest(pack=m['id'], file=entry['name']):
                    root = ET.fromstring('<rules>' + body + '</rules>')
                    for rule in root.iter('rule'):
                        rid = rule.get('id')
                        self.assertNotIn(rid, seen,
                                         'rule %s duplicated in %s and %s'
                                         % (rid, seen.get(rid), m['id']))
                        seen[rid] = m['id']

    def test_decoder_xml_parses(self):
        import xml.etree.ElementTree as ET
        for pdir, m in self.packs:
            for entry in m.get('files', []):
                if entry['type'] != 'decoder':
                    continue
                path = os.path.join(pdir, 'decoders', entry['name'])
                with io.open(path, encoding='utf-8') as fh:
                    body = fh.read()
                with self.subTest(pack=m['id'], file=entry['name']):
                    ET.fromstring('<decoders>' + body + '</decoders>')

    def test_manifest_has_the_fields_the_catalogue_renders(self):
        for _, m in self.packs:
            with self.subTest(pack=m.get('id')):
                for field in ('id', 'name', 'name_zh', 'version', 'summary',
                              'summary_zh', 'author', 'license', 'files'):
                    self.assertIn(field, m)
                self.assertTrue(m['files'])

    def _pack_dir_of(self, m):
        return os.path.join(self.packs_dir, m['id'])

    def test_setup_steps_are_complete_in_both_languages(self):
        for _, m in self.packs:
            for i, st in enumerate(m.get('setup') or []):
                with self.subTest(pack=m['id'], step=i):
                    for field in ('title', 'title_zh', 'body', 'body_zh', 'platform'):
                        self.assertTrue(st.get(field), field)
                    self.assertIn(st['platform'], ('manager', 'all', 'windows', 'linux', 'macos', 'network'))
                    if st.get('verify'):
                        self.assertTrue(st.get('verify_zh'))
                    if st.get('file'):
                        sub, name = st['file'].split('/')
                        self.assertIn(sub, ('agent', 'rules', 'lists', 'decoders', 'scripts'))
                        self.assertTrue(os.path.isfile(os.path.join(self._pack_dir_of(m), sub, name)),
                                        st['file'])

    def test_custom_parent_rules_are_defined_in_the_same_pack(self):
        """jt-portable-detect hung its Windows rules off 100110, a rule in another
        pack. Installed alone, the parent was missing; with an old copy of the other
        pack it silenced them. A pack may only depend on built-in rules and itself."""
        import xml.etree.ElementTree as ET
        for _, m in self.packs:
            defined, used = set(), set()
            for e in m['files']:
                if e['type'] != 'rule':
                    continue
                with io.open(os.path.join(self._pack_dir_of(m), 'rules', e['name']), encoding='utf-8') as fh:
                    root = ET.fromstring('<r>' + fh.read() + '</r>')
                for rule in root.iter('rule'):
                    defined.add(int(rule.get('id')))
                    for tag in ('if_sid', 'if_matched_sid'):
                        for el in rule.iter(tag):
                            used.update(int(x) for x in re.split(r'[,\s]+', el.text.strip()) if x)
            with self.subTest(pack=m['id']):
                self.assertEqual(sorted(x for x in used if x >= 100000 and x not in defined), [])

    def test_no_broad_level_one_parent_under_builtin_fim_or_sysmon(self):
        """A level 0/1 rule that matches nearly every event of its kind silences
        the built-in detections it sits beside: 906200 did it to FIM for a month."""
        import xml.etree.ElementTree as ET
        broad_parents = {'550', '553', '554', '61603', '61607', '61613', '61615', '61617'}
        for _, m in self.packs:
            for e in m['files']:
                if e['type'] != 'rule':
                    continue
                with io.open(os.path.join(self._pack_dir_of(m), 'rules', e['name']), encoding='utf-8') as fh:
                    root = ET.fromstring('<r>' + fh.read() + '</r>')
                for rule in root.iter('rule'):
                    sids = {s.strip() for el in rule.iter('if_sid') for s in el.text.split(',')}
                    if int(rule.get('level')) <= 1 and sids & broad_parents:
                        conds = [c for c in rule if c.tag in ('field', 'list', 'match', 'regex')]
                        with self.subTest(rule=rule.get('id')):
                            # an exclusion must at least name a concrete path or value,
                            # not merely require that a field exists
                            self.assertTrue(conds)
                            for c in conds:
                                self.assertNotIn((c.text or '').strip(), ('.+', '\\.+', '.*'))

    def test_windows_portable_rules_against_decoded_eventchannel_values(self):
        """wazuh-logtest cannot replay an eventchannel event on 4.14 (it decodes it
        as plain JSON), so the Windows rule chains are checked here against values
        shaped exactly as analysisd decodes them: two backslashes per separator.
        This found 906102 and 906170 both matching an archive run, through a
        lookahead that a backtracking \\\\+ could step past."""
        import xml.etree.ElementTree as ET
        path = os.path.join(self.packs_dir, 'jt-portable-detect', 'rules', 'zz-906100-jt_portable_rules.xml')
        with io.open(path, encoding='utf-8') as fh:
            root = ET.fromstring('<r>' + fh.read() + '</r>')
        rules = {}
        for r in root.iter('rule'):
            rules[r.get('id')] = {
                'fields': [(f.get('name').split('.')[-1], f.text, f.get('type')) for f in r.findall('field')],
                'lists': [(l.get('field').split('.')[-1], l.get('lookup')) for l in r.findall('list')],
                'parents': [s.strip() for el in r.findall('if_sid') for s in el.text.split(',')]}
        approved = {'PuTTY', 'WinSCP.exe'}

        def matches(rid, ev):
            r = rules[rid]
            for key, pat, typ in r['fields']:
                if ev.get(key) is None or not re.search(pat if typ == 'pcre2' else pat.replace('\\.', '.'), ev[key]):
                    return False
            for key, lookup in r['lists']:
                hit = key == 'originalFileName' and ev.get(key) in approved
                if (lookup == 'match_key') != hit:
                    return False
            return True

        def finals(parent, ev):
            out = []
            for rid in rules:
                if parent in rules[rid]['parents'] and matches(rid, ev):
                    out += finals(rid, ev) or [rid]
            return sorted(set(out))

        b = '\\\\'
        u = b.join(['C:', 'Users', 'user'])

        def p(*a):
            return b.join((u,) + a)
        cases = [
            ('61603', {'image': p('Downloads', 't.exe'), 'parentImage': 'cmd.exe'}, ['906100']),
            ('61603', {'image': p('Downloads', 't.exe'), 'parentImage': b.join(['C:', 'Windows', 'explorer.exe'])}, ['906106']),
            ('61603', {'image': p('AppData', 'Local', 'Temp', 'Temp1_t.zip', 't.exe'), 'parentImage': 'x'}, ['906170']),
            ('61603', {'image': p('AppData', 'Local', 'Temp', 'Rar$EXa12.3', 't.exe'), 'parentImage': 'x'}, ['906170']),
            ('61603', {'image': p('AppData', 'Local', 'Temp', 'abc', 't.exe'), 'parentImage': 'x'}, ['906102']),
            ('61603', {'image': p('Tools', 'nc.exe'), 'parentImage': 'x'}, ['906171']),
            ('61603', {'image': p('proj', 'target', 'debug', 'a.exe'), 'parentImage': 'x'}, ['906172']),
            ('61603', {'image': p('.cargo', 'bin', 'rustup.exe'), 'parentImage': 'x'}, []),
            ('61603', {'image': p('Downloads', 'a.exe'), 'parentImage': 'x', 'originalFileName': 'AnyDesk.exe', 'product': 'AnyDesk'}, ['906175']),
            ('61603', {'image': p('Downloads', 'a.exe'), 'parentImage': 'x', 'originalFileName': 'WinSCP.exe', 'product': 'AnyDesk'}, ['906140']),
            ('61603', {'image': p('Downloads', 'ngrok.exe'), 'parentImage': 'x'}, ['906176']),
            ('61603', {'image': b.join(['C:', 'Windows', 'SystemTemp', 'x', 't.exe']), 'parentImage': 'x'}, ['906104']),
            ('61603', {'image': p('OneDrive - Corp', 'Desktop', 't.exe'), 'parentImage': 'x'}, ['906100']),
            ('61617', {'targetFilename': p('Downloads', 'x.zip') + ':Zone.Identifier', 'contents': 'ZoneId=3'}, ['906122']),
            ('61617', {'targetFilename': p('AppData', 'Local', 'Temp', 'WinGet', 'x.exe') + ':Zone.Identifier', 'contents': 'ZoneId=3'}, ['906123']),
            ('61617', {'targetFilename': p('Downloads', 'x.exe'), 'contents': ''}, []),
            ('61613', {'image': b.join(['C:', 'Windows', 'System32', 'OpenSSH', 'sftp-server.exe']), 'targetFilename': p('Downloads', 'x.exe')}, ['906124']),
            ('61613', {'image': b.join(['C:', 'Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe']), 'targetFilename': p('Downloads', 'x.exe')}, []),
            ('92213', {'targetFilename': p('AppData', 'Local', 'Temp', 'cfg.json')}, ['906167']),
            ('92213', {'targetFilename': p('AppData', 'Local', 'Temp', 'drop.exe')}, []),
            ('92213', {'targetFilename': p('AppData', 'Local', 'Temp', 'nsdNC.tmp', 'System.dll'),
                       'image': 'setup.exe'}, ['906125']),
            ('92213', {'targetFilename': p('AppData', 'Local', 'Temp', 'b0rvrt0j.dll'),
                       'image': b.join(['C:', 'Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe'])}, ['906126']),
            ('92213', {'targetFilename': p('AppData', 'Local', 'Temp', 'b0rvrt0j.dll'), 'image': 'evil.exe'}, []),
            ('61600', {'eventID': '29', 'image': 'explorer.exe', 'targetFilename': p('Downloads', 'test.pdf')}, ['906183']),
            ('61600', {'eventID': '29', 'image': b.join(['C:', 'Windows', 'System32', 'OpenSSH', 'sftp-server.exe']), 'targetFilename': p('Downloads', 'x.exe')}, ['906181']),
            ('61600', {'eventID': '29', 'image': 'explorer.exe', 'targetFilename': b.join(['E:', 'x.exe'])}, ['906182']),
            ('61600', {'eventID': '29', 'image': 'chrome.exe', 'targetFilename': p('Downloads', 'Unconfirmed 1.crdownload')}, ['906180']),
            ('60601', {'providerName': 'jt-channel-watchdog', 'eventID': '100'}, ['906190']),
            ('60601', {'providerName': 'SomeApp', 'eventID': '100'}, []),
            ('60602', {'providerName': 'jt-channel-watchdog', 'eventID': '101'}, ['906191']),
        ]
        for parent, ev, want in cases:
            with self.subTest(parent=parent, event=ev):
                got = finals(parent, ev)
                if parent == '61600' and not got and matches('906180', ev):
                    got = ['906180']
                self.assertEqual(got, want)

    def test_rules_using_if_group_load_after_the_builtin_ruleset(self):
        """<if_group> only attaches to rules already loaded, and rule files load in
        filename order across the built-in and custom directories. jt-ioc's
        01-906000-... sorts before 0595-win-sysmon, and analysisd answered "Group
        'sysmon_event3' was not found ... will be ignored"."""
        import xml.etree.ElementTree as ET
        for _, m in self.packs:
            provided = set()        # groups the pack's own earlier rules carry
            rule_files = sorted((os.path.basename(e['dest']), e['name']) for e in m['files']
                                if e['type'] == 'rule')
            for dest, name in rule_files:
                with io.open(os.path.join(self._pack_dir_of(m), 'rules', name), encoding='utf-8') as fh:
                    root = ET.fromstring('<r>' + fh.read() + '</r>')
                for rule in root.iter('rule'):
                    for el in rule.iter('if_group'):
                        group = el.text.strip()
                        if group in provided:
                            continue    # attaches to this pack's own rules, loaded earlier
                        with self.subTest(file=name, group=group):
                            # every built-in file is named 0NNN-...; anything
                            # sorting after '0999' loads after all of them
                            self.assertGreater(dest, '0999')
                    for el in rule.iter('group'):
                        provided.update(g for g in el.text.split(',') if g)

    def test_agent_ignore_patterns_are_plain_os_match(self):
        """syscheck <ignore type="sregex"> is OS_Match: only ^ $ | ! are special.
        Brackets, parentheses or backslashes there are matched literally."""
        for dirpath, _, names in os.walk(self.packs_dir):
            for n in names:
                if not n.endswith('.conf'):
                    continue
                with io.open(os.path.join(dirpath, n), encoding='utf-8') as fh:
                    body = re.sub(r'<!--.*?-->', '', fh.read(), flags=re.S)
                for pat in re.findall(r'<ignore type="sregex">([^<]*)</ignore>', body):
                    with self.subTest(file=n, pattern=pat):
                        self.assertNotRegex(pat, r'[\\()\[\]]')

    def test_powershell_scripts_are_ascii(self):
        """Windows PowerShell 5.1 reads a script without a byte-order mark in the
        system code page, so one non-ASCII character in a shipped .ps1 is decoded
        differently on a Chinese or Japanese Windows than on an English one."""
        for dirpath, _, names in os.walk(self.packs_dir):
            for n in names:
                if n.endswith('.ps1'):
                    with self.subTest(file=n):
                        with io.open(os.path.join(dirpath, n), 'rb') as fh:
                            data = fh.read()
                        self.assertTrue(all(b < 0x80 for b in data))

    def test_index_matches_the_catalogue_on_disk(self):
        index_path = os.path.join(self.packs_dir, 'INDEX')
        if not os.path.isfile(index_path):
            self.skipTest('no INDEX file')
        with io.open(index_path, encoding='utf-8') as fh:
            listed = sorted(l.strip() for l in fh if l.strip())
        actual = []
        for dirpath, _, names in os.walk(self.packs_dir):
            for n in names:
                if n == 'INDEX':
                    continue
                rel = os.path.relpath(os.path.join(dirpath, n), os.path.dirname(self.packs_dir))
                actual.append(rel)
        self.assertEqual(listed, sorted(actual))


class TestPreflightPrivacyPattern(unittest.TestCase):
    """The pre-release privacy check is what stops a real address being published.

    A regex that quietly stops matching would fail open, so the pattern is
    pinned here rather than only being exercised by running the tool.
    """

    @classmethod
    def setUpClass(cls):
        import importlib.util
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root, 'tools', 'preflight.py')
        if not os.path.isfile(path):
            raise unittest.SkipTest('tools/preflight.py not present')
        spec = importlib.util.spec_from_file_location('preflight', path)
        cls.pf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.pf)

    def _flags(self, value):
        m = self.pf.INTERNAL.search(value)
        return bool(m) and not self.pf.PLACEHOLDER.match(m.group(0))

    def test_flags_real_private_addresses_and_hosts(self):
        for value in ('192.168.1.164', '10.20.30.40', '172.16.5.9',   # preflight:allow-example
                      'dnsp1', 'edr1', 'someone@realdomain.tw'):      # preflight:allow-example
            with self.subTest(value=value):
                self.assertTrue(self._flags(value), '%s should be flagged' % value)

    def test_leaves_documentation_placeholders_alone(self):
        for value in ('192.168.1.100', '192.168.1.1', '10.0.0.50',
                      'you@example.com', 'agent-example'):
            with self.subTest(value=value):
                self.assertFalse(self._flags(value), '%s should not be flagged' % value)

    def test_version_strings_are_not_mistaken_for_addresses(self):
        """Zimbra jars carry names like 10.1.20.1762506875."""
        for value in ('10.1.20', '10.1.20.1762506875', '10.745.688',
                      'zm-taglib-10.1.17.1762506875.jar'):
            with self.subTest(value=value):
                self.assertFalse(self._flags(value), '%s should not be flagged' % value)


if __name__ == '__main__':
    unittest.main(verbosity=2)


class TestAlertDigest(unittest.TestCase):
    """The jt-alert-digest script, which is shipped but is not part of the app.

    Three of its properties are the kind that break silently. A subject line
    that acquires one non-ASCII character becomes a MIME encoded word, which
    some clients show to the reader verbatim; that is what the format was
    replacing. A group heading built from the first alert's description puts
    one alert's address into a heading covering a dozen. And an alert field is
    attacker-influenced text going into HTML.
    """

    @classmethod
    def setUpClass(cls):
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'packs', 'jt-alert-digest', 'scripts', 'jt-alert-digest.py')
        if not os.path.isfile(path):
            raise unittest.SkipTest('jt-alert-digest is not present')
        spec = importlib.util.spec_from_file_location('jt_alert_digest', path)
        cls.mod = importlib.util.module_from_spec(spec)
        # Importing from inside packs/ would leave a __pycache__ directory
        # there, which packs/INDEX then disagrees with. The pack ships source,
        # so nothing is gained by caching the bytecode.
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec.loader.exec_module(cls.mod)
        finally:
            sys.dont_write_bytecode = previous

    def _group(self, level, descriptions, count=1):
        return {'level': level, 'descriptions': list(descriptions), 'mitre': [],
                'count': count, 'first': '2026-01-02T03:04:05.000+0000',
                'last': '2026-01-02T03:04:09.000+0000', 'samples': []}

    def test_subject_is_plain_ascii(self):
        groups = {('100973', 'mail2'): self._group(
            14, ['[HIGH] Account read an extreme volume — café 中文'])}
        line = self.mod.subject(groups, 1)
        line.encode('ascii')          # raises if anything non-ASCII survived

    def test_subject_drops_the_severity_marker_the_badge_already_carries(self):
        groups = {('1', 'h'): self._group(12, ['[HIGH] Something happened'])}
        self.assertNotIn('[HIGH]', self.mod.subject(groups, 1))

    def test_group_heading_keeps_only_what_the_whole_group_shares(self):
        # Wazuh interpolates $(field), so every alert's description differs.
        prefix = self.mod.shared_prefix([
            '[HIGH] Malicious remote address: 10.0.0.1',
            '[HIGH] Malicious remote address: 10.0.0.2',
        ])
        self.assertIn('Malicious remote address', prefix)
        self.assertNotIn('10.0.0.1', prefix)
        self.assertNotIn('10.0.0.2', prefix)

    def test_a_single_alert_keeps_its_whole_description(self):
        self.assertEqual(self.mod.shared_prefix(['[HIGH] One specific thing']),
                         'One specific thing')

    def test_alert_content_is_escaped_into_the_html(self):
        alert = {'rule': {'id': '1', 'level': 12, 'description': 'x'},
                 'agent': {'name': 'h'}, 'timestamp': '2026-01-02T03:04:05.000+0000',
                 'full_log': '<script>alert(1)</script>'}
        group = self._group(12, ['x'])
        group['samples'] = [alert]
        html = self.mod.render_html({('1', 'h'): group}, 1, 12, None)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)

    def test_every_group_names_its_host_with_address_and_agent_id(self):
        """A reader asked which machine a message was about: the agent name sat in
        small grey capitals inside the level line, with no address at all."""
        import tempfile
        alert = {'rule': {'id': '100807', 'level': 12, 'description': 'Web artefact'},
                 'agent': {'id': '047', 'name': 'dev1', 'ip': '192.0.2.86'},
                 'timestamp': '2026-10-05T14:59:34.000+0800'}
        with tempfile.TemporaryDirectory() as d:
            alerts, state = os.path.join(d, 'alerts.json'), os.path.join(d, 'state')
            with io.open(alerts, 'w', encoding='utf-8') as fh:
                fh.write(json.dumps(alert) + '\n')
            with io.open(state, 'w', encoding='utf-8') as fh:
                fh.write('0')
            groups, total, _ = self.mod.collect(alerts, state, 12)
        html = self.mod.render_html(groups, total, 12, None)
        text = self.mod.render_text(groups, total, 12, None)
        for out in (html, text):
            self.assertIn('dev1', out)
            self.assertIn('192.0.2.86', out)
            self.assertIn('agent 047', out)
        self.assertIn('Host: dev1 (192.0.2.86, agent 047)', text)
        self.assertIn('hosts: dev1', text)

    def test_ids_alerts_are_summarised_not_dumped(self):
        """A Suricata alert printed its whole EVE JSON line as the only field."""
        alert = {'rule': {'id': '100621', 'level': 12, 'description': 'Suricata x'},
                 'agent': {'id': '044', 'name': 'fw', 'ip': '192.0.2.1'},
                 'timestamp': '2026-10-05T16:11:36.000+0800',
                 'full_log': '{"event_type":"alert","src_ip":"198.51.100.19"}',
                 'data': {'src_ip': '198.51.100.19', 'dest_ip': '203.0.113.251', 'proto': 'TCP',
                          'src_port': '4444', 'dest_port': '443', 'in_iface': 'igb2',
                          'alert': {'signature': 'ET EXPLOIT Something', 'action': 'allowed',
                                    'category': 'Attempted Administrator Privilege Gain'}}}
        fields = dict(self.mod.interesting_fields(alert))
        self.assertEqual(fields['Signature'], 'ET EXPLOIT Something')
        self.assertEqual(fields['Flow'], '198.51.100.19:4444  ->  203.0.113.251:443  TCP')
        self.assertIn('allowed', fields['Action'])
        self.assertNotIn('Log', fields)

    def test_long_values_wrap_inside_the_card(self):
        """An unbroken JSON log widened the table past the card: word-break in a
        cell is ignored under the automatic table layout."""
        alert = {'rule': {'id': '1', 'level': 12, 'description': 'x'},
                 'agent': {'name': 'h'}, 'timestamp': '2026-01-02T03:04:05.000+0000',
                 'full_log': '{"k":"' + 'v' * 400 + '"}'}
        group = self._group(12, ['x'])
        group['samples'] = [alert]
        html = self.mod.render_html({('1', 'h'): group}, 1, 12, None)
        self.assertIn('table-layout:fixed', html)
        self.assertIn('overflow-wrap:anywhere', html)

    def test_plain_text_alternative_does_not_pad_into_columns(self):
        # Column alignment is what every mail client's rewrapping destroys.
        alert = {'rule': {'id': '1', 'level': 12, 'description': 'x'},
                 'agent': {'name': 'h'}, 'timestamp': '2026-01-02T03:04:05.000+0000',
                 'data': {'srcip': '10.0.0.1'}}
        group = self._group(12, ['x'])
        group['samples'] = [alert]
        text = self.mod.render_text({('1', 'h'): group}, 1, 12, None)
        self.assertIn('Source: 10.0.0.1', text)
