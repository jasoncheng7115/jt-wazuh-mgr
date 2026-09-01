#!/usr/bin/env python3
"""Coverage for the operational half of the UI: agents, groups, nodes, packs.

test_web_ui.py grew up around the read paths -- rules, decoders, CDB lists,
search. The routes that *change* something were largely untested, which is the
wrong way round: a guard nobody tests is one refactor away from being gone, and
these are the routes that restart nodes, rewrite ossec.conf and delete files.

Two rules hold throughout, both about not damaging the machine running the tests:

  - The Wazuh API is mocked by WebUITestCase, so no request leaves the process.
  - Several handlers shell out or touch the filesystem *after* their validation
    passes. Those are exercised only along the rejection path, which returns
    before any of that happens. Where a success path is asserted, it is one that
    reaches nothing but the mocked API.

The route-guard test derives its list from the app's own url_map rather than a
hand-written one, so a route added later is covered without anyone remembering.
"""

import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import lib.web_ui as web_ui  # noqa: E402
from test_web_ui import WebUITestCase  # noqa: E402


# Stand-in values for URL parameters, chosen to be valid so that a route which
# rejects them would be failing for the wrong reason.
PARAM_VALUES = {
    'agent_id': '001', 'name': 'default', 'filename': 'agent.conf',
    'file_type': 'config', 'pack_id': 'jt-ioc', 'username': 'wazuh',
    'category': 'ossec', 'log_type': 'current', 'rule_id': '100500',
    'group_name': 'default', 'node_name': 'node01',
}

# Routes that must stay reachable without a session, for obvious reasons.
PUBLIC_ROUTES = {'/login', '/logout', '/static/<path:filename>', '/images/<path:filename>'}


def concrete_path(rule):
    """Turn '/api/agents/<agent_id>/key' into '/api/agents/001/key'."""
    path = rule.rule

    def sub(m):
        arg = m.group(0).strip('<>').split(':')[-1]
        return PARAM_VALUES.get(arg, 'x')

    return re.sub(r'<[^>]+>', sub, path)


class TestEveryRouteRequiresSession(unittest.TestCase):
    """No route may serve data to a caller without a session.

    Derived from url_map, so this keeps holding as routes are added. The check
    that matters is the negative one: not "did we remember to test /api/foo"
    but "is there any route at all that answers an anonymous caller".
    """

    def test_no_route_answers_an_anonymous_caller(self):
        app = web_ui.create_app()
        app.config['TESTING'] = True
        client = app.test_client()
        checked = 0

        for rule in app.url_map.iter_rules():
            if rule.endpoint == 'static' or rule.rule in PUBLIC_ROUTES:
                continue
            methods = sorted(rule.methods - {'HEAD', 'OPTIONS'})
            for method in methods:
                path = concrete_path(rule)
                with self.subTest(method=method, path=path):
                    resp = getattr(client, method.lower())(path)
                    if rule.rule.startswith('/api/'):
                        self.assertEqual(
                            resp.status_code, 401,
                            '%s %s answered an anonymous caller with %d'
                            % (method, path, resp.status_code))
                    else:
                        # Page routes redirect to the login form instead.
                        self.assertIn(resp.status_code, (301, 302, 401))
                    checked += 1

        # A guard against this test silently covering nothing, which is how a
        # loop over an empty list passes forever.
        self.assertGreater(checked, 60, 'expected the app to expose more routes')


class TestGroupOperations(WebUITestCase):
    """Group routes take the group name straight from the URL."""

    BAD_NAMES = ['..', '../etc', 'a/b', 'a;rm -rf /', 'a b', 'a$(id)', 'a|b', '', 'x' * 129]

    def test_group_routes_reject_unsafe_names(self):
        for name in self.BAD_NAMES:
            if not name:
                continue  # an empty segment does not route
            for method, suffix in [('get', '/config'), ('put', '/config'),
                                   ('get', '/files'), ('post', '/agents'),
                                   ('delete', '/agents'), ('post', '/move'),
                                   ('post', '/exclusive'), ('get', '/config/download')]:
                path = '/api/groups/%s%s' % (name, suffix)
                with self.subTest(name=name, path=path):
                    resp = getattr(self.client, method)(
                        path, json={}, content_type='application/json')
                    self.assertNotEqual(
                        resp.status_code, 200,
                        'unsafe group name %r was accepted by %s' % (name, path))

    def test_group_file_read_rejects_traversal(self):
        for filename in ['../ossec.conf', '..%2fossec.conf', 'a/../../etc/passwd',
                         'agent.conf;id', 'agent conf']:
            with self.subTest(filename=filename):
                resp = self.client.get('/api/groups/default/files/%s' % filename)
                self.assertNotEqual(resp.status_code, 200)

    def test_group_file_read_accepts_a_plain_name(self):
        """The rejections above must come from validation, not from everything failing."""
        real = web_ui.WazuhAPISession.request_raw
        web_ui.WazuhAPISession.request_raw = lambda *a, **k: (True, '<agent_config/>')
        try:
            resp = self.client.get('/api/groups/default/files/agent.conf')
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.get_json()['filename'], 'agent.conf')
        finally:
            web_ui.WazuhAPISession.request_raw = real

    def test_group_agent_membership_validates_agent_ids(self):
        for bad in ['abc', '1;id', '../1', '9999999', '-1']:
            with self.subTest(agent=bad):
                resp = self.client.post('/api/groups/default/agents',
                                        json={'agent_ids': [bad]})
                self.assertNotEqual(resp.status_code, 200,
                                    'agent id %r was accepted' % bad)


class TestNodeOperations(WebUITestCase):
    """Node routes reach subprocess and the filesystem, so their guards matter most."""

    BAD_NAMES = ['..', '../..', 'a/b', 'node;id', 'node$(id)', 'node|id', 'a b', 'x' * 129]

    def test_node_routes_reject_unsafe_names(self):
        for name in self.BAD_NAMES:
            for method, suffix in [('get', '/config'), ('put', '/config'),
                                   ('get', '/config/validate'), ('post', '/restart'),
                                   ('post', '/reconnect'), ('put', '/reload-ruleset'),
                                   ('get', '/daemon-stats'), ('get', '/logs-info'),
                                   ('get', '/sync-detail'), ('get', '/upgrade-files'),
                                   ('get', '/download/config')]:
                path = '/api/nodes/%s%s' % (name, suffix)
                with self.subTest(name=name, path=path):
                    resp = getattr(self.client, method)(
                        path, json={}, content_type='application/json')
                    self.assertNotEqual(
                        resp.status_code, 200,
                        'unsafe node name %r was accepted by %s' % (name, path))

    def test_node_file_download_is_limited_to_two_files(self):
        """The route serves files by keyword, never by path."""
        for file_type in ['passwd', '../../etc/passwd', 'ossec.conf', 'client.keys',
                          'cluster-key/../../etc/passwd']:
            with self.subTest(file_type=file_type):
                resp = self.client.get('/api/nodes/node01/download/%s' % file_type)
                self.assertNotEqual(resp.status_code, 200,
                                    'file type %r was served' % file_type)

    def test_upgrade_file_delete_rejects_traversal_and_non_wpk(self):
        for filename in ['../../etc/ossec.conf', 'a/b.wpk', '..\\x.wpk',
                         'notes.txt', 'x.wpk.sh', '.wpk']:
            with self.subTest(filename=filename):
                resp = self.client.delete(
                    '/api/nodes/node01/upgrade-files/%s' % filename)
                self.assertNotEqual(resp.status_code, 200,
                                    'filename %r was accepted for deletion' % filename)

    def test_node_log_route_rejects_unknown_categories(self):
        for category, log_type in [('../etc', 'current'), ('ossec', '../../passwd'),
                                   ('a;id', 'current')]:
            with self.subTest(category=category, log_type=log_type):
                resp = self.client.get('/api/nodes/node01/logs/%s/%s' % (category, log_type))
                self.assertNotEqual(resp.status_code, 200)


class TestDestructiveAgentOperations(WebUITestCase):
    """Queue DB cleaning deletes files and restarts agents."""

    def test_queue_db_clean_validates_every_agent_id(self):
        for bad in ['abc', '1;rm -rf /', '../../etc', '1234567', '']:
            with self.subTest(agent=bad):
                resp = self.client.post('/api/agents/queue-db/clean',
                                        json={'agent_ids': ['001', bad]})
                self.assertEqual(resp.status_code, 400,
                                 'agent id %r reached the delete path' % bad)

    def test_queue_db_clean_rejects_a_non_list_of_ids(self):
        resp = self.client.post('/api/agents/queue-db/clean', json={'agent_ids': '001'})
        # A bare string is iterable, so a careless implementation would treat it
        # as ['0','0','1'] and act on agent 0. It must not reach the delete path.
        self.assertNotEqual(resp.status_code, 200)

    def test_agent_key_route_validates_the_id(self):
        for bad in ['abc', '../000', '1;id']:
            with self.subTest(agent=bad):
                self.assertNotEqual(
                    self.client.get('/api/agents/%s/key' % bad).status_code, 200)


class TestPackInstallGuards(WebUITestCase):
    """Pack installation writes into the live ruleset, so its guards are load-bearing."""

    def test_unknown_pack_is_rejected(self):
        resp = self.client.post('/api/packs/no-such-pack/install', json={})
        self.assertEqual(resp.status_code, 404)

    def test_pack_id_cannot_escape_the_pack_directory(self):
        for pack_id in ['../../etc', '..', 'a/b', 'jt-ioc/../../../etc']:
            with self.subTest(pack_id=pack_id):
                resp = self.client.post('/api/packs/%s/install' % pack_id, json={})
                self.assertNotEqual(resp.status_code, 200)

    def test_manifest_destinations_are_confined_to_ruleset_directories(self):
        """Reached through the view's closure.

        _validate_dest is local to create_app, and the alternative -- driving a
        crafted manifest through the install route -- would write into the real
        ruleset of whatever machine runs the tests. This asserts the guard
        directly instead.
        """
        view = self.app.view_functions['install_pack']
        while hasattr(view, '__wrapped__'):  # login_required wraps it
            view = view.__wrapped__
        validate = None
        for name, cell in zip(view.__code__.co_freevars, view.__closure__ or ()):
            if name == '_validate_dest':
                validate = cell.cell_contents
        self.assertIsNotNone(validate, '_validate_dest is no longer a closure of install_pack')
        for bad in ['/etc/passwd', '../../etc/passwd', 'etc/../../x',
                    'var/ossec/x', 'etc/rules/../../../x']:
            self.assertFalse(validate(bad), '%r was accepted as a destination' % bad)
        for good in ['etc/rules/x.xml', 'etc/lists/x', 'etc/decoders/x.xml']:
            self.assertTrue(validate(good), '%r was rejected as a destination' % good)


class TestConfigurationEditing(WebUITestCase):
    """Config routes write ossec.conf, which can take a node out of service."""

    def test_node_config_put_rejects_an_empty_or_huge_body(self):
        for body in [{'content': ''}, {}, {'content': 'x' * (5 * 1024 * 1024)}]:
            with self.subTest(size=len(str(body))):
                resp = self.client.put('/api/nodes/node01/config', json=body)
                self.assertNotEqual(resp.status_code, 200)

    def test_group_config_put_rejects_malformed_xml(self):
        resp = self.client.put('/api/groups/default/config',
                               json={'content': '<agent_config><localfile>'})
        self.assertNotEqual(resp.status_code, 200)

    def test_group_config_put_rejects_an_external_entity(self):
        """XXE: a config editor that resolves entities reads any file it can open."""
        xxe = ('<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
               '<agent_config>&x;</agent_config>')
        resp = self.client.put('/api/groups/default/config', json={'content': xxe})
        body = resp.get_data(as_text=True)
        self.assertNotIn('root:', body, 'an external entity was resolved')


class TestReadOnlyOperationalRoutes(WebUITestCase):
    """The remaining routes, checked for shape rather than behaviour."""

    def test_routes_answer_a_logged_in_caller(self):
        for path in ['/api/settings', '/api/stats/summary', '/api/nodes/services',
                     '/api/nodes/sync-status', '/api/agents/queue-size']:
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertIn(resp.status_code, (200, 500),
                              '%s returned %d' % (path, resp.status_code))
                if resp.status_code == 200:
                    self.assertEqual(resp.mimetype, 'application/json')

    def test_settings_never_returns_a_credential(self):
        resp = self.client.get('/api/settings')
        if resp.status_code != 200:
            self.skipTest('settings unavailable in this environment')
        body = json.dumps(resp.get_json()).lower()
        for leak in ['password', 'passwd', 'secret', 'token', 'api_key']:
            self.assertNotIn('"%s"' % leak, body,
                             'the settings response carries a %s field' % leak)


def closure_var(func, name, _depth=0):
    """Find a function defined inside create_app, by name, through the closures.

    The pack helpers are locals of create_app rather than module attributes, so
    the alternative would be driving them through the install route -- which
    writes into the real ruleset of whatever machine runs the tests.
    """
    while hasattr(func, '__wrapped__'):
        func = func.__wrapped__
    if _depth > 3 or not hasattr(func, '__code__'):
        return None
    pairs = list(zip(func.__code__.co_freevars, func.__closure__ or ()))
    for var, cell in pairs:
        if var == name:
            try:
                return cell.cell_contents
            except ValueError:
                return None
    for var, cell in pairs:
        try:
            inner = cell.cell_contents
        except ValueError:
            continue
        if callable(inner) and hasattr(inner, '__code__'):
            found = closure_var(inner, name, _depth + 1)
            if found is not None:
                return found
    return None


OSSEC_CONF = """<ossec_config>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
  </ruleset>
</ossec_config>
"""


class TestClusterListDeclaration(WebUITestCase):
    """A CDB list declaration has to reach every node, or the pack half works.

    The cluster synchronises etc/rules, etc/decoders and etc/lists, but ossec.conf
    is in its excluded_files. A rule pointing at a list the node has not declared
    is ignored silently, and workers are where agent events are processed.
    """

    def setUp(self):
        super().setUp()
        self.apply = closure_var(self.app.view_functions['install_pack'],
                                 '_apply_list_declarations')
        self.assertIsNotNone(self.apply, '_apply_list_declarations not reachable')

    def test_declaration_is_added_once_and_is_idempotent(self):
        out = self.apply(OSSEC_CONF, ['etc/lists/jason_tools_threat_ip'])
        self.assertIn('<list>etc/lists/jason_tools_threat_ip</list>', out)
        self.assertEqual(out.count('<list>etc/lists/jason_tools_threat_ip</list>'), 1)
        again = self.apply(out, ['etc/lists/jason_tools_threat_ip'])
        self.assertEqual(again, out, 'declaring twice changed the file a second time')

    def test_declaration_keeps_the_indentation_of_its_neighbours(self):
        out = self.apply(OSSEC_CONF, ['etc/lists/x'])
        line = [ln for ln in out.split('\n') if 'etc/lists/x' in ln][0]
        self.assertTrue(line.startswith('    <list>'), repr(line))

    def test_declaration_is_removed_cleanly(self):
        added = self.apply(OSSEC_CONF, ['etc/lists/x'])
        removed = self.apply(added, ['etc/lists/x'], remove=True)
        self.assertEqual(removed, OSSEC_CONF)

    def test_existing_declarations_are_left_alone(self):
        out = self.apply(OSSEC_CONF, ['etc/lists/audit-keys'])
        self.assertEqual(out, OSSEC_CONF)

    def test_a_config_without_a_ruleset_block_is_not_mangled(self):
        plain = '<ossec_config>\n  <global><jsonout_output>yes</jsonout_output></global>\n</ossec_config>\n'
        self.assertEqual(self.apply(plain, ['etc/lists/x']), plain)


class TestPeerDeclaration(WebUITestCase):
    """The declaration is pushed to peers over the API, not over SSH.

    SSH would require the operator to have configured node keys first, which a
    pack install cannot assume.
    """

    NODES = [{'name': 'node-01', 'type': 'master'}, {'name': 'node-02', 'type': 'worker'}]

    def _install_api(self, put_ok=True, writes_take_effect=True):
        """A cluster whose worker configuration is stateful.

        A fake that always returns the original text would make the read-back
        check fail for the wrong reason, and would never exercise the case this
        check exists for: a node that accepts the upload without applying it.
        """
        calls = []
        stored = {}

        def fake_raw(_self, method, endpoint, body=None, params=None,
                     content_type='application/octet-stream'):
            calls.append((method, endpoint, body))
            node = endpoint.split('/')[2]
            if method == 'GET':
                return True, stored.get(node, OSSEC_CONF)
            if not put_ok:
                return False, 'permission denied'
            if writes_take_effect:
                stored[node] = body
            return True, 'ok'

        self._real_raw = web_ui.WazuhAPISession.request_raw
        self._real_nodes = web_ui.WazuhAPISession.get_nodes
        web_ui.WazuhAPISession.request_raw = fake_raw
        web_ui.WazuhAPISession.get_nodes = lambda _self: self.NODES
        self.addCleanup(setattr, web_ui.WazuhAPISession, 'request_raw', self._real_raw)
        self.addCleanup(setattr, web_ui.WazuhAPISession, 'get_nodes', self._real_nodes)
        return calls

    def _peers_fn(self):
        fn = closure_var(self.app.view_functions['install_pack'], '_declare_lists_on_peers')
        self.assertIsNotNone(fn, '_declare_lists_on_peers not reachable')
        return fn

    def test_the_master_is_not_written_to_over_the_api(self):
        """The tool runs on the master, whose file it edits directly."""
        calls = self._install_api()
        with self.app.test_request_context():
            with self.client.session_transaction():
                pass
            originals, failures = self._run(self._peers_fn(), ['etc/lists/x'])
        self.assertEqual(failures, [])
        endpoints = [c[1] for c in calls]
        self.assertTrue(all('node-01' not in e for e in endpoints),
                        'the master was written to over the API: %s' % endpoints)
        self.assertTrue(any('node-02' in e for e in endpoints),
                        'the worker was never written to: %s' % endpoints)
        self.assertIn('node-02', originals)

    def test_a_failing_peer_is_reported_rather_than_ignored(self):
        self._install_api(put_ok=False)
        with self.app.test_request_context():
            originals, failures = self._run(self._peers_fn(), ['etc/lists/x'])
        self.assertTrue(failures, 'a peer that refused the write reported success')
        self.assertEqual(failures[0]['node'], 'node-02')
        self.assertIn('permission denied', failures[0]['error'])
        self.assertIn('over SSH', failures[0]['error'],
                      'the SSH fallback was not attempted or not reported')
        self.assertEqual(originals, {}, 'a failed write was recorded as rollback state')

    def test_a_write_that_does_not_take_effect_is_caught(self):
        """A 200 from the API means accepted, not applied."""
        self._install_api(writes_take_effect=False)
        with self.app.test_request_context():
            originals, failures = self._run(self._peers_fn(), ['etc/lists/x'])
        self.assertTrue(failures, 'a write that never landed was reported as success')
        self.assertIn('still not in place', failures[0]['error'])
        self.assertIn('node-02', originals,
                      'the node was changed, so it must be restorable')

    def test_declaring_twice_sends_no_second_write(self):
        calls = self._install_api()
        with self.app.test_request_context():
            self._run(self._peers_fn(), ['etc/lists/x'])
            before = len([c for c in calls if c[0] == 'PUT'])
            self._run(self._peers_fn(), ['etc/lists/x'])
            after = len([c for c in calls if c[0] == 'PUT'])
        self.assertEqual(before, after, 'a redundant declaration was written again')

    def test_nothing_is_sent_when_the_pack_declares_no_list(self):
        calls = self._install_api()
        with self.app.test_request_context():
            originals, failures = self._run(self._peers_fn(), [])
        self.assertEqual((originals, failures, calls), ({}, [], []))

    def _run(self, fn, paths, remove=False):
        """Call the helper inside a request context with a logged-in session."""
        from flask import session as flask_session
        flask_session['api_session'] = {
            'host': 'localhost', 'port': 55000, 'username': 'tester',
            'token': 'fake-token', 'session_exp': 9999999999,
        }
        return fn(paths, remove=remove)


if __name__ == '__main__':
    unittest.main()
