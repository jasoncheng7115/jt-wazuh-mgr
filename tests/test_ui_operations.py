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


if __name__ == '__main__':
    unittest.main()
