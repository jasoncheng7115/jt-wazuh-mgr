"""The Wazuh dashboards shipped with the rule packs (packs/<id>/dashboards/).

Each file is OpenSearch Dashboards saved objects, imported into the Wazuh
dashboard with overwrite. What can go wrong without anyone noticing:

- a filter that also counts other rules' alerts (rule.id is a keyword, so a
  plain range on it is a text range: "10051" sorts inside 100500-100599);
- an object id that changes between builds, so an import adds a second copy
  instead of replacing the first and a removal misses it;
- a reference to anything but the index pattern the Wazuh dashboard creates;
- a standard visualization on a field the alerts template does not map, which
  renders as "Could not locate that index-pattern-field" until an alert with
  that field has been indexed (verified on OpenSearch Dashboards 2.19.6);
- a committed file that no longer matches its manifest.
"""

import bisect
import glob
import importlib.util
import io
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKS_DIR = os.path.join(ROOT, 'packs')
INDEX_PATTERN_ID = 'wazuh-alerts-*'


def load_builder():
    path = os.path.join(ROOT, 'tools', 'build_pack_dashboards.py')
    spec = importlib.util.spec_from_file_location('build_pack_dashboards', path)
    mod = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = previous
    return mod


# ---- an evaluator for the rule filter, with OpenSearch's semantics on a keyword
#
# A range query on a keyword walks the sorted term dictionary: it selects the
# terms between the two bounds in byte order. A regexp query must match the
# whole term. Rule ids are 1 to 999999 and Wazuh writes them without leading
# zeros, so the universe of terms is str(1) .. str(999999), sorted as text.

UNIVERSE = None
BY_LENGTH = {}


def universe():
    global UNIVERSE
    if UNIVERSE is None:
        UNIVERSE = sorted(str(i) for i in range(1, 1000000))
    return UNIVERSE


TOKEN = re.compile(r'\s*(?:(\()|(\))|(AND)\b|(OR)\b|rule\.id:\[(\d+) TO (\d+)\]|rule\.id:/\[0-9\]\{(\d+)\}/)')


def tokenize(query):
    pos, out = 0, []
    query = query.strip()
    while pos < len(query):
        m = TOKEN.match(query, pos)
        if not m or m.end() == pos:
            raise ValueError('unexpected text at %d: %r' % (pos, query[pos:pos + 30]))
        if m.group(1):
            out.append(('(',))
        elif m.group(2):
            out.append((')',))
        elif m.group(3):
            out.append(('AND',))
        elif m.group(4):
            out.append(('OR',))
        elif m.group(5):
            out.append(('range', m.group(5), m.group(6)))
        else:
            out.append(('len', int(m.group(7))))
        pos = m.end()
    return out


def evaluate(tokens):
    """Set of rule ids (strings) the query selects. Lucene's classic parser has
    no real precedence between AND and OR, so a group mixing them without
    parentheses is rejected rather than guessed."""
    terms = universe()

    def atom(i):
        tok = tokens[i]
        if tok[0] == '(':
            value, i = group(i + 1)
            if tokens[i][0] != ')':
                raise ValueError('unbalanced parentheses')
            return value, i + 1
        if tok[0] == 'range':
            lo, hi = bisect.bisect_left(terms, tok[1]), bisect.bisect_right(terms, tok[2])
            return set(terms[lo:hi]), i + 1
        if tok[0] == 'len':
            if tok[1] not in BY_LENGTH:
                BY_LENGTH[tok[1]] = frozenset(t for t in terms if len(t) == tok[1])
            return BY_LENGTH[tok[1]], i + 1
        raise ValueError('unexpected %r' % (tok,))

    def group(i):
        value, i = atom(i)
        op = None
        while i < len(tokens) and tokens[i][0] in ('AND', 'OR'):
            if op and tokens[i][0] != op:
                raise ValueError('AND and OR mixed without parentheses')
            op = tokens[i][0]
            other, i = atom(i + 1)
            value = (value & other) if op == 'AND' else (value | other)
        return value, i

    value, i = group(0)
    if i != len(tokens):
        raise ValueError('trailing tokens')
    return value


def expected_ids(declared):
    parts = declared if isinstance(declared, list) else [declared]
    out = set()
    for part in parts:
        lo, hi = (int(x) for x in part.split('-'))
        out |= {str(i) for i in range(lo, hi + 1)}
    return out


class TestRuleFilterEvaluator(unittest.TestCase):
    """The evaluator is only worth something if it shows the naive filter wrong."""

    def test_a_plain_text_range_is_wrong_on_keywords(self):
        got = evaluate(tokenize('rule.id:[100500 TO 100599]'))
        self.assertIn('10051', got)          # rule 10051 sorts between the bounds
        self.assertIn('10059', got)
        self.assertNotIn('1005', got)        # a prefix sorts before the lower bound
        self.assertNotEqual(got, expected_ids('100500-100599'))

    def test_the_length_clause_makes_it_exact(self):
        builder = load_builder()
        for declared in ('100500-100599', ['100800-100999', '133300-133399'], '5-1200', '99990-100010'):
            with self.subTest(declared=declared):
                self.assertEqual(evaluate(tokenize(builder.rule_query(declared))), expected_ids(declared))


class TestPackDashboards(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.builder = load_builder()
        cls.fields = cls.builder.template_fields()
        cls.packs = []
        for mf in sorted(glob.glob(os.path.join(PACKS_DIR, '*', 'manifest.json'))):
            with io.open(mf, encoding='utf-8') as fh:
                m = json.load(fh)
            path = os.path.join(os.path.dirname(mf), 'dashboards', m['id'] + '.ndjson')
            objects = []
            if os.path.isfile(path):
                with io.open(path, encoding='utf-8') as fh:
                    objects = [json.loads(line) for line in fh if line.strip()]
            cls.packs.append((m, path, objects))
        if not cls.packs:
            raise unittest.SkipTest('no packs/ catalogue in this checkout')

    def test_the_field_list_is_the_alerts_template(self):
        for name, kind in (('rule.id', 'keyword'), ('rule.level', 'long'), ('rule.description', 'keyword'),
                           ('agent.name', 'keyword'), ('data.srcip', 'keyword'),
                           ('data.dstuser', 'keyword'), ('timestamp', 'date')):
            with self.subTest(field=name):
                self.assertEqual(self.fields.get(name), kind)
        self.assertGreater(len(self.fields), 500)

    def test_every_pack_ships_a_dashboard_that_matches_the_generator(self):
        for m, path, _ in self.packs:
            with self.subTest(pack=m['id']):
                self.assertTrue(os.path.isfile(path), 'missing %s; run tools/build_pack_dashboards.py' % path)
                with io.open(path, encoding='utf-8') as fh:
                    committed = fh.read()
                self.assertEqual(committed, self.builder.build(m['id'], self.fields),
                                 'stale; run tools/build_pack_dashboards.py')

    def test_the_build_is_deterministic(self):
        for m, _, _ in self.packs[:5]:
            with self.subTest(pack=m['id']):
                self.assertEqual(self.builder.build(m['id']), self.builder.build(m['id']))

    def test_every_line_parses_and_the_embedded_json_too(self):
        for m, _, objects in self.packs:
            with self.subTest(pack=m['id']):
                self.assertTrue(objects)
                types = [o['type'] for o in objects]
                self.assertEqual(types.count('dashboard'), 1)
                self.assertEqual(types.count('search'), 1)
                self.assertTrue(set(types) <= {'dashboard', 'search', 'visualization'})
                for o in objects:
                    a = o['attributes']
                    for key in ('visState', 'uiStateJSON', 'panelsJSON', 'optionsJSON'):
                        if key in a:
                            json.loads(a[key])
                    json.loads(a['kibanaSavedObjectMeta']['searchSourceJSON'])
                    if o['type'] == 'visualization' and json.loads(a['visState'])['type'] == 'vega':
                        json.loads(json.loads(a['visState'])['params']['spec'])

    def test_object_ids_are_fixed_and_unique(self):
        seen = {}
        for m, _, objects in self.packs:
            for o in objects:
                with self.subTest(pack=m['id'], id=o['id']):
                    self.assertRegex(o['id'], r'^jt-pack-%s-[a-z0-9-]+$' % re.escape(m['id']))
                    self.assertNotIn(o['id'], seen)
                    seen[o['id']] = m['id']
            ids = {o['type']: o['id'] for o in objects if o['type'] != 'visualization'}
            self.assertEqual(ids.get('dashboard'), 'jt-pack-%s-dashboard' % m['id'])
            self.assertEqual(ids.get('search'), 'jt-pack-%s-search' % m['id'])

    def test_references_are_the_alerts_index_pattern_or_the_packs_own_objects(self):
        for m, _, objects in self.packs:
            own = {(o['type'], o['id']) for o in objects}
            for o in objects:
                with self.subTest(pack=m['id'], id=o['id']):
                    names = set()
                    for ref in o['references']:
                        names.add(ref['name'])
                        if ref['type'] == 'index-pattern':
                            self.assertEqual(ref['id'], INDEX_PATTERN_ID)
                        else:
                            self.assertIn((ref['type'], ref['id']), own)
                    source = json.loads(o['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])
                    self.assertNotIn('index', source, 'an index id inline instead of a reference')
                    if 'indexRefName' in source:
                        self.assertIn(source['indexRefName'], names)
                    if o['type'] == 'dashboard':
                        panels = json.loads(o['attributes']['panelsJSON'])
                        self.assertEqual(sorted(p['panelRefName'] for p in panels), sorted(names))
                        self.assertEqual(len(panels), len(objects) - 1, 'every object is on the dashboard')
                    vis = json.loads(o['attributes'].get('visState') or '{}')
                    if vis.get('type') == 'vega':
                        spec = json.loads(vis['params']['spec'])
                        self.assertEqual(spec['data']['url']['index'], INDEX_PATTERN_ID)

    def _queries(self, objects):
        for o in objects:
            source = json.loads(o['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])
            vis = json.loads(o['attributes'].get('visState') or '{}')
            if vis.get('type') == 'vega':
                spec = json.loads(vis['params']['spec'])
                must = spec['data']['url']['body']['query']['bool']['must']
                qs = [c['query_string']['query'] for c in must if isinstance(c, dict) and 'query_string' in c]
                self.assertEqual(len(qs), 1, o['id'])
                yield o['id'], qs[0]
            elif vis.get('type') == 'markdown' or o['type'] == 'dashboard':
                # no data of their own; the dashboard's query is left empty for the operator
                self.assertEqual(source['query']['query'], '', o['id'])
            else:
                self.assertEqual(source['query']['language'], 'lucene', o['id'])
                yield o['id'], source['query']['query']

    def test_every_panel_selects_exactly_the_packs_rule_ids(self):
        for m, _, objects in self.packs:
            want = expected_ids(m['rule_id_range'])
            checked = {}
            for oid, query in self._queries(objects):
                with self.subTest(pack=m['id'], object=oid):
                    if query not in checked:
                        checked[query] = evaluate(tokenize(query))
                    self.assertEqual(checked[query], want)
            self.assertEqual(len(checked), 1, 'one filter per pack')

    def _fields_used(self, objects):
        for o in objects:
            a = o['attributes']
            if o['type'] == 'search':
                for c in a['columns']:
                    yield o['id'], c, 'column'
                for s in a['sort']:
                    yield o['id'], s[0], 'sort'
                continue
            vis = json.loads(a.get('visState') or '{}')
            if vis.get('type') == 'vega':
                spec = json.loads(vis['params']['spec'])
                for agg in spec['data']['url']['body']['aggs'].values():
                    for body in agg.values():
                        yield o['id'], body['field'], 'vega'
                for clause in spec['data']['url']['body']['query']['bool']['must']:
                    if isinstance(clause, dict) and 'range' in clause:
                        for f in clause['range']:
                            yield o['id'], f, 'vega'
                continue
            for agg in vis.get('aggs', []):
                if 'field' in agg.get('params', {}):
                    yield o['id'], agg['params']['field'], 'agg'

    def test_every_field_is_in_the_wazuh_template_and_dynamic_ones_only_in_vega(self):
        for m, _, objects in self.packs:
            for oid, field, where in self._fields_used(objects):
                with self.subTest(pack=m['id'], object=oid, field=field):
                    kind = self.builder.field_kind(field, self.fields)
                    if where == 'agg':
                        # a standard visualization needs the field in the index
                        # pattern, which only template fields are from the start
                        self.assertEqual(kind, 'static')
                    if where == 'column' and kind == 'dynamic':
                        pass        # Discover shows an unknown column as "-", not an error

    def test_the_layout_fits_the_grid_without_overlap(self):
        for m, _, objects in self.packs:
            dash = [o for o in objects if o['type'] == 'dashboard'][0]
            cells = set()
            for p in json.loads(dash['attributes']['panelsJSON']):
                g = p['gridData']
                with self.subTest(pack=m['id'], panel=p['panelIndex']):
                    self.assertLessEqual(g['x'] + g['w'], 48)
                    for x in range(g['x'], g['x'] + g['w']):
                        for y in range(g['y'], g['y'] + g['h']):
                            self.assertNotIn((x, y), cells)
                            cells.add((x, y))

    def test_titles_name_the_pack_in_both_languages(self):
        for m, _, objects in self.packs:
            dash = [o for o in objects if o['type'] == 'dashboard'][0]
            with self.subTest(pack=m['id']):
                self.assertTrue(dash['attributes']['title'].startswith('jt · '))
                for o in objects:
                    if o['type'] != 'dashboard':
                        self.assertTrue(o['attributes']['title'].startswith(m['id'] + ' · '))

    def test_the_optional_manifest_section_is_well_formed(self):
        allowed = {'fields', 'columns', 'srcip', 'dstuser'}
        for m, _, _ in self.packs:
            opts = m.get('dashboard')
            if opts is None:
                continue
            with self.subTest(pack=m['id']):
                self.assertTrue(set(opts) <= allowed, sorted(set(opts) - allowed))
                for item in opts.get('fields', []):
                    item = {'field': item} if isinstance(item, str) else item
                    self.assertTrue(set(item) <= {'field', 'title', 'title_zh', 'size'})
                    self.builder.field_kind(item['field'], self.fields)
                    if 'title' in item:
                        self.assertTrue(item.get('title_zh'), 'a title needs title_zh too')
                for c in opts.get('columns', []):
                    self.builder.field_kind(c, self.fields)


if __name__ == '__main__':
    unittest.main()
