#!/usr/bin/env python3
"""Build a Wazuh dashboard for every rule pack.

    tools/build_pack_dashboards.py            write packs/<id>/dashboards/<id>.ndjson
    tools/build_pack_dashboards.py --check    exit 1 if a committed file is stale
    tools/build_pack_dashboards.py <id> ...   only these packs

Each file holds OpenSearch Dashboards saved objects (Wazuh dashboard 4.14.9 is
OpenSearch Dashboards 2.19.6): one dashboard, its visualizations and a saved
search, all limited to the pack's own alerts by its rule ID range(s). Import
with POST /api/saved_objects/_import?overwrite=true, or Dashboards Management
-> Saved objects -> Import.

The object ids are fixed (jt-pack-<id>-<part>), so importing a newer file
replaces the objects instead of adding copies, and a removal deletes exactly
these ids. The output is a pure function of the manifest: running it twice
gives byte-identical files, and tests/test_pack_dashboards.py fails when a
committed file no longer matches.

Every object points at the index pattern the Wazuh dashboard creates for
alerts: id "wazuh-alerts-*", time field "timestamp" (wazuh-dashboard-plugins
v4.14.9, plugins/main/public/react-services/saved-objects.js,
createWazuhIndexPattern). Nothing here creates or changes that index pattern.

The rule filter. rule.id is a keyword in the alerts template, so a range on
it compares text: rule.id:[100500 TO 100599] also matches "10051" (it sorts
between them). Wazuh rule ids have at most six digits, and between strings of
the same length the text order is the numeric order, so each range is
written as a text range AND a regular expression on the length:
    rule.id:[100500 TO 100599] AND rule.id:/[0-9]{6}/
A range whose ends differ in length is split per length.

Panels. Standard visualizations for fields the alerts template maps up front
(they are in every wazuh-alerts index from the moment it exists, so the index
pattern always knows them). A pack-specific field under data.* is mapped only
when the first alert carrying it is indexed, and a standard visualization on
a field the index pattern does not know yet fails to render ("Could not
locate that index-pattern-field"), which is how a freshly installed pack
would look. Those fields get a Vega chart instead: it queries the index
directly, follows the dashboard's time range, query and filters, and shows
an empty chart until there is data.

Optional manifest section, all keys optional:
    "dashboard": {
      "fields": [{"field": "data.attack_category", "title": "Attack category",
                  "title_zh": "攻擊類別", "size": 10}, ...],
      "columns": ["data.attack_category", ...],   # extra saved-search columns
      "srcip": true|false, "dstuser": true|false  # override the detection
    }
"""

import glob
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKS_DIR = os.path.join(ROOT, 'packs')
FIELDS_FILE = os.path.join(ROOT, 'tests', 'wazuh_alerts_fields_4.14.9.txt')

INDEX_PATTERN_ID = 'wazuh-alerts-*'
TIME_FIELD = 'timestamp'
INDEX_REF = 'kibanaSavedObjectMeta.searchSourceJSON.index'
MAX_RULE_ID_DIGITS = 6           # Wazuh rule ids are 1 to 999999
HIGH_LEVEL = 12                  # Wazuh's default email_alert_level

# Wazuh levels 0-15, light to dark: the same level has the same colour in
# every pack's dashboard.
LEVEL_COLOURS = {
    0: '#B9C2CC', 1: '#B9C2CC', 2: '#A2B0BF', 3: '#54B399', 4: '#6DCCB1',
    5: '#9AC7A0', 6: '#D6BF57', 7: '#E7C53A', 8: '#F1A44C', 9: '#EE8A3C',
    10: '#E7664C', 11: '#DA5A3B', 12: '#CC3D2E', 13: '#B42B21', 14: '#8F1D15',
    15: '#5E0E09',
}


# ---------------------------------------------------------------- the filter

def parse_ranges(declared):
    parts = declared if isinstance(declared, list) else [declared]
    out = []
    for part in parts:
        m = re.match(r'^(\d+)-(\d+)$', part or '')
        if not m:
            raise ValueError('rule_id_range entry %r is not "lo-hi"' % (part,))
        lo, hi = int(m.group(1)), int(m.group(2))
        if not 1 <= lo <= hi <= 10 ** MAX_RULE_ID_DIGITS - 1:
            raise ValueError('rule_id_range %r is outside 1-999999' % (part,))
        out.append((lo, hi))
    return out


def rule_query(declared):
    """Lucene query that selects exactly the rule ids in the declared range(s)."""
    by_length = {}
    for lo, hi in parse_ranges(declared):
        for digits in range(len(str(lo)), len(str(hi)) + 1):
            a, b = max(lo, 10 ** (digits - 1)), min(hi, 10 ** digits - 1)
            if a <= b:
                by_length.setdefault(digits, []).append('rule.id:[%d TO %d]' % (a, b))
    clauses = []
    for digits in sorted(by_length):
        ranges = by_length[digits]
        inner = ranges[0] if len(ranges) == 1 else '(%s)' % ' OR '.join(ranges)
        clauses.append('%s AND rule.id:/[0-9]{%d}/' % (inner, digits))
    if len(clauses) == 1:
        return clauses[0]
    return ' OR '.join('(%s)' % c for c in clauses)


# ------------------------------------------------------------ field handling

def template_fields():
    fields = {}
    with io.open(FIELDS_FILE, encoding='utf-8') as fh:
        for line in fh:
            if line.startswith('#') or not line.strip():
                continue
            name, kind = line.rstrip('\n').split('\t')
            fields[name] = kind
    return fields


def field_kind(name, fields):
    """'static' (mapped by the template), 'dynamic' (a data.* path the
    template's string_as_keyword dynamic template maps on first sight), or
    raises for a name no alert index can hold."""
    if name in fields:
        if fields[name] in ('text', 'geo_point'):
            raise ValueError('%s is a %s field and cannot be aggregated' % (name, fields[name]))
        return 'static'
    if not re.match(r'^data\.[A-Za-z0-9_.@-]+$', name) or '..' in name or name.endswith('.'):
        raise ValueError('%s is neither in the Wazuh alerts template nor under data.*' % name)
    parts = name.split('.')
    for i in range(1, len(parts)):
        prefix = '.'.join(parts[:i])
        if prefix in fields:
            raise ValueError('%s is under %s, a %s field' % (name, prefix, fields[prefix]))
    return 'dynamic'


SUBDIR = {'rule': 'rules', 'decoder': 'decoders', 'list': 'lists'}


def _pack_text(pdir, manifest, kind):
    for entry in manifest.get('files', []):
        if entry.get('type') == kind:
            path = os.path.join(pdir, SUBDIR[kind], entry['name'])
            with io.open(path, encoding='utf-8') as fh:
                yield re.sub(r'<!--.*?-->', '', fh.read(), flags=re.S)


def carries(pdir, manifest):
    """Whether the pack's alerts carry data.srcip / data.dstuser: its own
    decoders extract them, or its rules match on them (then the parent
    decoder extracts them). The manifest may override either answer."""
    decoders = '\n'.join(_pack_text(pdir, manifest, 'decoder'))
    rules = '\n'.join(_pack_text(pdir, manifest, 'rule'))
    order = set()
    for o in re.findall(r'<order>(.*?)</order>', decoders, re.S):
        order |= {x.strip() for x in o.split(',')}
    srcip = ('srcip' in order or re.search(r'<srcip[\s>]|<same_source_ip\s*/>|\$\(srcip\)|'
                                           r'<field name="srcip"', rules) is not None)
    dstuser = (bool(order & {'user', 'dstuser'}) or
               re.search(r'<user[\s>]|<same_user\s*/>|\$\(dstuser\)|<field name="dstuser"', rules) is not None)
    opts = manifest.get('dashboard') or {}
    if 'srcip' in opts:
        srcip = bool(opts['srcip'])
    if 'dstuser' in opts:
        dstuser = bool(opts['dstuser'])
    return srcip, dstuser


# ------------------------------------------------------------ saved objects

def dumps(value):
    """JSON inside a saved object's attribute (a string holding JSON)."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def short_names(manifest):
    en = re.sub(r'\s+Detection Suite$', '', manifest['name']).strip()
    zh = re.sub(r'\s*偵測套組$', '', manifest['name_zh']).strip()
    return en, zh


def bilingual(en, zh):
    return en if not zh or zh == en else '%s｜%s' % (en, zh)


def search_source(query):
    return dumps({'filter': [], 'indexRefName': INDEX_REF,
                  'query': {'language': 'lucene', 'query': query}})


def terms(agg_id, field, size, schema, label=None, order_by='1'):
    params = {'field': field, 'missingBucket': False, 'missingBucketLabel': 'Missing',
              'order': 'desc', 'orderBy': order_by, 'otherBucket': False,
              'otherBucketLabel': 'Other', 'size': size}
    if label:
        params['customLabel'] = label
    return {'enabled': True, 'id': agg_id, 'params': params, 'schema': schema, 'type': 'terms'}


def count(label=None):
    return {'enabled': True, 'id': '1', 'params': {'customLabel': label} if label else {},
            'schema': 'metric', 'type': 'count'}


TABLE_PARAMS = {'percentageCol': '', 'perPage': 10, 'showMetricsAtAllLevels': False,
                'showPartialRows': False, 'showTotal': False, 'totalFunc': 'sum'}


def level_colours():
    return {'vis': {'colors': {str(k): v for k, v in sorted(LEVEL_COLOURS.items())}}}


class Builder:
    def __init__(self, pdir, manifest, fields):
        self.m = manifest
        self.pid = manifest['id']
        self.query = rule_query(manifest['rule_id_range'])
        self.fields = fields
        self.en, self.zh = short_names(manifest)
        self.objects = []
        self.titles = {}          # object id -> panel title without the pack id
        self.panels = []          # (object id, type, width, height)
        self.srcip, self.dstuser = carries(pdir, manifest)
        opts = manifest.get('dashboard') or {}
        self.extra = []
        for item in opts.get('fields') or []:
            item = {'field': item} if isinstance(item, str) else dict(item)
            item['kind'] = field_kind(item['field'], fields)
            self.extra.append(item)
        self.columns = list(opts.get('columns') or [f['field'] for f in self.extra][:3])
        for c in self.columns:
            field_kind(c, fields)

    def oid(self, part):
        return 'jt-pack-%s-%s' % (self.pid, part)

    def vis(self, part, title, vis_state, ui_state=None, uses_index=True):
        attrs = {'description': '', 'title': '%s · %s' % (self.pid, title),
                 'uiStateJSON': dumps(ui_state or {}), 'version': 1,
                 'visState': dumps(dict(vis_state, title='%s · %s' % (self.pid, title)))}
        refs = []
        if uses_index:
            attrs['kibanaSavedObjectMeta'] = {'searchSourceJSON': search_source(self.query)}
            refs = [{'id': INDEX_PATTERN_ID, 'name': INDEX_REF, 'type': 'index-pattern'}]
        else:
            attrs['kibanaSavedObjectMeta'] = {'searchSourceJSON': dumps({'filter': [], 'query': {
                'language': 'lucene', 'query': ''}})}
        self.objects.append({'attributes': attrs, 'id': self.oid(part),
                             'migrationVersion': {'visualization': '7.10.0'},
                             'references': refs, 'type': 'visualization'})
        self.titles[self.oid(part)] = title
        return self.oid(part)

    # -- panels
    def intro(self):
        ranges = self.m['rule_id_range']
        ranges = ', '.join(ranges) if isinstance(ranges, list) else ranges
        text = '\n\n'.join([
            '### %s' % bilingual(self.m['name'], self.m['name_zh']),
            '`%s` · rules %s｜規則 %s' % (self.pid, ranges, ranges),
            self.m.get('summary_zh', ''),
            self.m.get('summary', ''),
            'Discover query｜在 Discover 使用的查詢:\n\n`%s`' % self.query,
        ])
        vid = self.vis('intro', 'About｜說明', {
            'aggs': [], 'type': 'markdown',
            'params': {'fontSize': 11, 'markdown': text, 'openLinksInNewTab': False}},
            uses_index=False)
        self.panels.append((vid, 'visualization', 20, 12))

    def metric(self):
        vid = self.vis('count', 'Alerts｜告警數', {
            'type': 'metric',
            'aggs': [count('Alerts｜告警'),
                     {'enabled': True, 'id': '2', 'schema': 'group', 'type': 'filters', 'params': {
                         'filters': [
                             {'input': {'language': 'lucene', 'query': '*'}, 'label': 'All｜全部'},
                             {'input': {'language': 'lucene', 'query': 'rule.level:>=%d' % HIGH_LEVEL},
                              'label': 'Level %d+｜等級 %d 以上' % (HIGH_LEVEL, HIGH_LEVEL)}]}}],
            'params': {'addLegend': False, 'addTooltip': True, 'type': 'metric', 'metric': {
                'colorSchema': 'Green to Red', 'colorsRange': [{'from': 0, 'to': 10000}],
                'invertColors': False, 'labels': {'show': True}, 'metricColorMode': 'None',
                'percentageMode': False, 'useRanges': False,
                'style': {'bgColor': False, 'bgFill': '#000', 'fontSize': 36,
                          'labelColor': False, 'subText': ''}}}})
        self.panels.append((vid, 'visualization', 12, 12))

    def levels(self):
        vid = self.vis('levels', 'Level distribution｜等級分布', {
            'type': 'pie',
            'aggs': [count('Alerts｜告警'),
                     terms('2', 'rule.level', 16, 'segment', 'Level｜等級', order_by='_key')],
            'params': {'addLegend': True, 'addTooltip': True, 'isDonut': True, 'legendPosition': 'right',
                       'type': 'pie', 'labels': {'last_level': True, 'show': False, 'truncate': 100,
                                                 'values': True}}},
            ui_state=level_colours())
        self.panels.append((vid, 'visualization', 16, 12))

    def timeline(self):
        vid = self.vis('timeline', 'Alerts over time by level｜各等級告警趨勢', {
            'type': 'histogram',
            'aggs': [count('Alerts｜告警'),
                     {'enabled': True, 'id': '2', 'schema': 'segment', 'type': 'date_histogram',
                      'params': {'drop_partials': False, 'extended_bounds': {}, 'field': TIME_FIELD,
                                 'interval': 'auto', 'min_doc_count': 1, 'scaleMetricValues': False,
                                 'useNormalizedOpenSearchInterval': True}},
                     terms('3', 'rule.level', 16, 'group', 'Level｜等級', order_by='_key')],
            'params': {
                'addLegend': True, 'addTimeMarker': False, 'addTooltip': True,
                'categoryAxes': [{'id': 'CategoryAxis-1', 'labels': {'filter': True, 'show': True,
                                                                     'truncate': 100},
                                  'position': 'bottom', 'scale': {'type': 'linear'}, 'show': True,
                                  'style': {}, 'title': {}, 'type': 'category'}],
                'grid': {'categoryLines': False}, 'labels': {'show': False}, 'legendPosition': 'right',
                'seriesParams': [{'data': {'id': '1', 'label': 'Alerts｜告警'}, 'drawLinesBetweenPoints': True,
                                  'lineWidth': 2, 'mode': 'stacked', 'show': True, 'showCircles': True,
                                  'type': 'histogram', 'valueAxis': 'ValueAxis-1'}],
                'thresholdLine': {'color': '#E7664C', 'show': False, 'style': 'full', 'value': 10,
                                  'width': 1},
                'times': [], 'type': 'histogram',
                'valueAxes': [{'id': 'ValueAxis-1', 'labels': {'filter': False, 'rotate': 0, 'show': True,
                                                               'truncate': 100},
                               'name': 'LeftAxis-1', 'position': 'left',
                               'scale': {'mode': 'normal', 'type': 'linear'}, 'show': True, 'style': {},
                               'title': {'text': 'Alerts｜告警'}, 'type': 'value'}]}},
            ui_state=level_colours())
        self.panels.append((vid, 'visualization', 48, 13))

    def top_rules(self):
        vid = self.vis('rules', 'Top rules｜觸發最多的規則', {
            'type': 'table',
            'aggs': [count('Alerts｜告警'),
                     {'enabled': True, 'id': '4', 'schema': 'metric', 'type': 'max',
                      'params': {'customLabel': 'Level｜等級', 'field': 'rule.level'}},
                     terms('2', 'rule.id', 50, 'bucket', 'Rule｜規則'),
                     terms('3', 'rule.description', 1, 'bucket', 'Description｜說明')],
            'params': TABLE_PARAMS})
        self.panels.append((vid, 'visualization', 30, 16))

    def top_terms(self, part, field, title, size=20, w=24, h=16, column=None):
        vid = self.vis(part, title, {
            'type': 'table',
            'aggs': [count('Alerts｜告警'), terms('2', field, size, 'bucket', column or field)],
            'params': TABLE_PARAMS})
        self.panels.append((vid, 'visualization', w, h))

    def vega_terms(self, part, field, title, size=10):
        spec = {
            '$schema': 'https://vega.github.io/schema/vega-lite/v5.json',
            'data': {
                'url': {
                    'index': INDEX_PATTERN_ID,
                    'body': {
                        'size': 0,
                        'query': {'bool': {
                            'must': ['%dashboard_context-must_clause%',
                                     {'range': {TIME_FIELD: {'%timefilter%': True}}},
                                     {'query_string': {'query': self.query, 'analyze_wildcard': True}}],
                            'filter': ['%dashboard_context-filter_clause%'],
                            'must_not': ['%dashboard_context-must_not_clause%']}},
                        'aggs': {'top': {'terms': {'field': field, 'size': size}}},
                    },
                },
                'format': {'property': 'aggregations.top.buckets'},
            },
            # An empty result (no such alert yet) is not a problem; without this
            # Vega-Lite prints "Infinite extent" warnings over the empty chart.
            # Errors are still shown.
            'config': {'kibana': {'hideWarnings': True}, 'axisY': {'labelLimit': 260}},
            'mark': {'type': 'bar', 'tooltip': True, 'color': '#6092C0'},
            'encoding': {
                'y': {'field': 'key', 'type': 'nominal', 'sort': '-x', 'title': field},
                'x': {'field': 'doc_count', 'type': 'quantitative', 'title': 'Alerts｜告警'},
            },
        }
        vid = self.vis(part, title, {
            'aggs': [], 'type': 'vega',
            'params': {'spec': json.dumps(spec, ensure_ascii=False, indent=2, sort_keys=True)}},
            uses_index=False)
        self.panels.append((vid, 'visualization', 24, 14))

    def search(self):
        columns = ['rule.id', 'rule.level', 'rule.description', 'agent.name']
        if self.srcip:
            columns.append('data.srcip')
        if self.dstuser:
            columns.append('data.dstuser')
        columns += [c for c in self.columns if c not in columns]
        self.objects.append({
            'attributes': {
                'columns': columns, 'description': '', 'hits': 0,
                'kibanaSavedObjectMeta': {'searchSourceJSON': search_source(self.query)},
                'sort': [[TIME_FIELD, 'desc']],
                'title': '%s · Latest alerts｜最新告警' % self.pid, 'version': 1},
            'id': self.oid('search'), 'migrationVersion': {'search': '7.9.3'},
            'references': [{'id': INDEX_PATTERN_ID, 'name': INDEX_REF, 'type': 'index-pattern'}],
            'type': 'search'})
        self.titles[self.oid('search')] = 'Latest alerts｜最新告警'
        self.panels.append((self.oid('search'), 'search', 48, 20))

    def dashboard(self):
        panels, refs = [], []
        x = y = row_h = 0
        for i, (oid, otype, w, h) in enumerate(self.panels):
            if x + w > 48:
                x, y, row_h = 0, y + row_h, 0
            # the dashboard title names the pack; the panel shows the short title
            panel = {'embeddableConfig': {'title': self.titles[oid]}, 'gridData': {'h': h, 'i': str(i + 1), 'w': w, 'x': x, 'y': y},
                     'panelIndex': str(i + 1), 'panelRefName': 'panel_%d' % i, 'version': '7.10.0'}
            panels.append(panel)
            refs.append({'id': oid, 'name': 'panel_%d' % i, 'type': otype})
            x += w
            row_h = max(row_h, h)
        ranges = self.m['rule_id_range']
        ranges = ', '.join(ranges) if isinstance(ranges, list) else ranges
        return {
            'attributes': {
                'description': 'jt-wazuh-mgr rule pack %s, rules %s｜jt-wazuh-mgr 規則套件 %s，規則 %s'
                               % (self.pid, ranges, self.pid, ranges),
                'hits': 0,
                'kibanaSavedObjectMeta': {'searchSourceJSON': dumps(
                    {'filter': [], 'query': {'language': 'kuery', 'query': ''}})},
                'optionsJSON': dumps({'hidePanelTitles': False, 'useMargins': True}),
                'panelsJSON': dumps(panels),
                'refreshInterval': {'pause': True, 'value': 0},
                'timeFrom': 'now-7d', 'timeRestore': True, 'timeTo': 'now',
                'title': 'jt · %s' % bilingual(self.en, self.zh), 'version': 1},
            'id': self.oid('dashboard'), 'migrationVersion': {'dashboard': '7.9.3'},
            'references': refs, 'type': 'dashboard'}

    def build(self):
        self.intro()
        self.metric()
        self.levels()
        self.timeline()
        self.top_rules()
        self.top_terms('agents', 'agent.name', 'Top agents｜告警最多的代理程式', w=18,
                       column='Agent｜代理程式')
        if self.srcip:
            self.top_terms('srcip', 'data.srcip', 'Top source addresses｜來源位址排行',
                           column='Source address (data.srcip)｜來源位址')
        if self.dstuser:
            self.top_terms('dstuser', 'data.dstuser', 'Top accounts｜帳號排行',
                           column='Account (data.dstuser)｜帳號')
        for item in self.extra:
            field = item['field']
            title = bilingual(item.get('title') or field, item.get('title_zh') or '')
            part = 'field-' + re.sub(r'[^a-z0-9]+', '-', field.lower()).strip('-')
            if item['kind'] == 'static':
                self.top_terms(part, field, title, size=int(item.get('size', 20)),
                               column='%s (%s)' % (title, field))
            else:
                self.vega_terms(part, field, title, size=int(item.get('size', 10)))
        self.search()
        objects = self.objects + [self.dashboard()]
        return ''.join(json.dumps(o, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n'
                       for o in objects)


def load_manifest(pack_id):
    pdir = os.path.join(PACKS_DIR, pack_id)
    with io.open(os.path.join(pdir, 'manifest.json'), encoding='utf-8') as fh:
        return pdir, json.load(fh)


def build(pack_id, fields=None):
    pdir, manifest = load_manifest(pack_id)
    return Builder(pdir, manifest, fields or template_fields()).build()


def output_path(pack_id):
    return os.path.join(PACKS_DIR, pack_id, 'dashboards', pack_id + '.ndjson')


def all_packs():
    return sorted(os.path.basename(os.path.dirname(p))
                  for p in glob.glob(os.path.join(PACKS_DIR, '*', 'manifest.json')))


def main(argv):
    check = '--check' in argv
    packs = [a for a in argv if not a.startswith('--')] or all_packs()
    fields = template_fields()
    stale = []
    for pack_id in packs:
        if not re.match(r'^[a-z0-9][a-z0-9._-]{0,63}$', pack_id):
            raise SystemExit('invalid pack id %r' % pack_id)
        body = build(pack_id, fields)
        path = output_path(pack_id)
        current = None
        if os.path.isfile(path):
            with io.open(path, encoding='utf-8') as fh:
                current = fh.read()
        if current == body:
            continue
        stale.append(pack_id)
        if not check:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(body)
    if check:
        if stale:
            print('stale dashboards: %s (run tools/build_pack_dashboards.py)' % ', '.join(stale))
            return 1
        print('%d dashboards up to date' % len(packs))
        return 0
    print('%d written, %d unchanged' % (len(stale), len(packs) - len(stale)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
