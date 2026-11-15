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
      "rules_by": {"field": "data.jt_ai.agent", "title": "AI agent", "title_zh": "AI 代理"},
                                                  # "Top rules" with one more column (Vega table)
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


# The language the dashboards are built in: 'en' or 'zh-TW' (2026-10-30, owner:
# "separate Chinese and English versions, a widget with both is too much text").
LANG = 'en'
LANGS = ('en', 'zh-TW')


def T(en, zh):
    return zh if LANG == 'zh-TW' and zh else en


def bilingual(en, zh):
    return T(en, zh)


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
        self.untitled = set()     # panels that carry their own label (the count cards)
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
            '### %s' % T(self.m['name'], self.m['name_zh']),
            T('`%s` · rules %s', '`%s` · 規則 %s') % (self.pid, ranges),
            T(self.m.get('summary', ''), self.m.get('summary_zh', '')),
            T('Discover query:', '在 Discover 使用的查詢：') + '\n\n`%s`' % self.query,
        ])
        vid = self.vis('intro', T('About', '說明'), {
            'aggs': [], 'type': 'markdown',
            'params': {'fontSize': 11, 'markdown': text, 'openLinksInNewTab': False}},
            uses_index=False)
        # a row of its own (2026-11-06, owner): the text no longer squeezes the counts. Its height
        # follows the summary: about 95 characters of Chinese or 190 of English to a line at full width.
        summary = T(self.m.get('summary', ''), self.m.get('summary_zh', ''))
        per_line = 95 if LANG == 'zh-TW' else 190
        lines = -(-len(summary) // per_line)
        self.panels.append((vid, 'visualization', 48, max(9, min(15, 8 + lines))))

    def metric(self):
        """Three counts, one card each (2026-11-06, owner: "the numbers are too small",
        "like the separate cards" of the Wazuh overview), in the colour of what they
        mean (2026-10-30) and clickable (2026-11-01): a click adds the level range
        (or, for all alerts, the pack's rules) as a dashboard filter through
        opensearchDashboardsAddFilter. A metric visualization colours by value range
        only, and Vega-Lite has no click handler that can call that function, so
        each card is a small Vega spec: all alerts in blue; levels 7-11 amber and
        12+ red when there are any, green when there are none. The number scales
        with the card."""
        mid_lo, high = 7, HIGH_LEVEL
        cards = [
            ('count', T('All alerts', '全部告警'), {'match_all': {}},
             {'query_string': {'query': self.query, 'analyze_wildcard': True}},
             T('%s rules' % self.pid, '%s 的規則' % self.pid), "'#1f5bb0'"),
            ('count-mid', T('Level %d-%d' % (mid_lo, high - 1), '等級 %d–%d' % (mid_lo, high - 1)),
             {'range': {'rule.level': {'gte': mid_lo, 'lte': high - 1}}},
             {'range': {'rule.level': {'gte': mid_lo, 'lte': high - 1}}},
             T('Level %d-%d' % (mid_lo, high - 1), '等級 %d–%d' % (mid_lo, high - 1)),
             "datum.doc_count == 0 ? '#2e7d32' : '#b26a00'"),
            ('count-high', T('Level %d+' % high, '等級 %d 以上' % high),
             {'range': {'rule.level': {'gte': high}}},
             {'range': {'rule.level': {'gte': high}}},
             T('Level %d+' % high, '等級 %d 以上' % high),
             "datum.doc_count == 0 ? '#2e7d32' : '#c62828'"),
        ]
        for part, label, agg, flt, flt_name, colour in cards:
            # the third argument is the filter's label; without it the pill shows the query JSON
            click = 'opensearchDashboardsAddFilter(%s, %s, %s)' % (
                json.dumps(flt, sort_keys=True), json.dumps(INDEX_PATTERN_ID), json.dumps(flt_name, ensure_ascii=False))
            spec = {
                '$schema': 'https://vega.github.io/schema/vega/v5.json',
                'autosize': {'type': 'fit', 'contains': 'padding'},
                'config': {'kibana': {'hideWarnings': True}},
                'data': [{
                    'name': 'lv',
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
                            'aggs': {'lv': {'filters': {'filters': [agg]}}},
                        },
                    },
                    'format': {'property': 'aggregations.lv.buckets'},
                    'transform': [
                        {'type': 'formula', 'as': 'num', 'expr': "format(datum.doc_count, ',')"},
                        {'type': 'formula', 'as': 'colour', 'expr': colour},
                    ],
                }],
                'signals': [{'name': 'jtFilter', 'value': None,
                             'on': [{'events': '@num:click, @lbl:click', 'update': click}]}],
                'marks': [
                    {'name': 'num', 'type': 'text', 'from': {'data': 'lv'}, 'encode': {
                        'enter': {'x': {'signal': 'width / 2'}, 'y': {'signal': 'height * 0.62'},
                                  'text': {'field': 'num'}, 'fill': {'field': 'colour'}, 'align': {'value': 'center'},
                                  'baseline': {'value': 'bottom'},
                                  # as large as the card allows: by height, and by width for long numbers
                                  'fontSize': {'signal': 'max(18, min(height * 0.5, width * 1.6 / max(3, length(datum.num))))'},
                                  'fontWeight': {'value': 'bold'}, 'cursor': {'value': 'pointer'},
                                  'tooltip': {'value': T('Click to filter the dashboard', '點擊以篩選看板')}},
                        'hover': {'opacity': {'value': 0.75}}, 'update': {'opacity': {'value': 1}}}},
                    {'name': 'lbl', 'type': 'text', 'from': {'data': 'lv'}, 'encode': {
                        'enter': {'x': {'signal': 'width / 2'}, 'y': {'signal': 'height * 0.62'},
                                  'text': {'value': '- %s -' % label}, 'fill': {'value': '#3d444d'},
                                  'align': {'value': 'center'}, 'baseline': {'value': 'top'}, 'dy': {'value': 8},
                                  'fontSize': {'signal': 'max(12, min(18, height * 0.09))'},
                                  'cursor': {'value': 'pointer'}}}},
                ],
            }
            vid = self.vis(part, label, {
                'aggs': [], 'type': 'vega',
                'params': {'spec': json.dumps(spec, ensure_ascii=False, indent=2, sort_keys=True)}},
                uses_index=False)
            self.panels.append((vid, 'visualization', 10, 10))
            self.untitled.add(vid)

    def levels(self):
        vid = self.vis('levels', T('Level distribution', '等級分布'), {
            'type': 'pie',
            'aggs': [count(T('Alerts', '告警')),
                     terms('2', 'rule.level', 16, 'segment', T('Level', '等級'), order_by='_key')],
            'params': {'addLegend': True, 'addTooltip': True, 'isDonut': True, 'legendPosition': 'right',
                       'type': 'pie', 'labels': {'last_level': True, 'show': False, 'truncate': 100,
                                                 'values': True}}},
            ui_state=level_colours())
        self.panels.append((vid, 'visualization', 18, 10))   # beside the three 10-wide cards

    def timeline(self):
        vid = self.vis('timeline', T('Alerts over time by level', '各等級告警趨勢'), {
            'type': 'histogram',
            'aggs': [count(T('Alerts', '告警')),
                     {'enabled': True, 'id': '2', 'schema': 'segment', 'type': 'date_histogram',
                      'params': {'drop_partials': False, 'extended_bounds': {}, 'field': TIME_FIELD,
                                 'interval': 'auto', 'min_doc_count': 1, 'scaleMetricValues': False,
                                 'useNormalizedOpenSearchInterval': True}},
                     terms('3', 'rule.level', 16, 'group', T('Level', '等級'), order_by='_key')],
            'params': {
                'addLegend': True, 'addTimeMarker': False, 'addTooltip': True,
                'categoryAxes': [{'id': 'CategoryAxis-1', 'labels': {'filter': True, 'show': True,
                                                                     'truncate': 100},
                                  'position': 'bottom', 'scale': {'type': 'linear'}, 'show': True,
                                  'style': {}, 'title': {}, 'type': 'category'}],
                'grid': {'categoryLines': False}, 'labels': {'show': False}, 'legendPosition': 'right',
                'seriesParams': [{'data': {'id': '1', 'label': T('Alerts', '告警')}, 'drawLinesBetweenPoints': True,
                                  'lineWidth': 2, 'mode': 'stacked', 'show': True, 'showCircles': True,
                                  'type': 'histogram', 'valueAxis': 'ValueAxis-1'}],
                'thresholdLine': {'color': '#E7664C', 'show': False, 'style': 'full', 'value': 10,
                                  'width': 1},
                'times': [], 'type': 'histogram',
                'valueAxes': [{'id': 'ValueAxis-1', 'labels': {'filter': False, 'rotate': 0, 'show': True,
                                                               'truncate': 100},
                               'name': 'LeftAxis-1', 'position': 'left',
                               'scale': {'mode': 'normal', 'type': 'linear'}, 'show': True, 'style': {},
                               'title': {'text': T('Alerts', '告警')}, 'type': 'value'}]}},
            ui_state=level_colours())
        self.panels.append((vid, 'visualization', 48, 13))

    def top_rules(self):
        vid = self.vis('rules', T('Top rules', '觸發最多的規則'), {
            'type': 'table',
            'aggs': [count(T('Alerts', '告警')),
                     {'enabled': True, 'id': '4', 'schema': 'metric', 'type': 'max',
                      'params': {'customLabel': T('Level', '等級'), 'field': 'rule.level'}},
                     terms('2', 'rule.id', 50, 'bucket', T('Rule', '規則')),
                     terms('3', 'rule.description', 1, 'bucket', T('Description', '說明'))],
            'params': TABLE_PARAMS},
            # Columns are rule, description, alerts, level (buckets first). OSD 2.19's
            # table reads uiState vis.columnsWidth as initial pixel widths; columns
            # without one share the rest, so the description gets the room.
            ui_state={'vis': {'columnsWidth': [{'colIndex': 0, 'width': 90}, {'colIndex': 2, 'width': 100},
                                               {'colIndex': 3, 'width': 70}]}})
        self.panels.append((vid, 'visualization', 32, 16))

    def vega_table(self, part, title, aggs, prop, transforms, columns, default_sort, w, h):
        """A table drawn in Vega for fields that exist only in data.*: a standard table on a field
        the index pattern does not know yet shows an error, this one shows an empty table.
        A click on a column header sorts by it (again: the other way round, an arrow shows
        which), and a click on a cell of a filter column adds that value as a dashboard filter
        through opensearchDashboardsAddFilter, which Vega-Lite cannot call (2026-11-15, owner:
        the first Vega tables could do neither). columns: dicts with key, label, x, align,
        optional right (x counts from the right edge), filter (a field), number (format with
        separators), limit (pixels or a Vega expression) and colour (a Vega expression)."""
        # looks like OSD's own data table (2026-11-15, owner: the first version looked cramped):
        # EUI font and colours, 14 px text, 34 px rows with a rule under each, a bold header
        # over a dark rule, the row under the pointer shaded
        row_h, head_h = 34, 38
        font = 'Inter UI, -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif'
        signals = [
            # one signal holds both, so the toggle never depends on the order signals update in
            {'name': 'sortBy', 'value': {'field': default_sort, 'desc': True},
             'on': [{'events': '@jtHead:click',
                     'update': '{field: datum.key, desc: datum.key === sortBy.field ? !sortBy.desc : datum.num}'}]},
            {'name': 'sortField', 'update': 'sortBy.field'},
            {'name': 'sortDesc', 'update': 'sortBy.desc'},
        ]
        marks = [
            {'name': 'jtHead', 'type': 'text', 'from': {'data': 'head'}, 'encode': {'update': {
                'x': {'signal': 'datum.right ? width - datum.x : datum.x'}, 'y': {'value': head_h / 2},
                'align': {'field': 'align'},
                'text': {'signal': "datum.label + (datum.key === sortField ? (sortDesc ? ' \u25bc' : ' \u25b2') : '')"},
                'fontWeight': {'value': 'bold'}, 'fill': {'value': '#1A1C21'}, 'cursor': {'value': 'pointer'},
                'tooltip': {'value': T('Click to sort', '點擊以排序')}}}},
            {'type': 'rule', 'encode': {'update': {
                'x': {'value': 0}, 'x2': {'signal': 'width'}, 'y': {'value': head_h}, 'y2': {'value': head_h},
                'stroke': {'value': '#343741'}, 'strokeWidth': {'value': 2}}}},
            # a band per row: the rule under it and the shade under the pointer
            {'type': 'rect', 'from': {'data': 'rows'}, 'encode': {
                'update': {'x': {'value': 0}, 'x2': {'signal': 'width'},
                           'y': {'signal': 'datum.row * %d + %d' % (row_h, head_h)}, 'height': {'value': row_h},
                           'fill': {'value': '#FFFFFF'}, 'fillOpacity': {'value': 0}},
                'hover': {'fill': {'value': '#F5F7FA'}, 'fillOpacity': {'value': 1}}}},
            {'type': 'rule', 'from': {'data': 'rows'}, 'encode': {'update': {
                'x': {'value': 0}, 'x2': {'signal': 'width'},
                'y': {'signal': '(datum.row + 1) * %d + %d' % (row_h, head_h)},
                'y2': {'signal': '(datum.row + 1) * %d + %d' % (row_h, head_h)},
                'stroke': {'value': '#D3DAE6'}}}},
        ]
        for c in columns:
            x = {'signal': 'width - %d' % c['x']} if c.get('right') else {'value': c['x']}
            enc = {'x': x, 'y': {'signal': '(datum.row + 0.5) * %d + %d' % (row_h, head_h)},
                   'align': {'value': c.get('align', 'left')},
                   'text': ({'signal': "format(datum.%s, ',')" % c['key']} if c.get('number') else {'field': c['key']})}
            if c.get('limit') is not None:
                enc['limit'] = {'signal': c['limit']} if isinstance(c['limit'], str) else {'value': c['limit']}
            if c.get('filter'):
                name = 'jtCell_' + re.sub(r'[^A-Za-z0-9]', '', c['key'])
                enc.update({'fill': {'value': '#006BB4'}, 'cursor': {'value': 'pointer'},
                            'tooltip': {'signal': "'%s' + ': ' + datum.%s" % (
                                T('Click to filter', '點擊以篩選'), c['key'])}})
                flt = "{'match_phrase': {%s: datum.%s}}" % (json.dumps(c['filter']), c['key'])
                signals.append({'name': name + 'Filter', 'value': None, 'on': [{
                    'events': '@%s:click' % name,
                    'update': "datum.%s === '-' ? null : opensearchDashboardsAddFilter(%s, %s, %s + ': ' + datum.%s)" % (
                        c['key'], flt, json.dumps(INDEX_PATTERN_ID), json.dumps(c['filter']), c['key'])}]})
                mark = {'name': name}
            else:
                mark = {}
                if c.get('colour'):
                    enc['fill'] = {'signal': c['colour']}
                if c.get('tooltip'):
                    enc['tooltip'] = {'field': c['key']}
            mark.update({'type': 'text', 'from': {'data': 'rows'}, 'encode': {'update': enc}})
            marks.append(mark)
        spec = {
            '$schema': 'https://vega.github.io/schema/vega/v5.json',
            # fit: the panel's size becomes width and height (none leaves them 0)
            'autosize': {'type': 'fit', 'contains': 'padding'},
            'padding': {'left': 8, 'right': 8, 'top': 4, 'bottom': 4},
            'config': {'kibana': {'hideWarnings': True},
                       'text': {'fontSize': 14, 'baseline': 'middle', 'font': font, 'fill': '#343741'}},
            'signals': signals,
            'data': [
                {'name': 'src', 'url': {'index': INDEX_PATTERN_ID, 'body': {
                    'size': 0,
                    'query': {'bool': {
                        'must': ['%dashboard_context-must_clause%',
                                 {'range': {TIME_FIELD: {'%timefilter%': True}}},
                                 {'query_string': {'query': self.query, 'analyze_wildcard': True}}],
                        'filter': ['%dashboard_context-filter_clause%'],
                        'must_not': ['%dashboard_context-must_not_clause%']}},
                    'aggs': aggs}},
                 'format': {'property': prop}, 'transform': transforms},
                {'name': 'rows', 'source': 'src', 'transform': [
                    # the window numbers rows in its own sort order, so the sort goes here
                    {'type': 'window', 'ops': ['row_number'], 'as': ['row0'],
                     'sort': {'field': {'signal': 'sortField'},
                              'order': {'signal': "sortDesc ? 'descending' : 'ascending'"}}},
                    {'type': 'formula', 'as': 'row', 'expr': 'datum.row0 - 1'},
                    {'type': 'filter', 'expr': 'datum.row < floor((height - %d) / %d)' % (head_h, row_h)}]},
                # num: what the first click on this header does (numbers start high, text A-Z)
                {'name': 'head', 'values': [{'key': c['key'], 'label': c['label'], 'x': c['x'], 'right': bool(c.get('right')),
                                             'align': c.get('align', 'left'), 'num': bool(c.get('number') or c.get('numeric'))}
                                            for c in columns]},
            ],
            'marks': marks,
        }
        vid = self.vis(part, title, {
            'aggs': [], 'type': 'vega',
            'params': {'spec': json.dumps(spec, ensure_ascii=False, indent=2, sort_keys=True)}},
            uses_index=False)
        self.panels.append((vid, 'visualization', w, h))

    def vega_rule_table(self, field, label):
        """The "Top rules" table with one more column, a field that exists only in data.*
        (manifest dashboard.rules_by): rule x value rows (the value "-" when an alert lacks
        the field). Sortable, and a click on a rule or a value filters the dashboard."""
        aggs = {'r': {'terms': {'field': 'rule.id', 'size': 50}, 'aggs': {
            'v': {'terms': {'field': field, 'size': 5, 'missing': '-'}},
            'd': {'terms': {'field': 'rule.description', 'size': 1}},
            'l': {'max': {'field': 'rule.level'}}}}}
        transforms = [
            {'type': 'flatten', 'fields': ['v.buckets'], 'as': ['vb']},
            {'type': 'formula', 'as': 'rule', 'expr': 'datum.key'},
            {'type': 'formula', 'as': 'value', 'expr': 'datum.vb.key'},
            {'type': 'formula', 'as': 'alerts', 'expr': 'datum.vb.doc_count'},
            {'type': 'formula', 'as': 'desc', 'expr': "length(datum.d.buckets) ? datum.d.buckets[0].key : ''"},
            {'type': 'formula', 'as': 'level', 'expr': 'datum.l.value'},
        ]
        columns = [
            {'key': 'rule', 'label': T('Rule', '規則'), 'x': 0, 'filter': 'rule.id'},
            {'key': 'level', 'label': T('Level', '等級'), 'x': 135, 'align': 'right', 'numeric': True,
             'colour': "datum.level >= 12 ? '#BD271E' : '#343741'"},
            {'key': 'value', 'label': label, 'x': 160, 'limit': 170, 'filter': field},
            {'key': 'alerts', 'label': T('Alerts', '告警'), 'x': 410, 'align': 'right', 'number': True},
            {'key': 'desc', 'label': T('Description', '說明'), 'x': 435, 'limit': 'width - 435', 'tooltip': True},
        ]
        self.vega_table('rules', T('Top rules', '觸發最多的規則'), aggs, 'aggregations.r.buckets', transforms,
                        columns, 'alerts', 32, 16)

    def top_terms(self, part, field, title, size=20, w=24, h=16, column=None):
        vid = self.vis(part, title, {
            'type': 'table',
            'aggs': [count(T('Alerts', '告警')), terms('2', field, size, 'bucket', column or field)],
            'params': TABLE_PARAMS},
            ui_state={'vis': {'columnsWidth': [{'colIndex': 1, 'width': 110}]}})
        self.panels.append((vid, 'visualization', w, h))

    def geo_map(self):
        """Where the public source addresses are: Wazuh's ingest pipeline geolocates data.srcip into
        GeoLocation (country, city, a geo_point). Private addresses have no location and are left out.
        A Vega map, not a coordinate map (tile_map): OSD 2.19's Vega panels bring their own Leaflet,
        and with one on the same dashboard a tile_map loads its data but never draws a point (tested
        in OSD 2.19.6: the same tile_map alone on a dashboard draws). The base tiles come from the
        OpenSearch maps service; without Internet access the circles still draw on a blank background,
        and the country table next to it needs no tiles at all."""
        spec = {
            '$schema': 'https://vega.github.io/schema/vega/v5.json',
            'config': {'kibana': {'type': 'map', 'latitude': 25, 'longitude': 15, 'zoom': 2, 'minZoom': 1,
                                  'maxZoom': 10, 'zoomControl': True, 'scrollWheelZoom': False,
                                  'delayRepaint': True, 'hideWarnings': True}},
            'data': [{
                'name': 'points',
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
                        'aggs': {'cells': {
                            'geohash_grid': {'field': 'GeoLocation.location', 'precision': 2, 'size': 2000},
                            'aggs': {'centre': {'geo_centroid': {'field': 'GeoLocation.location'}},
                                     'country': {'terms': {'field': 'GeoLocation.country_name', 'size': 1}}}}},
                    },
                },
                'format': {'property': 'aggregations.cells.buckets'},
                'transform': [
                    {'type': 'geopoint', 'projection': 'projection',
                     'fields': ['centre.location.lon', 'centre.location.lat']},
                    {'type': 'formula', 'as': 'place',
                     'expr': "length(datum.country.buckets) ? datum.country.buckets[0].key : ''"}],
            }],
            'scales': [{'name': 'size', 'type': 'sqrt', 'domain': {'data': 'points', 'field': 'doc_count'},
                        'range': [40, 1600]},
                       {'name': 'colour', 'type': 'sequential', 'scheme': 'orangered',
                        'domain': {'data': 'points', 'field': 'doc_count'}}],
            'marks': [{
                'type': 'symbol', 'from': {'data': 'points'},
                'encode': {'update': {
                    'x': {'field': 'x'}, 'y': {'field': 'y'},
                    'size': {'scale': 'size', 'field': 'doc_count'},
                    'fill': {'scale': 'colour', 'field': 'doc_count'}, 'fillOpacity': {'value': 0.75},
                    'stroke': {'value': '#7f2704'}, 'strokeWidth': {'value': 1},
                    'tooltip': {'signal': "{'%s': datum.place, '%s': datum.doc_count}"
                                          % (T('Country', '國家'), T('Alerts', '告警'))}}},
            }],
        }
        vid = self.vis('geo-map', T('Source locations', '來源位置地圖'), {
            'aggs': [], 'type': 'vega',
            'params': {'spec': json.dumps(spec, ensure_ascii=False, indent=2, sort_keys=True)}},
            uses_index=False)
        self.panels.append((vid, 'visualization', 48, 22))

    def vega_terms(self, part, field, title, size=10):
        """Top values of a field that exists only in data.*: a sortable Vega table, a click on
        a value filters the dashboard."""
        aggs = {'top': {'terms': {'field': field, 'size': max(size, 20)}}}
        transforms = [{'type': 'formula', 'as': 'value', 'expr': 'datum.key'},
                      {'type': 'formula', 'as': 'alerts', 'expr': 'datum.doc_count'}]
        columns = [{'key': 'value', 'label': '%s (%s)' % (title, field), 'x': 0, 'limit': 'width - 90',
                    'filter': field},
                   {'key': 'alerts', 'label': T('Alerts', '告警'), 'x': 0, 'right': True, 'align': 'right',
                    'number': True}]
        self.vega_table(part, title, aggs, 'aggregations.top.buckets', transforms, columns, 'alerts', 24, 14)

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
                'title': T('%s · Latest alerts', '%s · 最新告警') % self.pid, 'version': 1},
            'id': self.oid('search'), 'migrationVersion': {'search': '7.9.3'},
            'references': [{'id': INDEX_PATTERN_ID, 'name': INDEX_REF, 'type': 'index-pattern'}],
            'type': 'search'})
        self.titles[self.oid('search')] = T('Latest alerts', '最新告警')
        self.panels.append((self.oid('search'), 'search', 48, 20))

    def dashboard(self):
        panels, refs = [], []
        x = y = row_h = 0
        for i, (oid, otype, w, h) in enumerate(self.panels):
            if x + w > 48:
                x, y, row_h = 0, y + row_h, 0
            # the dashboard title names the pack; the panel shows the short title
            config = {'title': self.titles[oid]}
            if oid in self.untitled:
                config['hidePanelTitles'] = True
            panel = {'embeddableConfig': config, 'gridData': {'h': h, 'i': str(i + 1), 'w': w, 'x': x, 'y': y},
                     'panelIndex': str(i + 1), 'panelRefName': 'panel_%d' % i, 'version': '7.10.0'}
            panels.append(panel)
            refs.append({'id': oid, 'name': 'panel_%d' % i, 'type': otype})
            x += w
            row_h = max(row_h, h)
        ranges = self.m['rule_id_range']
        ranges = ', '.join(ranges) if isinstance(ranges, list) else ranges
        return {
            'attributes': {
                'description': T('jt-wazuh-mgr rule pack %s, rules %s', 'jt-wazuh-mgr 規則套件 %s，規則 %s')
                               % (self.pid, ranges),
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
        opts = self.m.get('dashboard') or {}
        if opts.get('rules_by'):
            by = opts['rules_by']
            by = {'field': by} if isinstance(by, str) else by
            self.vega_rule_table(by['field'], bilingual(by.get('title') or by['field'], by.get('title_zh') or ''))
        else:
            self.top_rules()
        self.top_terms('agents', 'agent.name', T('Top agents', '告警最多的代理程式'), w=16,
                       column=T('Agent', '代理程式'))
        if self.srcip:
            self.top_terms('srcip', 'data.srcip', T('Top source addresses', '來源位址排行'),
                           column=T('Source address (data.srcip)', '來源位址'))
            self.top_terms('country', 'GeoLocation.country_name', T('Top source countries', '來源國家排行'),
                           column=T('Country', '國家'))
            self.geo_map()
        if self.dstuser:
            self.top_terms('dstuser', 'data.dstuser', T('Top accounts', '帳號排行'),
                           column=T('Account (data.dstuser)', '帳號'))
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


def build(pack_id, fields=None, lang='en'):
    """One pack's dashboard in one language. Both languages use the same
    object ids: importing the other one replaces it in place."""
    global LANG
    pdir, manifest = load_manifest(pack_id)
    previous, LANG = LANG, lang
    try:
        return Builder(pdir, manifest, fields or template_fields()).build()
    finally:
        LANG = previous


def output_path(pack_id, lang='en'):
    name = pack_id + ('.ndjson' if lang == 'en' else '.%s.ndjson' % lang)
    return os.path.join(PACKS_DIR, pack_id, 'dashboards', name)


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
        for lang in LANGS:
            body = build(pack_id, fields, lang)
            path = output_path(pack_id, lang)
            current = None
            if os.path.isfile(path):
                with io.open(path, encoding='utf-8') as fh:
                    current = fh.read()
            if current == body:
                continue
            stale.append('%s (%s)' % (pack_id, lang))
            if not check:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
                    fh.write(body)
    if check:
        if stale:
            print('stale dashboards: %s (run tools/build_pack_dashboards.py)' % ', '.join(stale))
            return 1
        print('%d dashboards up to date (%s)' % (len(packs), ', '.join(LANGS)))
        return 0
    print('%d written, %d unchanged' % (len(stale), len(packs) * len(LANGS) - len(stale)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
