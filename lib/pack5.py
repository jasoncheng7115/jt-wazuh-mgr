"""Rule packs on Wazuh 5.x (beta).

On 5.x the ruleset lives in the indexer: decoders, KVDBs and Sigma rules are documents managed through
the Content Manager API (/_plugins/_content_manager/...), promoted draft -> test -> custom; detection
runs in the indexer's Security Analytics detectors, and the 4.x frequency rules become Alerting
bucket-level monitors. A pack's 5.x content is in packs/<id>/v5/ (see tools/pack5_dev.py for the
layout); the root and syslog-header decoders every pack hangs under are the integration "jt-base" in
packs5-base/.

The draft space may hold the site's own unfinished work, so nothing here resets a space: a pack's
resources are created next to whatever is there, and each promotion carries only the changes that
belong to the pack (plus the policy, which a promotion always copies whole). The installed version is
written into the integration's metadata.documentation, so the indexer itself says what is installed.
"""

import json
import os

import yaml

from . import __version__

CM = '/_plugins/_content_manager'
SA = '/_plugins/_security_analytics'
ALERTING = '/_plugins/_alerting'
BASE_TITLE = 'jt-base'
ROOT_DECODER = 'decoder/jt-core/0'
MARK = 'jt-wazuh-mgr pack'
SEVERITY = {'critical': '1', 'high': '2', 'medium': '3', 'low': '4', 'informational': '5'}
# Security Analytics and the Content Manager ship with limits sized for a handful of user rules.
SETTINGS_FLOOR = {
    'plugins.content_manager.max_rules': 4000,
    'plugins.content_manager.max_decoders': 1000,
    'plugins.security_analytics.max_rules_per_detector': 400,
    'plugins.security_analytics.max_detectors': 60,
}


class Pack5Error(Exception):
    pass


# --- reading the packs on disk ------------------------------------------------------------------

def _docs(directory):
    out = []
    for name in sorted(os.listdir(directory)) if os.path.isdir(directory) else []:
        if name.endswith(('.yml', '.yaml')):
            with open(os.path.join(directory, name), encoding='utf-8') as fh:
                for doc in yaml.safe_load_all(fh):
                    if doc:
                        out.extend(doc if isinstance(doc, list) else [doc])
    return out


def load(directory):
    """One integration directory (a pack's v5/ or packs5-base/)."""
    with open(os.path.join(directory, 'integration.yml'), encoding='utf-8') as fh:
        integ = yaml.safe_load(fh)
    det = {}
    if os.path.exists(os.path.join(directory, 'detector.yml')):
        with open(os.path.join(directory, 'detector.yml'), encoding='utf-8') as fh:
            det = yaml.safe_load(fh) or {}
    return {'integration': integ, 'decoders': _docs(os.path.join(directory, 'decoders')),
            'kvdbs': _docs(os.path.join(directory, 'kvdbs')), 'rules': _docs(os.path.join(directory, 'rules')),
            'monitors': _docs(os.path.join(directory, 'monitors')), 'detector': det}


def catalog(packs_dir):
    """Packs that have 5.x content, with what a person needs to choose them."""
    out = []
    for pid in sorted(os.listdir(packs_dir)):
        v5 = os.path.join(packs_dir, pid, 'v5')
        mf = os.path.join(packs_dir, pid, 'manifest.json')
        if not (os.path.isfile(os.path.join(v5, 'integration.yml')) and os.path.isfile(mf)):
            continue
        with open(mf, encoding='utf-8') as fh:
            m = json.load(fh)
        c = load(v5)
        out.append({'id': pid, 'name': m.get('name', pid), 'name_zh': m.get('name_zh', ''),
                    'summary': m.get('summary', ''), 'summary_zh': m.get('summary_zh', ''),
                    'version': m.get('version', ''), 'beta': True,
                    'decoders': len(c['decoders']), 'rules': len(c['rules']), 'monitors': len(c['monitors']),
                    'kvdbs': len(c['kvdbs']), 'rules_only': not c['decoders'],
                    'agent_group': bool(m.get('agent_group')),
                    'notes_file': os.path.isfile(os.path.join(v5, 'PORTING.md'))})
    return out


# --- the indexer ----------------------------------------------------------------------------------

class Indexer:
    """Minimal client for the Wazuh 5.x indexer. The credentials are used for this request only."""

    def __init__(self, url, username, password, verify=True, http=None):
        if http is None:
            import requests as http
        self.url = url.rstrip('/')
        self.auth = (username, password)
        self.verify = verify
        self.http = http

    def call(self, method, path, body=None, ok=(200, 201)):
        r = self.http.request(method, self.url + path, auth=self.auth, verify=self.verify, timeout=120,
                              json=body, headers={'Content-Type': 'application/json'})
        try:
            data = r.json()
        except ValueError:
            data = {'raw': r.text[:500]}
        if r.status_code not in ok:
            msg = data.get('message') if isinstance(data, dict) else None
            if isinstance(data, dict) and isinstance(data.get('error'), dict):
                msg = data['error'].get('reason') or msg
            raise Pack5Error('%s %s: HTTP %s %s' % (method, path.split('?')[0], r.status_code, msg or data))
        return data

    def search(self, index, query, size=500, source=None):
        body = {'size': size, 'query': query}
        if source:
            body['_source'] = source
        return self.call('POST', '/%s/_search' % index, body, ok=(200, 404)).get('hits', {}).get('hits', [])


def _space_docs(ix, kind, space, query=None):
    q = {'bool': {'filter': [{'term': {'space.name': space}}] + ([query] if query else [])}}
    return [h['_source'].get('document', {}) for h in ix.search('wazuh-threatintel-%s-a' % kind, q)]


def integration(ix, title, space):
    for d in _space_docs(ix, 'integrations', space, {'match_phrase': {'document.metadata.title': title}}):
        if (d.get('metadata') or {}).get('title') == title:
            return d
    return None


def policy(ix, space):
    docs = _space_docs(ix, 'policies', space)
    return docs[0] if docs else {}


# --- status ---------------------------------------------------------------------------------------

def status(ix, packs_dir):
    """Which packs are installed (custom space), at which version, with detector and monitors."""
    installed = {}
    for d in _space_docs(ix, 'integrations', 'custom'):
        doc = (d.get('metadata') or {}).get('documentation') or ''
        if doc.startswith(MARK):
            installed[d['metadata']['title']] = doc.split()[3] if len(doc.split()) > 3 else ''
    dets = _detectors(ix)
    mons = _monitor_names(ix)
    out = {}
    for p in catalog(packs_dir):
        pid = p['id']
        out[pid] = {'installed_version': installed.get(pid), 'detector': pid in dets,
                    'monitors': len([n for n in mons if n.startswith('[%s] ' % pid)])}
    return out


def _detectors(ix):
    res = ix.call('POST', SA + '/detectors/_search', {'size': 500, 'query': {'match_all': {}}}, ok=(200, 404))
    return {h['_source'].get('name'): h['_id'] for h in (res.get('hits') or {}).get('hits', [])}


def _monitor_names(ix):
    res = ix.call('POST', ALERTING + '/monitors/_search', {'size': 1000, 'query': {'match_all': {}}}, ok=(200, 404))
    return {h['_source'].get('name', ''): h['_id'] for h in (res.get('hits') or {}).get('hits', [])
            if h['_source'].get('name')}


# --- install / update -----------------------------------------------------------------------------

def _delete_integration_draft(ix, title, log):
    """Remove an integration and everything under it from the draft space; returns the removed ids."""
    integ = integration(ix, title, 'draft')
    if not integ:
        return set()
    gone = set()
    for kind, key in (('rules', 'rules'), ('decoders', 'decoders'), ('kvdbs', 'kvdbs')):
        for rid in integ.get(key) or []:
            ix.call('DELETE', '%s/%s/%s' % (CM, kind, rid), ok=(200, 404))
            gone.add(rid)
    ix.call('DELETE', '%s/integrations/%s' % (CM, integ['id']), ok=(200, 404))
    gone.add(integ['id'])
    log.append('draft: removed %s (%d resources)' % (title, len(gone) - 1))
    return gone


def _create(ix, content, version, pack_id, log):
    """Create an integration with its KVDBs, decoders and rules in draft; returns (id, ids, decoder ids by name)."""
    integ = dict(content['integration'])
    meta = dict(integ.get('metadata') or {})
    meta['documentation'] = '%s %s %s (Wazuh 5.x beta, jt-wazuh-mgr %s)' % (MARK, pack_id, version, __version__)
    integ['metadata'] = meta
    title = meta['title']
    iid = ix.call('POST', CM + '/integrations', {'resource': integ})['message']
    ids, names = {iid}, {}
    for k in content['kvdbs']:
        ids.add(ix.call('POST', CM + '/kvdbs', {'integration': iid, 'resource': k})['message'])
    for d in content['decoders']:
        did = ix.call('POST', CM + '/decoders', {'integration': iid, 'resource': d})['message']
        ids.add(did)
        names[d['name']] = did
    for r in content['rules']:
        r = dict(r)
        r['logsource'] = dict(r.get('logsource') or {}, product=title)
        ids.add(ix.call('POST', CM + '/rules', {'integration': iid, 'resource': r})['message'])
    log.append('draft: created %s (%d decoders, %d kvdbs, %d rules)' % (
        title, len(content['decoders']), len(content['kvdbs']), len(content['rules'])))
    return iid, ids, names


def _promote(ix, space, ids, log):
    """Promote only the changes that touch ids (and the policy) from space to the next one."""
    preview = ix.call('GET', CM + '/promote?space=' + space)
    changes = preview.get('changes') or (preview.get('message') or {}).get('changes') or {}
    mine = {k: [c for c in v if k == 'policy' or c.get('id') in ids] for k, v in changes.items()}
    if not any(mine[k] for k in mine if k != 'policy'):
        return
    ix.call('POST', CM + '/promote', {'space': space, 'changes': mine})
    log.append('promoted %s -> %s (%d changes)' % (space, 'test' if space == 'draft' else 'custom',
                                                    sum(len(v) for k, v in mine.items() if k != 'policy')))


def _ensure_settings(ix, log):
    cur = ix.call('GET', '/_cluster/settings?include_defaults=true&flat_settings=true')
    merged = {}
    for part in ('defaults', 'persistent', 'transient'):
        merged.update(cur.get(part) or {})
    raise_ = {k: v for k, v in SETTINGS_FLOOR.items() if k in merged and int(merged[k]) < v}
    if raise_:
        ix.call('PUT', '/_cluster/settings', {'persistent': raise_})
        log.append('raised limits: %s' % ', '.join('%s=%s' % kv for kv in sorted(raise_.items())))


def _detector(ix, pack_id, content, log):
    title = content['integration']['metadata']['title']
    q = {'bool': {'filter': [{'match_phrase': {'document.logsource.product': title}}, {'term': {'space.name': 'custom'}}]}}
    rule_ids = [h['_source']['document']['id'] for h in ix.search('wazuh-threatintel-rules-a', q, source=['document.id'])]
    if not rule_ids:
        return
    indices = content['detector'].get('indices') or ['wazuh-events-v5-%s' % content['integration']['category']]
    det = {'type': 'detector', 'name': title, 'detector_type': title, 'enabled': True,
           'schedule': {'period': {'interval': 1, 'unit': 'MINUTES'}},
           'inputs': [{'detector_input': {'description': '%s %s (Wazuh 5.x beta)' % (MARK, pack_id),
                                          'indices': indices, 'custom_rules': [{'id': i} for i in rule_ids],
                                          'pre_packaged_rules': []}}], 'triggers': []}
    ix.call('POST', SA + '/detectors', det)
    log.append('detector %s: %d rules over %s' % (title, len(rule_ids), ', '.join(indices)))


def monitor_body(pack_id, m):
    index = 'wazuh-findings-v5-*' if m['source'] == 'findings' else 'wazuh-events-v5-*'
    filters = [{'terms': {f: v}} if isinstance(v, list) else {'term': {f: v}} for f, v in m['match'].items()]
    filters.append({'range': {'@timestamp': {'gte': '{{period_end}}||-%s' % m['window'], 'lte': '{{period_end}}',
                                             'format': 'epoch_millis'}}})
    comp = {'composite': {'size': 1000, 'sources': [{f.replace('.', '_'): {'terms': {'field': f}}}
                                                    for f in m['group_by']]}}
    if 'distinct' in m:
        comp['aggregations'] = {'distinct': {'cardinality': {'field': m['distinct']['field']}}}
        path, script = {'distinct': 'distinct'}, 'params.distinct >= %d' % m['distinct']['gte']
        what = '%d or more different %s' % (m['distinct']['gte'], m['distinct']['field'])
    else:
        path, script = {'count': '_count'}, 'params.count >= %d' % m['count']
        what = '%d or more' % m['count']
    return {'type': 'monitor', 'monitor_type': 'bucket_level_monitor', 'enabled': True,
            'name': '[%s] %s %s' % (pack_id, m['id'], m['title']),
            'schedule': {'period': {'interval': 1, 'unit': 'MINUTES'}},
            'inputs': [{'search': {'indices': [index], 'query': {
                'size': 0, 'query': {'bool': {'filter': filters}}, 'aggregations': {'groups': comp}}}}],
            'triggers': [{'bucket_level_trigger': {
                'name': '%s within %s' % (what, m['window']), 'severity': SEVERITY[m['level']],
                'condition': {'buckets_path': path, 'parent_bucket_path': 'groups',
                              'script': {'source': script, 'lang': 'painless'}},
                'actions': []}}]}


def _monitors(ix, pack_id, content, log, remove_only=False):
    for name, mid in _monitor_names(ix).items():
        if name.startswith('[%s] ' % pack_id):
            ix.call('DELETE', '%s/monitors/%s' % (ALERTING, mid), ok=(200, 404))
    if remove_only:
        return
    for m in content['monitors']:
        ix.call('POST', ALERTING + '/monitors', monitor_body(pack_id, m))
    if content['monitors']:
        log.append('monitors: %d' % len(content['monitors']))


def _delete_detector(ix, title):
    did = _detectors(ix).get(title)
    if did:
        ix.call('DELETE', '%s/detectors/%s' % (SA, did), ok=(200, 404))


def install(ix, packs_dir, base_dir, pack_id, version):
    """Install or update one pack. Returns the list of steps taken; raises Pack5Error on the first failure."""
    v5 = os.path.join(packs_dir, pack_id, 'v5')
    if not os.path.isfile(os.path.join(v5, 'integration.yml')):
        raise Pack5Error('%s has no Wazuh 5.x content' % pack_id)
    content, base = load(v5), load(base_dir)
    title = content['integration']['metadata']['title']
    log = []
    _ensure_settings(ix, log)

    pol = policy(ix, 'draft')
    base_integ = integration(ix, BASE_TITLE, 'draft')
    root = pol.get('root_decoder') or ''
    touched = set()
    if not base_integ:
        bid, bids, bnames = _create(ix, base, version, BASE_TITLE, log)
        touched |= bids
        root_id = bnames[ROOT_DECODER]
    else:
        bid = base_integ['id']
        root_id = next((d['id'] for d in _space_docs(ix, 'decoders', 'draft', {'match_phrase': {'document.name': ROOT_DECODER}})
                        if d.get('name') == ROOT_DECODER), None)
    if root and root != root_id:
        raise Pack5Error('the custom space already has a root decoder of its own (%s); jt-wazuh-mgr packs need '
                         'their root %s, so they cannot be installed next to it in this beta' % (root, ROOT_DECODER))

    _delete_detector(ix, title)                     # promotions refuse to leave a detector without rules
    touched |= _delete_integration_draft(ix, title, log)
    iid, ids, _ = _create(ix, content, version, pack_id, log)
    touched |= ids

    pol = policy(ix, 'draft')
    order = [i for i in (pol.get('integrations') or []) if i != bid]
    meta = dict(pol.get('metadata') or {})
    for k, v in (('author', 'jt-wazuh-mgr'), ('description', 'Custom content'), ('documentation', ''),
                 ('references', ['https://github.com/jasoncheng7115/jt-wazuh-mgr'])):
        meta.setdefault(k, v)
    ix.call('PUT', CM + '/policy/draft', {'resource': {
        'metadata': meta, 'root_decoder': root_id, 'integrations': [bid] + order,
        'filters': pol.get('filters') or [], 'enrichments': pol.get('enrichments') or [], 'enabled': True,
        'index_unclassified_events': bool(pol.get('index_unclassified_events', False)),
        'index_discarded_events': bool(pol.get('index_discarded_events', False))}})

    _promote(ix, 'draft', touched, log)
    _promote(ix, 'test', touched, log)
    _detector(ix, pack_id, content, log)
    _monitors(ix, pack_id, content, log)
    return log


def remove(ix, packs_dir, pack_id):
    v5 = os.path.join(packs_dir, pack_id, 'v5')
    content = load(v5)
    title = content['integration']['metadata']['title']
    log = []
    _monitors(ix, pack_id, content, log, remove_only=True)
    _delete_detector(ix, title)
    gone = _delete_integration_draft(ix, title, log)
    if gone:
        _promote(ix, 'draft', gone, log)
        _promote(ix, 'test', gone, log)
    log.append('removed %s' % pack_id)
    return log
