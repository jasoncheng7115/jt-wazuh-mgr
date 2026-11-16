#!/usr/bin/env python3
"""CycloneDX 1.5 SBOM of what a jt-wazuh-mgr release uses: sbom.cdx.json at the top of the tree.

    tools/make_sbom.py            write sbom.cdx.json
    tools/make_sbom.py --check    exit 1 if the committed file is stale

Components:
  - the Python packages the tool runs on, at the versions it was built and tested with: the wheels in
    offline_packages/ (what `install.sh --offline` installs and what the production managers run).
    An online install resolves requirements.txt at install time and may get newer versions; the
    SBOM says so in a property. Two wheels of one version for different Pythons are one component.
  - the browser libraries the interface loads from cdnjs (CodeMirror), with their SRI hashes;
  - the Trivy container image the jt-container-vuln pack runs on agent hosts, pinned by digest.
The rule packs themselves are Wazuh rules, decoders, lists and Python scripts that use the standard
library only, so they add no components of their own.

The output is a pure function of the tree (no timestamp, the serial number derives from the version),
so it can be committed and checked like the pack dashboards.
"""
import glob
import hashlib
import io
import json
import os
import re
import sys
import uuid
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'sbom.cdx.json')
WHEELS = os.path.join(ROOT, 'offline_packages')
NAMESPACE = uuid.UUID('6b1d1f2c-3c1e-4a8e-9a55-6a7a2f1c0e11')     # fixed: same version -> same serial

# classifier -> SPDX id, for wheels that carry no License-Expression / License field
CLASSIFIERS = {'MIT License': 'MIT', 'BSD License': 'BSD-3-Clause', 'Apache Software License': 'Apache-2.0',
               'Mozilla Public License 2.0 (MPL 2.0)': 'MPL-2.0'}
SPDX = re.compile(r'^[A-Za-z0-9.+-]+(?: (?:AND|OR|WITH) [A-Za-z0-9.+-]+)*$')


def version():
    with io.open(os.path.join(ROOT, 'lib', '__init__.py'), encoding='utf-8') as fh:
        return re.search(r'__version__\s*=\s*"([^"]+)"', fh.read()).group(1)


def wheel_meta(path):
    with zipfile.ZipFile(path) as z:
        name = next(n for n in z.namelist() if n.endswith('.dist-info/METADATA'))
        head = z.read(name).decode('utf-8', 'replace').split('\n\n', 1)[0]
    meta = {}
    for line in head.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            meta.setdefault(k.strip(), []).append(v.strip())
    lic = (meta.get('License-Expression') or [None])[0] or (meta.get('License') or [None])[0]
    if not lic or not SPDX.match(lic):
        for c in meta.get('Classifier', []):
            m = re.match(r'License :: OSI Approved :: (.+)$', c)
            if m and m.group(1) in CLASSIFIERS:
                lic = CLASSIFIERS[m.group(1)]
                break
    return meta['Name'][0], meta['Version'][0], lic


def python_components():
    by = {}
    for path in sorted(glob.glob(os.path.join(WHEELS, '*.whl'))):
        name, ver, lic = wheel_meta(path)
        with open(path, 'rb') as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        key = (name.lower().replace('_', '-'), ver)
        c = by.setdefault(key, {'name': key[0], 'version': ver, 'license': lic, 'wheels': []})
        c['wheels'].append((os.path.basename(path), digest))
    out = []
    for (name, ver), c in sorted(by.items()):
        purl = 'pkg:pypi/%s@%s' % (name, ver)
        comp = {'type': 'library', 'name': name, 'version': ver, 'purl': purl, 'bom-ref': purl,
                'properties': [{'name': 'jt-wazuh-mgr:wheel', 'value': '%s sha256:%s' % w} for w in c['wheels']]}
        if len(c['wheels']) == 1:
            comp['hashes'] = [{'alg': 'SHA-256', 'content': c['wheels'][0][1]}]
        if c['license']:
            key = 'id' if ' ' not in c['license'] else 'expression'
            comp['licenses'] = [{'license': {'id': c['license']}}] if key == 'id' else [{'expression': c['license']}]
        out.append(comp)
    return out


def browser_components():
    with io.open(os.path.join(ROOT, 'lib', 'web_ui.py'), encoding='utf-8') as fh:
        text = fh.read()
    files = {}
    for url, sri in re.findall(r'(https://cdnjs\.cloudflare\.com/ajax/libs/[^"]+)"\s+integrity="(sha384-[^"]+)"', text):
        m = re.match(r'https://cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)/', url)
        files.setdefault((m.group(1), m.group(2)), []).append((url, sri))
    out = []
    for (name, ver), refs in sorted(files.items()):
        purl = 'pkg:npm/%s@%s' % (name, ver)
        out.append({'type': 'library', 'name': name, 'version': ver, 'purl': purl, 'bom-ref': purl,
                    'licenses': [{'license': {'id': 'MIT'}}],
                    'externalReferences': [{'type': 'distribution', 'url': u, 'comment': 'SRI ' + s}
                                           for u, s in sorted(set(refs))],
                    'properties': [{'name': 'jt-wazuh-mgr:location',
                                    'value': 'loaded by the browser from cdnjs (subresource integrity checked); '
                                             'the editor works without it'}]})
    return out


def trivy_component():
    with io.open(os.path.join(ROOT, 'packs', 'jt-container-vuln', 'agent', 'jt-container-vuln.py'),
                 encoding='utf-8') as fh:
        text = fh.read()
    m = re.search(r'DEFAULT_TRIVY_IMAGE = \("([^"]+)"\s*"([0-9a-f]{64})"\)', text)
    if not m:
        return []
    image, digest = m.group(1).rstrip(':').split('@')[0], m.group(2)
    tag = re.search(r'refs/tags/v([0-9.]+)', text)
    ver = tag.group(1) if tag else None
    purl = 'pkg:oci/trivy@sha256%%3A%s?repository_url=%s' % (digest, image.replace('/trivy', ''))
    comp = {'type': 'container', 'name': 'trivy', 'purl': purl, 'bom-ref': purl,
            'hashes': [{'alg': 'SHA-256', 'content': digest}],
            'licenses': [{'license': {'id': 'Apache-2.0'}}],
            'properties': [{'name': 'jt-wazuh-mgr:location',
                            'value': 'run on agent hosts by the jt-container-vuln pack (pinned by digest; '
                                     'TRIVY_IMAGE can replace it)'}]}
    if ver:
        comp['version'] = ver
    return [comp]


def bom():
    v = version()
    comps = python_components() + browser_components() + trivy_component()
    ref = 'pkg:github/jasoncheng7115/jt-wazuh-mgr@v%s' % v
    return {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'serialNumber': 'urn:uuid:%s' % uuid.uuid5(NAMESPACE, v),
        'metadata': {
            'component': {'type': 'application', 'name': 'jt-wazuh-mgr', 'version': v, 'purl': ref,
                          'bom-ref': ref, 'licenses': [{'license': {'id': 'AGPL-3.0-or-later'}}]},
            'properties': [
                {'name': 'jt-wazuh-mgr:python-packages',
                 'value': 'the versions jt-wazuh-mgr was built and tested with (offline install); an online '
                          'install resolves requirements.txt at install time and may get newer ones'},
                {'name': 'jt-wazuh-mgr:python', 'value': '3.10 or newer'}]},
        'components': comps,
        'dependencies': [{'ref': ref, 'dependsOn': [c['bom-ref'] for c in comps]}],
    }


def render():
    return json.dumps(bom(), indent=1, ensure_ascii=False, sort_keys=True) + '\n'


def main(argv):
    text = render()
    if '--check' in argv:
        try:
            with io.open(OUT, encoding='utf-8') as fh:
                same = fh.read() == text
        except OSError:
            same = False
        if not same:
            print('sbom.cdx.json is stale: run tools/make_sbom.py')
            return 1
        return 0
    with io.open(OUT, 'w', encoding='utf-8') as fh:
        fh.write(text)
    print(OUT)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
