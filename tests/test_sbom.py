"""sbom.cdx.json (CycloneDX 1.5): committed, current, and covering what the tool needs."""
import importlib.util
import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load():
    spec = importlib.util.spec_from_file_location('make_sbom', os.path.join(ROOT, 'tools', 'make_sbom.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def vtuple(v):
    return tuple(int(x) for x in re.findall(r'\d+', v))


class TestSbom(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        with open(os.path.join(ROOT, 'sbom.cdx.json'), encoding='utf-8') as fh:
            self.text = fh.read()
        self.bom = json.loads(self.text)

    def test_committed_file_is_current(self):
        if not os.path.isdir(os.path.join(ROOT, 'offline_packages')):
            self.skipTest('the wheels are not in this tree')
        self.assertEqual(self.text, self.mod.render(), 'run tools/make_sbom.py')

    def test_shape(self):
        b = self.bom
        self.assertEqual((b['bomFormat'], b['specVersion']), ('CycloneDX', '1.5'))
        with open(os.path.join(ROOT, 'lib', '__init__.py'), encoding='utf-8') as fh:
            version = re.search(r'__version__\s*=\s*"([^"]+)"', fh.read()).group(1)
        self.assertEqual(b['metadata']['component']['version'], version)
        refs = [c['bom-ref'] for c in b['components']]
        self.assertEqual(len(refs), len(set(refs)))
        self.assertEqual(sorted(b['dependencies'][0]['dependsOn']), sorted(refs))
        for c in b['components']:
            with self.subTest(component=c['name']):
                self.assertTrue(c.get('licenses'), 'every component names its licence')

    def test_every_requirement_is_listed_at_an_allowed_version(self):
        have = {}
        for c in self.bom['components']:
            if c['purl'].startswith('pkg:pypi/'):
                have.setdefault(c['name'], []).append(c['version'])
        with open(os.path.join(ROOT, 'requirements.txt'), encoding='utf-8') as fh:
            for line in fh:
                m = re.match(r'^([A-Za-z0-9_.-]+)\s*>=\s*([0-9][0-9.]*)', line.strip())
                if not m:
                    continue
                name = m.group(1).lower().replace('_', '-')
                with self.subTest(requirement=name):
                    self.assertIn(name, have)
                    for v in have[name]:
                        self.assertGreaterEqual(vtuple(v), vtuple(m.group(2)))

    def test_browser_libraries_and_trivy(self):
        names = {c['name']: c for c in self.bom['components']}
        self.assertIn('codemirror', names)
        self.assertTrue(all(r['comment'].startswith('SRI sha384-') for r in names['codemirror']['externalReferences']))
        self.assertEqual(names['trivy']['type'], 'container')
        self.assertRegex(names['trivy']['hashes'][0]['content'], r'^[0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
