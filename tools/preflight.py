#!/usr/bin/env python3
"""Pre-release checks for JT Wazuh Manager.

Everything here exists because it was missed at least once. A checklist that
relies on memory fails quietly -- the version badge in the READMEs sat at 1.6.0
for nine releases while the checklist said to update it, and a decoder comment
carrying a real hostname and client IP shipped in a published pack despite a
written rule against exactly that.

Run from the project root:

    python3 tools/preflight.py

Exits non-zero if any check fails. Warnings do not fail the run but are worth
reading before tagging a release.

Standard library only, so it runs on the development host without the offline
wheels. It checks what can be checked mechanically; the steps it cannot cover --
the ZAP baseline scan, deploying, and verifying the cluster -- are listed at the
end as a reminder.
"""

import glob
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GITHUB = os.path.join(ROOT, 'github')

FAILURES = []
WARNINGS = []


def fail(check, detail):
    FAILURES.append((check, detail))


def warn(check, detail):
    WARNINGS.append((check, detail))


def read(path, binary=False):
    mode, enc = ('rb', None) if binary else ('r', 'utf-8')
    with io.open(path, mode, encoding=enc, errors=None if binary else 'ignore') as fh:
        return fh.read()


def current_version():
    m = re.search(r'__version__\s*=\s*[\'"]([^\'"]+)[\'"]',
                  read(os.path.join(ROOT, 'lib', '__init__.py')))
    return m.group(1) if m else None


# ---------------------------------------------------------------------------

def check_version_consistency(version):
    """The badge in the READMEs and on the Pages site must match lib/__init__."""
    gh_init = os.path.join(GITHUB, 'lib', '__init__.py')
    if os.path.isfile(gh_init):
        m = re.search(r'__version__\s*=\s*[\'"]([^\'"]+)[\'"]', read(gh_init))
        if not m or m.group(1) != version:
            fail('version', 'github/lib/__init__.py is %s, expected %s'
                 % (m.group(1) if m else 'unreadable', version))

    for rel in ('README.md', 'README-zh-TW.md',
                'github/README.md', 'github/README-zh-TW.md',
                'github/docs/index.html'):
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        badges = set(re.findall(r'version-([0-9]+\.[0-9]+\.[0-9]+)', read(path)))
        stale = badges - {version}
        if stale:
            fail('version', '%s carries badge %s, expected %s'
                 % (rel, ', '.join(sorted(stale)), version))


def check_changelog(version):
    for rel in ('github/CHANGELOG.md', 'github/CHANGELOG-zh-TW.md'):
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            fail('changelog', '%s is missing' % rel)
            continue
        if not re.search(r'^##\s*v' + re.escape(version) + r'\b', read(path), re.M):
            fail('changelog', '%s has no entry for v%s' % (rel, version))


def check_github_mirror():
    """Files that exist in both trees must be identical."""
    for rel in ('lib/web_ui.py', 'lib/i18n_engine.js', 'lib/__init__.py',
                'lib/config.py', 'lib/wazuh_api.py', 'lib/wazuh_cli.py',
                'tests/test_web_ui.py', 'wazuh_agent_mgr.py',
                'install.sh', 'uninstall.sh', 'README.md', 'README-zh-TW.md'):
        a, b = os.path.join(ROOT, rel), os.path.join(GITHUB, rel)
        if os.path.isfile(a) and os.path.isfile(b) and read(a, True) != read(b, True):
            fail('mirror', '%s differs between the working tree and github/' % rel)

    src = {os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, 'packs', '*', '*', '*'))}
    dst = {os.path.relpath(p, GITHUB) for p in glob.glob(os.path.join(GITHUB, 'packs', '*', '*', '*'))}
    for rel in sorted(src ^ dst):
        fail('mirror', 'packs/ differs: %s' % rel)
    for rel in sorted(src & dst):
        if read(os.path.join(ROOT, rel), True) != read(os.path.join(GITHUB, rel), True):
            fail('mirror', '%s differs between the working tree and github/' % rel)


# A dotted quad, all four octets present and in range, not part of a longer
# dotted string. Without the length guard a version like 10.1.20 reads as an
# address and every Zimbra manifest trips the check.
_OCTET = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
INTERNAL = re.compile(
    r'(?<![\w.])(?:'
    r'192\.168\.' + _OCTET + r'\.' + _OCTET +
    r'|10\.' + _OCTET + r'\.' + _OCTET + r'\.' + _OCTET +
    r'|172\.(?:1[6-9]|2\d|3[01])\.' + _OCTET + r'\.' + _OCTET +
    r')(?![\w.])'
    r'|\b(?:edr1|edr2|dnsp1|revproxy1|jt-glogarch)\b'  # preflight:allow-example
    r'|\b[\w.+-]+@(?!example\.)[\w-]+\.[a-z]{2,}\b'
)
# Addresses conventionally used as documentation placeholders, not real hosts.
PLACEHOLDER = re.compile(
    r'^(?:192\.168\.1\.(?:1|10|100)|192\.168\.0\.\d{1,3}|10\.0\.\d{1,3}\.\d{1,3})$')


def check_no_internal_data():
    """Nothing published may name a real host, address or mailbox."""
    for path in glob.glob(os.path.join(GITHUB, '**', '*'), recursive=True):
        if not os.path.isfile(path):
            continue
        rel = os.path.relpath(path, GITHUB)
        if rel.startswith(('.git' + os.sep, 'screenshots' + os.sep, 'images' + os.sep)):
            continue
        if rel.startswith('CHANGELOG'):
            continue  # release notes legitimately quote measurements
        if os.path.splitext(rel)[1] not in ('.py', '.js', '.xml', '.json', '.md',
                                            '.sh', '.html', '.yaml', '.yml', '.txt', ''):
            continue
        try:
            body = read(path)
        except Exception:
            continue
        for lineno, line in enumerate(body.split('\n'), 1):
            # A line may opt out with an explicit marker. Used by this file and
            # by the tests that pin the pattern, which have to contain real-
            # looking values to be worth anything. Deliberately per-line rather
            # than per-file, so exempting tests/ wholesale is not an option.
            if ALLOW_MARKER in line:
                continue
            m = INTERNAL.search(line)
            if m and not PLACEHOLDER.search(m.group(0)):
                fail('privacy', '%s:%d names %s' % (rel, lineno, m.group(0)))


ALLOW_MARKER = 'preflight' + ':allow-example'

SUBDIR = {'rule': 'rules', 'list': 'lists', 'decoder': 'decoders'}


def check_packs():
    manifests = sorted(glob.glob(os.path.join(ROOT, 'packs', '*', 'manifest.json')))
    if not manifests:
        warn('packs', 'no packs found')
        return
    seen_ids = {}
    for mf in manifests:
        pdir = os.path.dirname(mf)
        pack = os.path.basename(pdir)
        try:
            m = json.loads(read(mf))
        except Exception as e:
            fail('packs', '%s: manifest is not valid JSON (%s)' % (pack, e))
            continue

        for field in ('id', 'name', 'name_zh', 'version', 'summary', 'summary_zh',
                      'notes', 'notes_zh', 'author', 'license', 'files'):
            if field not in m:
                fail('packs', '%s: manifest has no %s' % (pack, field))

        declared = m.get('rule_id_range', '')
        lo = hi = None
        rng = re.match(r'^(\d+)\s*-\s*(\d+)$', declared)
        if rng:
            lo, hi = int(rng.group(1)), int(rng.group(2))

        for entry in m.get('files', []):
            name, etype = entry.get('name', ''), entry.get('type', '')
            if etype not in SUBDIR:
                fail('packs', '%s: unknown file type %r' % (pack, etype))
                continue
            path = os.path.join(pdir, SUBDIR[etype], name)
            if not os.path.isfile(path):
                fail('packs', '%s: %s is listed but missing' % (pack, name))
                continue
            digest = hashlib.sha256(read(path, True)).hexdigest()
            if digest != entry.get('sha256'):
                fail('packs', '%s: %s has a stale sha256 in the manifest' % (pack, name))
            dest = entry.get('dest', '')
            if '..' in dest or dest.startswith('/') or not dest.startswith('etc/'):
                fail('packs', '%s: unsafe dest %r' % (pack, dest))
            elif not dest.startswith('etc/%s/' % SUBDIR[etype]):
                fail('packs', '%s: %s installs to %s, which does not match its type'
                     % (pack, name, dest))

            if etype in ('rule', 'decoder'):
                import xml.etree.ElementTree as ET
                wrapper = 'rules' if etype == 'rule' else 'decoders'
                try:
                    ET.fromstring('<%s>%s</%s>' % (wrapper, read(path), wrapper))
                except Exception as e:
                    fail('packs', '%s: %s is not well-formed XML (%s)' % (pack, name, e))

            if etype == 'rule':
                body = read(path)
                for rid in re.findall(r'<rule id="(\d+)"', body):
                    if rid in seen_ids and seen_ids[rid] != pack:
                        fail('packs', 'rule %s appears in both %s and %s'
                             % (rid, seen_ids[rid], pack))
                    seen_ids[rid] = pack
                    if lo is not None and not (lo <= int(rid) <= hi):
                        fail('packs', '%s: rule %s is outside the declared range %s'
                             % (pack, rid, declared))
                for desc in re.findall(r'<description>(.*?)</description>', body, re.S):
                    if re.search(r'[一-鿿]', desc):
                        fail('i18n', '%s: %s has a non-English description: %s'
                             % (pack, name, ' '.join(desc.split())[:60]))
                check_correlation_levels(pack, name, body)


def check_correlation_levels(pack, name, body):
    """<if_matched_sid> does not fire against a level 0 rule.

    Measured on Wazuh 4.14.7: with the parent at level 0 the frequency rule never
    triggers however many events arrive. Level 0 means "stop processing", not
    merely "do not alert", so a silent parent must be level 1 or 2.
    """
    levels = {rid: int(lv) for rid, lv in
              re.findall(r'<rule id="(\d+)"[^>]*level="(\d+)"', body)}
    for block in re.findall(r'<rule id="(\d+)".*?</rule>', body, re.S):
        pass
    for m in re.finditer(r'<rule id="(\d+)"[^>]*>(.*?)</rule>', body, re.S):
        for parent in re.findall(r'<if_matched_sid>(\d+)</if_matched_sid>', m.group(2)):
            if levels.get(parent) == 0:
                fail('rules', '%s: rule %s correlates on %s, which is level 0 and '
                              'therefore never fires' % (pack, m.group(1), parent))


def check_index():
    idx = os.path.join(ROOT, 'packs', 'INDEX')
    if not os.path.isfile(idx):
        fail('packs', 'packs/INDEX is missing')
        return
    listed = sorted(l.strip() for l in read(idx).split('\n') if l.strip())
    actual = sorted(
        os.path.relpath(p, ROOT)
        for p in glob.glob(os.path.join(ROOT, 'packs', '**', '*'), recursive=True)
        if os.path.isfile(p) and os.path.basename(p) != 'INDEX')
    if listed != actual:
        missing = set(actual) - set(listed)
        extra = set(listed) - set(actual)
        if missing:
            fail('packs', 'packs/INDEX omits: %s' % ', '.join(sorted(missing)))
        if extra:
            fail('packs', 'packs/INDEX lists files that do not exist: %s'
                 % ', '.join(sorted(extra)))
    gh_idx = os.path.join(GITHUB, 'packs', 'INDEX')
    if os.path.isfile(gh_idx) and read(gh_idx) != read(idx):
        fail('packs', 'github/packs/INDEX differs from packs/INDEX')


def check_i18n_build():
    """web_ui.py embeds i18n_engine.js; a stale copy silently ships old strings."""
    engine = os.path.join(ROOT, 'lib', 'i18n_engine.js')
    web = os.path.join(ROOT, 'lib', 'web_ui.py')
    if not (os.path.isfile(engine) and os.path.isfile(web)):
        return
    src, embedded = read(engine), read(web)
    keys = re.findall(r"^\s{6}'([^']{4,80})':\s*'", src, re.M)
    missing = [k for k in keys if ("'%s':" % k) not in embedded]
    if missing:
        fail('i18n', 'web_ui.py is missing %d dictionary key(s) -- run '
                     'tools/build_i18n.py (e.g. %r)' % (len(missing), missing[0]))


def check_template_js():
    """The front end lives in a non-raw Python string; one bad escape breaks it."""
    import ast
    try:
        tree = ast.parse(read(os.path.join(ROOT, 'lib', 'web_ui.py')))
    except SyntaxError as e:
        fail('syntax', 'lib/web_ui.py does not parse: %s' % e)
        return
    if subprocess.run(['which', 'node'], capture_output=True).returncode != 0:
        warn('js', 'node is not installed, template JavaScript was not checked')
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (isinstance(target, ast.Name)
                    and target.id in ('HTML_TEMPLATE', 'LOGIN_TEMPLATE')
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                html = re.sub(r'\{\{.*?\}\}', '0', node.value.value)
                html = re.sub(r'\{%.*?%\}', '', html)
                js = '\n'.join(x for x in re.findall(
                    r'<script[^>]*>(.*?)</script>', html, re.S) if x.strip())
                with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False,
                                                 encoding='utf-8') as fh:
                    fh.write(js)
                    tmp = fh.name
                res = subprocess.run(['node', '--check', tmp],
                                     capture_output=True, text=True)
                os.unlink(tmp)
                if res.returncode != 0:
                    fail('js', '%s does not parse: %s'
                         % (target.id, res.stderr.strip().split('\n')[0]))


def check_screenshots():
    for rel in ('README.md', 'README-zh-TW.md'):
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        for shot in sorted(set(re.findall(r'\((screenshots/[^)]+)\)', read(path)))):
            if not os.path.isfile(os.path.join(ROOT, shot)):
                fail('docs', '%s references %s, which does not exist' % (rel, shot))
            if not os.path.isfile(os.path.join(GITHUB, shot)):
                fail('docs', '%s is not present under github/' % shot)


def check_placeholder_lists():
    """A rule matching an all-zero CDB list is coverage that cannot fire."""
    for path in sorted(glob.glob(os.path.join(ROOT, 'packs', '*', 'lists', '*'))):
        entries = [l for l in read(path).split('\n')
                   if l.strip() and not l.startswith('#')]
        if entries and all(re.match(r'^[^:]*[:=]?0{16,}', e) or re.match(r'^0{16,}', e)
                           for e in entries):
            pack = path.split(os.sep)[-3]
            warn('coverage', '%s/%s holds only placeholder entries, so the rules '
                             'matching it can never fire' % (pack, os.path.basename(path)))


def _tracked_files():
    """What git would actually publish. Anything ignored is not our problem."""
    try:
        res = subprocess.run(['git', '-C', GITHUB, 'ls-files'],
                             capture_output=True, text=True, timeout=30)
    except Exception:
        return None
    if res.returncode != 0:
        return None
    return {l.strip() for l in res.stdout.split('\n') if l.strip()}


def check_publish_hygiene():
    # Only flag junk that git would actually publish. A check that fires on
    # ignored build litter every single run teaches people to skim past the
    # whole report.
    tracked = _tracked_files()
    if tracked is None:
        warn('publish', 'github/ is not a git checkout, skipped the junk-file check')
    else:
        for rel in sorted(tracked):
            base = os.path.basename(rel)
            if (base.endswith(('.pyc', '.log', '.tar.gz', '.swp'))
                    or base == '.DS_Store' or '__pycache__' in rel.split(os.sep)):
                fail('publish', 'github/ tracks %s' % rel)
        for rel in ('README.md', 'README-zh-TW.md', 'LICENSE', 'SECURITY.md',
                    'CHANGELOG.md', 'CHANGELOG-zh-TW.md', 'install.sh'):
            if rel not in tracked:
                fail('publish', 'github/%s is not tracked by git' % rel)
    cfg = os.path.join(GITHUB, 'config.yaml')
    if os.path.isfile(cfg):
        body = read(cfg)
        for m in re.finditer(r'^\s*password:\s*(\S+)', body, re.M):
            value = m.group(1).strip('\'"')
            if value and not value.startswith('#') and value.lower() not in (
                    'null', '~', 'your_password', 'changeme', ''):
                fail('publish', 'github/config.yaml carries a password value')


def main():
    version = current_version()
    if not version:
        print('cannot read __version__ from lib/__init__.py')
        return 2
    print('JT Wazuh Manager pre-release checks -- v%s\n' % version)

    for label, fn in (
            ('version and badges', lambda: check_version_consistency(version)),
            ('changelog entries', lambda: check_changelog(version)),
            ('github/ mirrors the working tree', check_github_mirror),
            ('no internal hosts or addresses published', check_no_internal_data),
            ('pack manifests, hashes, rule IDs, descriptions', check_packs),
            ('packs/INDEX', check_index),
            ('i18n dictionary is embedded', check_i18n_build),
            ('template JavaScript parses', check_template_js),
            ('screenshots referenced by the READMEs', check_screenshots),
            ('CDB lists that are still placeholders', check_placeholder_lists),
            ('publishing hygiene', check_publish_hygiene),
    ):
        before = len(FAILURES), len(WARNINGS)
        fn()
        f, w = len(FAILURES) - before[0], len(WARNINGS) - before[1]
        mark = 'FAIL' if f else ('warn' if w else ' ok ')
        print('  [%s] %s' % (mark, label))

    if WARNINGS:
        print('\nWarnings (%d):' % len(WARNINGS))
        for check, detail in WARNINGS:
            print('  %-9s %s' % (check, detail))
    if FAILURES:
        print('\nFailures (%d):' % len(FAILURES))
        for check, detail in FAILURES:
            print('  %-9s %s' % (check, detail))

    print('\nNot checked here, still required before tagging a release:')
    print('  - python3 -m unittest discover -s tests')
    print('  - OWASP ZAP baseline scan, compared against the recorded baseline')
    print('  - deploy, then read the version back from the target path itself')
    print('  - on a cluster, sync rules to the worker and reload both nodes')

    if FAILURES:
        print('\n%d check(s) failed.' % len(FAILURES))
        return 1
    print('\nAll mechanical checks passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
