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
            if not m:
                continue
            if PLACEHOLDER.match(m.group(0)):
                continue
            # A CIDR suffix makes it a range definition, not a host. Rules that
            # classify RFC 1918 sources have to name those ranges to do their job.
            if re.match(r'/\d{1,2}\b', line[m.end():]):
                continue
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

        check_pack_extras(pack, pdir, m)


def check_pack_extras(pack, pdir, m):
    """Scripts and agent groups a pack installs are checked like its files.

    A pack that schedules an executable as root, or that creates an agent group,
    is doing more than dropping XML into etc/rules. Those parts get the same
    hash and validity checks as everything else.
    """
    import xml.etree.ElementTree as ET
    for entry in (m.get('scripts') or []):
        name = entry.get('name', '')
        path = os.path.join(pdir, 'scripts', name)
        if not os.path.isfile(path):
            fail('packs', '%s: script %s is listed but missing' % (pack, name))
            continue
        if hashlib.sha256(read(path, True)).hexdigest() != entry.get('sha256'):
            fail('packs', '%s: script %s has a stale sha256' % (pack, name))
        dest = entry.get('dest', '')
        if not dest.startswith('etc/jt-packs/bin/') or '..' in dest:
            fail('packs', '%s: script installs to %r, outside the pack bin directory'
                 % (pack, dest))
        schedule = (entry.get('cron') or '').strip()
        if schedule and not re.match(r'^[\d*/,\- ]{5,64}$', schedule):
            fail('packs', '%s: cron schedule %r is not a plain crontab expression'
                 % (pack, schedule))
        if schedule and len(schedule.split()) != 5:
            fail('packs', '%s: cron schedule %r does not have five fields'
                 % (pack, schedule))
        body = read(path)
        if not body.startswith('#!'):
            fail('packs', '%s: script %s has no shebang' % (pack, name))
        if re.search(r'[一-鿿]', body):
            fail('i18n', '%s: script %s contains non-English text' % (pack, name))

    grp = m.get('agent_group')
    if grp:
        gname = grp.get('name', '')
        if not re.match(r'^[A-Za-z0-9_-]{1,64}$', gname):
            fail('packs', '%s: agent group name %r is not a safe group name' % (pack, gname))
        cfg = os.path.join(pdir, 'agent', grp.get('config', 'agent.conf'))
        if not os.path.isfile(cfg):
            fail('packs', '%s: agent group config is missing' % pack)
        else:
            try:
                # agent.conf is a fragment, not a document: several
                # <agent_config> blocks with different os or profile
                # attributes is the normal shape, so wrap before parsing.
                ET.fromstring('<root>' + read(cfg) + '</root>')
            except Exception as e:
                fail('packs', '%s: agent group config is not well-formed XML (%s)' % (pack, e))
        for extra in (grp.get('files') or []):
            if not os.path.isfile(os.path.join(pdir, 'agent', str(extra))):
                fail('packs', '%s: agent group file %r is missing' % (pack, extra))


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



def check_heading_version(version):
    """The README heading carries the version too, and it is not a badge.

    The badge check passed for nine releases while the heading above it still
    said v1.6.0, because nothing looked at the heading. It is the first thing
    anyone reads on the GitHub project page.
    """
    for rel in ('README.md', 'README-zh-TW.md',
                'github/README.md', 'github/README-zh-TW.md'):
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        m = re.search(r'^#\s+\S+\s+v([0-9]+\.[0-9]+\.[0-9]+)', read(path), re.M)
        if not m:
            fail('heading', '%s has no "# <name> v<version>" heading' % rel)
        elif m.group(1) != version:
            fail('heading', '%s heading says v%s, expected v%s'
                 % (rel, m.group(1), version))


def check_licence():
    """One licence, stated the same way everywhere.

    A project that says AGPL in the badge, GPL in the README and Apache in a
    pack manifest has told three different people three different things.
    """
    lic = os.path.join(GITHUB, 'LICENSE')
    if not os.path.isfile(lic):
        fail('licence', 'github/LICENSE is missing')
        return
    body = read(lic)
    if 'GNU AFFERO GENERAL PUBLIC LICENSE' not in body:
        fail('licence', 'github/LICENSE is not the AGPL text')

    stale = ('Apache-2.0', 'Apache License', 'GPL-3.0-or-later',
             'license-GPL--3.0', 'license-Apache--2.0')
    for rel in ('github/README.md', 'github/README-zh-TW.md', 'github/docs/index.html'):
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        text = read(path)
        for token in stale:
            # AGPL-3.0-or-later legitimately contains GPL-3.0-or-later.
            hits = [m.start() for m in re.finditer(re.escape(token), text)]
            hits = [h for h in hits if not text[max(0, h - 1):h + len(token)].startswith('A')]
            if hits:
                fail('licence', '%s still mentions %s' % (rel, token))

    for man in sorted(glob.glob(os.path.join(ROOT, 'packs', '*', 'manifest.json'))):
        try:
            data = json.loads(read(man))
        except Exception:
            continue
        if data.get('license') not in (None, 'AGPL-3.0-or-later'):
            fail('licence', '%s declares %s'
                 % (os.path.relpath(man, ROOT), data.get('license')))


def check_project_name():
    """The published name is jt-wazuh-mgr, lower case, everywhere.

    It had been written three ways at once -- the repository name, a title-cased
    product name in the UI, and an older one still carrying the word Agent.
    """
    wrong = ('JT Wazuh Agent Manager', 'JT Wazuh Manager', 'Jt-Wazuh-Mgr', 'JT-Wazuh-Mgr')
    targets = ['github/README.md', 'github/README-zh-TW.md', 'github/docs/index.html',
               'lib/web_ui.py', 'lib/i18n_engine.js']
    for rel in targets:
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        text = read(path)
        for token in wrong:
            if token in text:
                fail('name', '%s uses "%s"; the name is jt-wazuh-mgr' % (rel, token))


def check_icons():
    """The icon set has to exist, and the pages have to point at it."""
    needed = ('icon.svg', 'favicon.ico', 'icon-16.png', 'icon-32.png',
              'icon-180.png', 'icon-192.png', 'icon-512.png')
    for name in needed:
        for base in (os.path.join(ROOT, 'images'), os.path.join(GITHUB, 'images')):
            if not os.path.isfile(os.path.join(base, name)):
                fail('icons', '%s is missing from %s'
                     % (name, os.path.relpath(base, ROOT)))
    ui = read(os.path.join(ROOT, 'lib', 'web_ui.py'))
    if 'images/icon.svg' not in ui:
        fail('icons', 'web_ui.py does not reference the project icon')
    if 'logo-1.png' in ui:
        fail('icons', 'web_ui.py still uses the company logo as its icon')


def check_agpl_source_offer():
    """AGPL section 13: a network user must be offered the source.

    For a hosted console that link in the interface is the offer, so losing it
    is a licence problem, not a cosmetic one.
    """
    ui = read(os.path.join(ROOT, 'lib', 'web_ui.py'))
    if 'AGPL-3.0' not in ui or 'github.com/jasoncheng7115/jt-wazuh-mgr' not in ui:
        fail('agpl', 'the interface does not offer its source to network users')


def main():
    version = current_version()
    if not version:
        print('cannot read __version__ from lib/__init__.py')
        return 2
    print('jt-wazuh-mgr pre-release checks -- v%s\n' % version)

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
            ('README heading version', lambda: check_heading_version(version)),
            ('one licence, stated the same everywhere', check_licence),
            ('the project name is jt-wazuh-mgr', check_project_name),
            ('icon set present and referenced', check_icons),
            ('AGPL source offer in the interface', check_agpl_source_offer),
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
    print('  - tests/e2e/run.sh   (browser journeys through a real browser)')
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
