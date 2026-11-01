#!/usr/bin/env python3
# jt-crs-update: keep the OWASP Core Rule Set of a ModSecurity v3 + nginx host current.
# Copyright Jason Tools Co., Ltd. / AGPL-3.0-or-later
#
# Run daily from cron as root on the web server. Each run:
#   1. asks GitHub for the CRS releases (no download when nothing is new);
#   2. takes the newest release of the major version in use once it has been out for
#      WAIT_DAYS (default 7), so that upstream can fix a bad release first; a new major
#      version is only reported;
#   3. downloads the "minimal" tarball and its .asc, and applies it only if the
#      signature is valid and made by the pinned CRS release key;
#   4. unpacks it next to the current version (crs-<version>/), points the crs symlink
#      at it, runs `nginx -t`, reloads nginx and checks the error log; any failure puts
#      the previous version back;
#   5. reports pending libmodsecurity3 / nginx package updates (never installs them:
#      the library needs an nginx restart, nginx needs a rebuilt module).
#
# Every outcome is one syslog line (tag jt-crs-update, "INFO|NOTICE|ERROR ...") that the
# jt-modsecurity pack turns into Wazuh alerts (133520-133529).
#
# Usage:
#   jt-crs-update            check and apply (cron)
#   jt-crs-update --check    report only, change nothing
#   jt-crs-update --dry-run  download and verify the newest release, change nothing
#   jt-crs-update --setup    turn an existing crs/ directory into crs-<version>/ + symlink
#   jt-crs-update --rollback switch back to the previous installed version
#   jt-crs-update --status   print the installed versions
#
# Settings: /etc/default/jt-crs-update (KEY=value lines) or the environment.

import calendar
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

DEFAULTS = {
    'CRS_DIR': '/etc/nginx/modsec/crs',            # the path main.conf includes (a symlink after --setup)
    'KEY': '/usr/local/share/jt-crs-update/crs-signing-key.asc',
    'STATE': '/var/lib/jt-crs-update/state.json',
    'NGINX_ERROR_LOG': '/var/log/nginx/error.log',
    'WAIT_DAYS': '7',
    'KEEP': '3',                                   # installed versions kept, the current one included
    'STALE_DAYS': '14',                            # no successful check for this long is an error
    'NOTICE_EVERY_DAYS': '7',                      # repeat the same notice at most this often
    'CHECK_APT': '1',
    'RELOAD': 'systemctl reload nginx',
}
# OWASP Core Rule Set release key, primary key fingerprint (coreruleset.org, "Verifying
# CRS releases"). A signature by any other key is refused even if gpg calls it good.
PINNED_FPR = '36006F0E0BA167832158821138EEACA1AB8A6E72'
API = 'https://api.github.com/repos/coreruleset/coreruleset/releases?per_page=40'
MAX_DOWNLOAD = 20 * 1024 * 1024
LEVELS = {'INFO': 'user.info', 'NOTICE': 'user.notice', 'ERROR': 'user.err'}


def settings():
    conf = dict(DEFAULTS)
    path = os.environ.get('JT_CRS_UPDATE_CONF', '/etc/default/jt-crs-update')
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    if k.strip() in conf:
                        conf[k.strip()] = v.strip().strip('"\'')
    except FileNotFoundError:
        pass
    for k in conf:
        if k in os.environ:
            conf[k] = os.environ[k]
    return conf


def log(level, msg, quiet=False):
    """One line to stdout and syslog. The rules read the level word and the text."""
    msg = ' '.join(str(msg).split())          # no newlines: one event, nothing to forge
    print('%s %s' % (level, msg))
    if not quiet:
        try:
            subprocess.run(['logger', '-t', 'jt-crs-update', '-p', LEVELS[level], '--',
                            '%s %s' % (level, msg)], check=False, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass


def vtuple(v):
    m = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)', v or '')
    return tuple(int(x) for x in m.groups()) if m else None


def vstr(t):
    return '%d.%d.%d' % t


def installed_version(path):
    """The version a CRS directory holds: the ver:'OWASP_CRS/x.y.z' its rules carry.

    Only the rule action counts. REQUEST-901 also mentions OWASP_CRS/3.1.0 in a
    comment (an example audit-log producer line), which read as the version once.
    """
    rules = os.path.join(path, 'rules')
    seen = {}
    try:
        names = sorted(n for n in os.listdir(rules) if n.endswith('.conf'))
    except OSError:
        return None
    for name in names:
        with open(os.path.join(rules, name), encoding='utf-8', errors='replace') as fh:
            for v in re.findall(r"ver:'OWASP_CRS/(\d+\.\d+\.\d+)'", fh.read()):
                seen[v] = seen.get(v, 0) + 1
    return vtuple(max(seen, key=seen.get)) if seen else None


def versions_on_disk(crs_dir):
    parent, base = os.path.split(crs_dir.rstrip('/'))
    found = {}
    for name in os.listdir(parent):
        m = re.fullmatch(re.escape(base) + r'-(\d+\.\d+\.\d+)', name)
        full = os.path.join(parent, name)
        if m and os.path.isdir(full) and not os.path.islink(full):
            found[vtuple(m.group(1))] = full
    return found


def current(crs_dir):
    """(version, target directory) of the symlink, or raise if not set up."""
    if not os.path.islink(crs_dir):
        raise RuntimeError('%s is not a symlink; run jt-crs-update --setup once' % crs_dir)
    target = os.path.realpath(crs_dir)
    v = installed_version(target)
    if not v:
        raise RuntimeError('cannot read the CRS version in %s' % target)
    return v, target


def switch(crs_dir, target):
    """Point the symlink at target atomically (relative link, same directory)."""
    parent = os.path.dirname(crs_dir.rstrip('/'))
    tmp = os.path.join(parent, '.%s.new' % os.path.basename(crs_dir.rstrip('/')))
    if os.path.lexists(tmp):
        os.unlink(tmp)
    os.symlink(os.path.basename(target), tmp)
    os.replace(tmp, crs_dir.rstrip('/'))


def fetch(url, limit, accept='application/octet-stream'):
    req = urllib.request.Request(url, headers={'User-Agent': 'jt-crs-update', 'Accept': accept})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError('%s is larger than %d bytes' % (url, limit))
    return data


def releases():
    """Published, non-prerelease releases as (version, published epoch, assets by name)."""
    out = []
    for r in json.loads(fetch(API, 5 * 1024 * 1024, 'application/vnd.github+json')):
        v = vtuple(r.get('tag_name', ''))
        if not v or r.get('draft') or r.get('prerelease'):
            continue
        ts = calendar.timegm(time.strptime(r['published_at'][:19], '%Y-%m-%dT%H:%M:%S'))
        out.append((v, ts, {a['name']: a['browser_download_url'] for a in r.get('assets', [])}))
    return out


def choose(cur, rels, wait_days, now):
    """What to do: ('apply'|'wait'|'current', release) plus the newest other-major release."""
    same = sorted((r for r in rels if r[0][0] == cur[0] and r[0] > cur), reverse=True)
    major = max((r for r in rels if r[0][0] > cur[0]), default=None)
    if not same:
        return 'current', None, major
    for r in same:                       # newest release that has waited long enough
        if now - r[1] >= wait_days * 86400:
            return 'apply', r, major
    return 'wait', same[0], major


def verify(tarball, asc, keyfile):
    """True when asc is a valid signature of tarball by the pinned primary key."""
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        base = ['gpg', '--homedir', home, '--batch', '--no-tty', '--quiet']
        imp = subprocess.run(base + ['--import', keyfile], capture_output=True, timeout=60)
        if imp.returncode != 0:
            raise RuntimeError('cannot import %s' % keyfile)
        res = subprocess.run(base + ['--status-fd', '1', '--verify', asc, tarball],
                             capture_output=True, text=True, timeout=60)
    for line in res.stdout.splitlines():
        f = line.split()
        # [GNUPG:] VALIDSIG <signing key fpr> <date> <ts> <exp> <ver> <res> <pk> <hash> <cls> <primary fpr>
        if len(f) >= 12 and f[1] == 'VALIDSIG' and f[-1].upper() == PINNED_FPR:
            return res.returncode == 0
    return False


def safe_extract(tarball, dest, top):
    """Unpack only plain files and directories under top/; refuse anything else."""
    with tarfile.open(tarball, 'r:gz') as tf:
        members = tf.getmembers()
        for m in members:
            name = m.name[2:] if m.name.startswith('./') else m.name
            if (not (name.rstrip('/') == top or name.startswith(top + '/')) or '..' in m.name.split('/')
                    or os.path.isabs(m.name) or not (m.isfile() or m.isdir())):
                raise RuntimeError('unexpected entry in the tarball: %r' % m.name)
        for m in members:
            m.mode = (m.mode & 0o755) | (0o755 if m.isdir() else 0o644)
            m.uid = m.gid = 0
            m.uname = m.gname = 'root'
            tf.extract(m, dest, set_attrs=True, numeric_owner=True)
    return os.path.join(dest, top)


def nginx_test():
    r = subprocess.run(['nginx', '-t'], capture_output=True, text=True, timeout=120)
    lines = [l for l in (r.stderr + r.stdout).splitlines() if l.strip()]
    return r.returncode == 0, (lines[0] if lines else '')


def errors_since(path, since):
    """[emerg]/[alert] lines written to the nginx error log at or after since."""
    out = []
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            fh.seek(max(0, os.path.getsize(path) - 256 * 1024))
            for line in fh:
                m = re.match(r'(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(emerg|alert)\]', line)
                if m and time.mktime(time.strptime(m.group(1), '%Y/%m/%d %H:%M:%S')) >= since - 1:
                    out.append(line.strip())
    except OSError:
        pass
    return out


def reload_and_check(conf):
    start = time.time()
    r = subprocess.run(conf['RELOAD'], shell=True, capture_output=True, text=True, timeout=120)
    time.sleep(3)
    bad = errors_since(conf['NGINX_ERROR_LOG'], start)
    if r.returncode != 0:
        bad.insert(0, (r.stderr or r.stdout or 'reload failed').strip().splitlines()[0])
    return bad


def load_state(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def notice_once(state, key, text, every_days, now):
    """Log a NOTICE unless the same text was logged less than every_days ago."""
    seen = state.setdefault('notices', {})
    prev = seen.get(key)
    if prev and prev.get('text') == text and now - prev.get('at', 0) < every_days * 86400:
        return
    log('NOTICE', text)
    seen[key] = {'text': text, 'at': now}


def apt_pending():
    """Pending updates of the packages the WAF depends on, as 'name a -> b' strings."""
    env = dict(os.environ, LC_ALL='C')
    subprocess.run(['apt-get', '-qq', 'update'], capture_output=True, timeout=600, env=env)
    r = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True, timeout=120, env=env)
    out = []
    for line in r.stdout.splitlines():
        m = re.match(r'(libmodsecurity3|nginx)/\S+ (\S+) \S+ \[upgradable from: (\S+)\]', line)
        if m:
            hint = 'restart nginx afterwards' if m.group(1) == 'libmodsecurity3' else \
                'rebuild the ModSecurity module for it first'
            out.append('%s %s -> %s (%s)' % (m.group(1), m.group(3), m.group(2), hint))
    return out


def prune(crs_dir, keep, cur_target, prev_target):
    on_disk = versions_on_disk(crs_dir)
    for v in sorted(on_disk, reverse=True)[keep:]:
        path = on_disk[v]
        if path not in (cur_target, prev_target):
            shutil.rmtree(path, ignore_errors=True)


def do_setup(conf):
    crs = conf['CRS_DIR'].rstrip('/')
    if os.path.islink(crs):
        v, target = current(crs)
        print('already set up: %s -> %s (CRS %s)' % (crs, os.path.basename(target), vstr(v)))
        return 0
    v = installed_version(crs)
    if not v:
        log('ERROR', 'setup: cannot read the CRS version in %s' % crs)
        return 1
    dest = '%s-%s' % (crs, vstr(v))
    if os.path.exists(dest):
        log('ERROR', 'setup: %s already exists' % dest)
        return 1
    os.rename(crs, dest)
    switch(crs, dest)
    ok, first = nginx_test()
    if not ok:
        os.unlink(crs)
        os.rename(dest, crs)
        log('ERROR', 'setup: nginx -t failed after the change (%s); restored %s' % (first, crs))
        return 1
    log('INFO', 'setup: %s is now a symlink to %s (CRS %s)' % (crs, os.path.basename(dest), vstr(v)))
    return 0


def do_rollback(conf):
    crs = conf['CRS_DIR'].rstrip('/')
    cur, target = current(crs)
    older = sorted((v for v in versions_on_disk(crs) if v < cur), reverse=True)
    if not older:
        log('ERROR', 'rollback: no older CRS version installed next to %s' % vstr(cur))
        return 1
    prev = versions_on_disk(crs)[older[0]]
    switch(crs, prev)
    ok, first = nginx_test()
    bad = [] if not ok else reload_and_check(conf)
    if not ok or bad:
        switch(crs, target)
        log('ERROR', 'rollback to CRS %s failed (%s); kept %s' % (vstr(older[0]), first if not ok else bad[0], vstr(cur)))
        if ok:
            reload_and_check(conf)
        return 1
    log('INFO', 'rolled back CRS %s -> %s (operator)' % (vstr(cur), vstr(older[0])))
    return 0


def run(conf, mode):
    crs = conf['CRS_DIR'].rstrip('/')
    now = time.time()
    state = load_state(conf['STATE'])
    quiet = mode == 'check'
    try:
        cur, cur_target = current(crs)
    except RuntimeError as e:
        log('ERROR', str(e), quiet)
        return 1
    try:
        rels = releases()
    except Exception as e:  # network, API, JSON: report and judge staleness
        log('ERROR', 'update check failed: %s' % e, quiet)
        last = state.get('last_check_ok')
        days = (now - last) / 86400 if last else None
        if not quiet and (days is None or days >= float(conf['STALE_DAYS'])):
            log('ERROR', 'no successful update check for %s (last %s)' % (
                'ever' if days is None else '%d days' % days,
                time.strftime('%Y-%m-%d', time.localtime(last)) if last else 'never'))
        if not quiet:
            save_state(conf['STATE'], state)
        return 1
    state['last_check_ok'] = now
    action, rel, major = choose(cur, rels, int(conf['WAIT_DAYS']), now)
    if major and not quiet:
        notice_once(state, 'major', 'CRS %s (new major version) is available; not applied automatically (now %s)'
                    % (vstr(major[0]), vstr(cur)), float(conf['NOTICE_EVERY_DAYS']), now)
    rc = 0
    if action == 'current':
        log('INFO', 'CRS %s is current' % vstr(cur), quiet=True)
    elif action == 'wait':
        log('INFO', 'CRS %s was released on %s; it will be applied after %s days (now %s)' % (
            vstr(rel[0]), time.strftime('%Y-%m-%d', time.localtime(rel[1])), conf['WAIT_DAYS'], vstr(cur)),
            quiet=quiet)
    elif mode == 'check':
        log('INFO', 'CRS %s is ready to be applied (now %s)' % (vstr(rel[0]), vstr(cur)), quiet=True)
    if mode == 'dry-run' and action == 'current':
        rel = next((r for r in rels if r[0] == cur), None)   # exercise download + signature on the current one
    if (action == 'apply' and mode == 'apply') or (mode == 'dry-run' and rel):
        rc = install(conf, crs, cur, cur_target, rel, dry=(mode == 'dry-run'))
    if not quiet and conf['CHECK_APT'] == '1' and shutil.which('apt'):
        try:
            pend = apt_pending()
            if pend:
                notice_once(state, 'apt', 'WAF package updates pending: %s' % '; '.join(pend),
                            float(conf['NOTICE_EVERY_DAYS']), now)
        except (OSError, subprocess.SubprocessError):
            pass
    if not quiet:
        save_state(conf['STATE'], state)
    return rc


def install(conf, crs, cur, cur_target, rel, dry=False):
    v, _, assets = rel
    name = 'coreruleset-%s-minimal.tar.gz' % vstr(v)
    if name not in assets or name + '.asc' not in assets:
        log('ERROR', 'CRS %s has no %s with a signature; nothing changed' % (vstr(v), name), dry)
        return 1
    parent = os.path.dirname(crs)
    with tempfile.TemporaryDirectory(dir=parent, prefix='.jt-crs-update-') as tmp:
        tb, asc = os.path.join(tmp, name), os.path.join(tmp, name + '.asc')
        try:
            with open(tb, 'wb') as fh:
                fh.write(fetch(assets[name], MAX_DOWNLOAD))
            with open(asc, 'wb') as fh:
                fh.write(fetch(assets[name + '.asc'], 64 * 1024))
        except Exception as e:
            log('ERROR', 'download of CRS %s failed: %s; nothing changed' % (vstr(v), e), dry)
            return 1
        try:
            good = verify(tb, asc, conf['KEY'])
        except Exception as e:
            good = False
            why = str(e)
        else:
            why = 'not signed by the CRS release key %s' % PINNED_FPR
        if not good:
            log('ERROR', 'signature check failed for %s (%s); nothing changed' % (name, why), dry)
            return 1
        try:
            src = safe_extract(tb, tmp, 'coreruleset-%s' % vstr(v))
            got = installed_version(src)
            if got != v:
                raise RuntimeError('the tarball holds CRS %s' % (vstr(got) if got else 'nothing readable'))
        except Exception as e:
            log('ERROR', 'CRS %s could not be unpacked: %s; nothing changed' % (vstr(v), e), dry)
            return 1
        if dry:
            print('INFO dry run: CRS %s downloaded, signature valid, unpacked; nothing changed' % vstr(v))
            return 0
        dest = '%s-%s' % (crs, vstr(v))
        if os.path.exists(dest):
            shutil.rmtree(dest)
        shutil.move(src, dest)
    switch(crs, dest)
    ok, first = nginx_test()
    if not ok:
        switch(crs, cur_target)
        log('ERROR', 'nginx rejected CRS %s (%s); rolled back to %s' % (vstr(v), first, vstr(cur)))
        return 1
    bad = reload_and_check(conf)
    if bad:
        switch(crs, cur_target)
        reload_and_check(conf)
        log('ERROR', 'nginx failed to reload with CRS %s (%s); rolled back to %s' % (vstr(v), bad[0][:200], vstr(cur)))
        return 1
    log('INFO', 'updated CRS %s -> %s' % (vstr(cur), vstr(v)))
    prune(crs, int(conf['KEEP']), dest, cur_target)
    return 0


def main(argv):
    modes = {'--check': 'check', '--dry-run': 'dry-run', '--setup': 'setup',
             '--rollback': 'rollback', '--status': 'status'}
    mode = 'apply'
    for a in argv:
        if a not in modes:
            print('usage: jt-crs-update [--check|--dry-run|--setup|--rollback|--status]')
            return 2
        mode = modes[a]
    if os.geteuid() != 0 and mode != 'status':
        print('run as root')
        return 2
    conf = settings()
    lock = open('/run/jt-crs-update.lock' if os.geteuid() == 0 else os.devnull, 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print('another jt-crs-update is running')
        return 1
    if mode == 'setup':
        return do_setup(conf)
    if mode == 'rollback':
        return do_rollback(conf)
    if mode == 'status':
        crs = conf['CRS_DIR'].rstrip('/')
        cur = os.path.realpath(crs) if os.path.islink(crs) else None
        for v, path in sorted(versions_on_disk(crs).items()):
            print('%s %s%s' % (vstr(v), path, '  <- in use' if path == cur else ''))
        if not cur:
            print('%s is not a symlink (run --setup)' % crs)
        return 0
    return run(conf, mode)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
