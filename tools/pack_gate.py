#!/usr/bin/env python3
"""Release gate for the rule packs: install them the way a customer does.

    tools/pack_gate.py run [--versions 4.12.0,4.13.1,4.14.9] [--only jt-a,jt-b]
                           [--from-tag v1.22.3] [--skip fresh,no-cron,upgrade,cluster]
                           [--keep] [--resume DIR]
    tools/pack_gate.py clean          remove every jtgate-* container and network

tools/pack_sandbox.py tests one pack at a time, copying its files in by hand.
That never exercised what a customer runs: the tool's own install route on a
clean manager, all packs together, on the Wazuh version the customer has, an
update from an older release, and a cluster whose worker the pack's setup
guide has to bring along. This gate does those four things in throwaway
wazuh/wazuh-manager containers and fails (exit 1) on anything wrong:

  fresh-<version>  every pack installed through POST /api/packs/<id>/install,
                   with a real Wazuh API session; then: no ERROR or WARNING
                   from wazuh-analysisd -t, every pack recorded as current,
                   every agent group registered, every cron file the install
                   reported present, every script compiling with the
                   manager's system python, every MITRE ID known to that
                   version's database, and every tests/pack_cases/*.json case
                   passing against the one manager holding all packs.
  upgrade          the packs of --from-tag installed with that release's own
                   tool, then the working tree's tool and packs, every pack
                   updated through POST /api/packs/<id>/update, the same
                   checks and the replay.
  cluster          a master and a worker; packs installed on the master (the
                   tool declares lists on the worker over the API), then each
                   pack's documented worker steps carried out as written;
                   the worker must load every list without warnings, hold the
                   scripts and schedules the guides name, and give the same
                   replay results as the master.
  no-cron          a scheduled pack on a manager without /etc/cron.d (the
                   official container image): the install must not report a
                   schedule it did not write.

A case whose line another installed pack is meant to take (a near miss that
belongs to a neighbouring product) carries "with_all_packs": {"expect_rule",
"expect_level", "why"}; the gate judges it by those, pack_sandbox ignores them.

Each scenario runs in its own containers (at most four at once), writes its
result to temp/pack-gate/<date>/<scenario>.json as soon as it finishes, and a
run started with --resume DIR skips the scenarios already recorded there.
Containers are removed at the end unless --keep.
"""

import argparse
import datetime
import glob
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import pack_sandbox as sb            # noqa: E402  readiness, slimming, replay helpers

OSSEC = '/var/ossec'
TOOL_DIR = '/opt/jtwm'              # where the tool is unpacked inside a container
DEFAULT_VERSIONS = ['4.12.0', '4.13.1', '4.14.9']
NETWORK = 'jtgate-net'
LOGTEST_THREADS = int(os.environ.get('JT_GATE_LOGTEST_THREADS', '3'))
RAW_DIR = None                      # set by run: raw replay output kept for analysis
CLUSTER_KEY = 'c98b62a9b6169ac5f67dae55ae4a9088'
PRINT_LOCK = threading.Lock()


def say(msg):
    with PRINT_LOCK:
        print('%s %s' % (time.strftime('%H:%M:%S'), msg), flush=True)


def run(cmd, data=None, check=True, timeout=None):
    r = subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError('command failed: %s\n%s' % (' '.join(cmd)[:300], (r.stdout + r.stderr)[-1500:]))
    return r


def dexec(name, *cmd, data=None, check=True, timeout=None):
    return run(['docker', 'exec', '-i', name] + list(cmd), data=data, check=check, timeout=timeout)


# --------------------------------------------------------------------------
# The tool bundle: what an install.sh puts on a manager, plus the wheels
# the manager's framework python lacks (it has requests and yaml, not Flask).
# --------------------------------------------------------------------------

def vendor_for(py_tag, dest):
    """Unpack the offline wheels usable by CPython <py_tag> (e.g. cp310)."""
    os.makedirs(dest, exist_ok=True)
    for whl in sorted(glob.glob(os.path.join(ROOT, 'offline_packages', '*.whl'))):
        base = os.path.basename(whl)
        if 'py3-none-any' in base or ('-%s-%s-' % (py_tag, py_tag)) in base:
            with zipfile.ZipFile(whl) as zf:
                zf.extractall(dest)


def bundle(tree, py_tag, out):
    """A tar of <tree>'s lib/, packs/, tests/pack_cases/ and the wheels."""
    vend = tempfile.mkdtemp(prefix='jtgate-vendor-')
    try:
        vendor_for(py_tag, vend)
        with tarfile.open(out, 'w:gz') as tf:
            for sub in ('lib', 'packs', 'tests/pack_cases', 'wazuh_agent_mgr.py'):
                p = os.path.join(tree, sub)
                if os.path.exists(p):
                    tf.add(p, arcname=sub, filter=lambda ti: None if '__pycache__' in ti.name else ti)
            conf = io.BytesIO(b'wazuh_path: /var/ossec\n')
            ti = tarfile.TarInfo('config.yaml')
            ti.size = len(conf.getvalue())
            tf.addfile(ti, conf)
            tf.add(vend, arcname='vendor')
    finally:
        shutil.rmtree(vend, ignore_errors=True)


def put_tool(name, tgz):
    dexec(name, 'sh', '-c', 'rm -rf %s && mkdir -p %s' % (TOOL_DIR, TOOL_DIR))
    run(['docker', 'cp', tgz, '%s:/tmp/jtwm.tgz' % name])
    dexec(name, 'sh', '-c', 'tar xzf /tmp/jtwm.tgz -C %s && rm -f /tmp/jtwm.tgz' % TOOL_DIR)


# --------------------------------------------------------------------------
# Driver run inside a container with the manager's framework python: logs in
# to the local Wazuh API (so cluster peers are reached the way they are for a
# customer) and calls the tool's routes through Flask's test client.
# --------------------------------------------------------------------------

DRIVER = r'''
import json, os, sys, time, base64, ssl, urllib.request
sys.path.insert(0, %(tool)r); sys.path.insert(1, %(tool)r + '/vendor')
action, args = sys.argv[1], json.loads(sys.argv[2])
token, user = None, None
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
for u, p in (('wazuh', 'wazuh'), ('wazuh-wui', 'wazuh-wui'), ('wazuh-wui', 'MyS3cr37P450r.*-')):
    try:
        req = urllib.request.Request('https://127.0.0.1:55000/security/user/authenticate?raw=true',
                                     method='POST', headers={'Authorization': 'Basic ' +
                                     base64.b64encode(('%%s:%%s' %% (u, p)).encode()).decode()})
        token = urllib.request.urlopen(req, context=ctx, timeout=20).read().decode().strip()
        user = u
        break
    except Exception as e:
        last = str(e)
if not token:
    print(json.dumps({'fatal': 'Wazuh API login failed: ' + last})); sys.exit(0)
import lib.web_ui as w
w.PACK_SYSTEM_PYTHON = '/usr/bin/python3'
app = w.create_app(); app.config['TESTING'] = True
c = app.test_client()
with c.session_transaction() as s:
    s['api_session'] = {'host': '127.0.0.1', 'port': 55000, 'username': user, 'token': token,
                        'session_exp': int(time.time()) + 7200, 'server_version': args.get('version', '')}
out = {'user': user, 'results': []}
if action == 'install':
    for pid in args['packs']:
        r = c.post('/api/packs/%%s/install' %% pid, json=args.get('body') or {})
        b = r.get_json(silent=True) or {}
        out['results'].append({'pack': pid, 'status': r.status_code, 'body': b})
elif action == 'update':
    for p in c.get('/api/packs').get_json()['packs']:
        if not p.get('update_available'):
            continue
        plan = c.get('/api/packs/%%s/update' %% p['id']).get_json(silent=True)
        r = c.post('/api/packs/%%s/update' %% p['id'], json={})
        out['results'].append({'pack': p['id'], 'from': p.get('installed_version'), 'to': p.get('version'),
                               'status': r.status_code, 'body': r.get_json(silent=True) or {}, 'plan': plan})
out['packs'] = c.get('/api/packs').get_json()['packs']
print(json.dumps(out, default=str))
''' % {'tool': TOOL_DIR}


def driver(name, action, args):
    r = dexec(name, OSSEC + '/framework/python/bin/python3', '-c', DRIVER, action, json.dumps(args),
              check=False, timeout=3600)
    lines = [l for l in r.stdout.splitlines() if l.startswith('{')]
    if not lines:
        raise RuntimeError('driver %s in %s produced nothing:\n%s' % (action, name, (r.stdout + r.stderr)[-2000:]))
    out = json.loads(lines[-1])
    if 'fatal' in out:
        raise RuntimeError(out['fatal'])
    return out


# --------------------------------------------------------------------------
# Replay of every case file inside the container, through the logtest socket
# (one process instead of one docker exec per case). FIM cases use
# pack_sandbox's own injection; a log case that fails over the socket is
# retried with pack_sandbox's wazuh-logtest path before it counts.
# --------------------------------------------------------------------------

REPLAY = r'''
import json, socket, struct, sys, glob, os, threading
from concurrent.futures import ThreadPoolExecutor
def req(msg):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('/var/ossec/queue/sockets/logtest')
    data = json.dumps(msg).encode()
    s.sendall(struct.pack('<I', len(data)) + data)
    size = struct.unpack('<I', s.recv(4))[0]
    buf = b''
    while len(buf) < size:
        buf += s.recv(size - len(buf))
    s.close()
    return json.loads(buf)
ORIGIN = {'name': 'jt-gate', 'module': 'jt-gate'}
def send(token, loc, line):
    p = {'event': line, 'log_format': 'syslog', 'location': loc}
    if token:
        p['token'] = token
    d = req({'version': 1, 'origin': ORIGIN, 'command': 'log_processing', 'parameters': p}).get('data', {})
    rule = (d.get('output') or {}).get('rule') or {}
    return d.get('token', token), [str(rule.get('id', 'none')), int(rule.get('level', 0) or 0),
                                   rule.get('description', '')]
def close(token):
    if token:
        try:
            req({'version': 1, 'origin': ORIGIN, 'command': 'remove_session', 'parameters': {'token': token}})
        except Exception:
            pass
def fresh(events):
    token, got = None, ['none', 0, '']
    try:
        for loc, line in events:
            token, got = send(token, loc, line)
    except Exception as e:
        got = ['error', 0, str(e)[:200]]
    close(token)
    return got
def judge(case, got):
    case = dict(case, **(case.get("with_all_packs") or {}))    # pack_sandbox ignores it
    want, wl = str(case['expect_rule']), case.get('expect_level')
    ok = got[1] == 0 if want == 'none' else (got[0] == want and (wl is None or got[1] == wl))
    return ok and all(t in (got[2] or '') for t in case.get('expect_in_description', []))
def events_of(case):
    default = case.get('location') or 'stdin'
    ev = []
    for b in case.get('before', []):
        ev.append((b.get('location') or default, b['log']) if isinstance(b, dict) else (default, b))
    for _ in range(int(case.get('repeat', 1))):
        for line in case['log'].split('\n'):
            ev.append((default, line))
    return ev
only, cdir, threads = set(json.loads(sys.argv[1])), sys.argv[2], int(sys.argv[3])
out_lock = threading.Lock()
def emit(pack, i, got, how):
    with out_lock:
        print(json.dumps({'pack': pack, 'i': i, 'got': got, 'how': how}), flush=True)
stateful = []
for path in sorted(glob.glob(cdir + '/*.json')):
    pack = os.path.basename(path)[:-5]
    if only and pack not in only:
        continue
    data = json.load(open(path))
    token = None
    for i, case in enumerate(data['cases'] + data.get('sequences', []), 1):
        if 'fim' in case:
            continue
        ev = events_of(case)
        if len(ev) > 1:
            stateful.append((pack, i, case, ev))
            continue
        # one line: a session shared by the pack's one-line cases; whatever
        # earlier cases left in it (counters, first-time-seen keys) can only
        # change a result, and a changed result is run again on its own
        try:
            token, got = send(token, ev[0][0], ev[0][1])
        except Exception as e:
            token, got = None, ['error', 0, str(e)[:200]]
        if judge(case, got):
            emit(pack, i, got, 'shared')
        else:
            stateful.append((pack, i, case, ev))
    close(token)
def work(item):
    pack, i, case, ev = item
    emit(pack, i, fresh(ev), 'fresh')
with ThreadPoolExecutor(max_workers=threads) as ex:
    list(ex.map(work, stateful))
'''


def judge(case, got):
    case = dict(case, **(case.get("with_all_packs") or {}))    # pack_sandbox ignores it
    rule, level, desc = got
    want, wlevel = str(case['expect_rule']), case.get('expect_level')
    ok = level == 0 if want == 'none' else (rule == want and (wlevel is None or level == wlevel))
    missing = [t for t in case.get('expect_in_description', []) if t not in (desc or '')]
    return ok and not missing


def load_cases(only):
    out = {}
    for path in sorted(glob.glob(os.path.join(ROOT, 'tests', 'pack_cases', '*.json'))):
        pack = os.path.basename(path)[:-5]
        if only and pack not in only:
            continue
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
        out[pack] = data
    return out


RELOAD = r"""
import asyncio
try:
    from wazuh.core.analysis import send_reload_ruleset_msg as s
    r = asyncio.run(s({'module': 'api'}))
    print('reloaded' if r.success else 'reload failed')
except Exception as e:
    print('no hot reload: %s' % e)
"""


def reload_ruleset(name):
    """Hot reload (recompiles CDB lists); a restart where the version has none."""
    r = dexec(name, OSSEC + '/framework/python/bin/python3', '-c', RELOAD, check=False, timeout=600)
    if 'reloaded' not in r.stdout:
        restart(name)
    else:
        time.sleep(3)


def wait_list_synced(source, target, paths, timeout=180):
    """Wait until the cluster has copied these list files from source to target."""
    cmd = 'for f in %s; do if [ -f $f ]; then md5sum $f; else echo "- $f"; fi; done' % ' '.join(paths)
    end = time.time() + timeout
    while time.time() < end:
        if dexec(source, 'sh', '-c', cmd, check=False).stdout == dexec(target, 'sh', '-c', cmd, check=False).stdout:
            return True
        time.sleep(5)
    return False


def with_case_lists(name, data, fn, writer=None):
    """Run fn() with one case file's sandbox_lists appended, then put the lists back.

    On a worker the lists are written on the master (writer): the cluster
    copies etc/lists from the master every few seconds, so entries written on
    the worker itself are gone again before or during the replay.
    """
    writer = writer or name
    lists = {k: v for k, v in (data.get('sandbox_lists') or {}).items() if re.match(r'^[A-Za-z0-9._-]+$', k)}
    paths = ['%s/etc/lists/%s' % (OSSEC, k) for k in lists]

    def settle():
        if writer != name and paths:
            # The cluster copies etc/lists with the compiled .cdb files. Built
            # only on the worker, the test entries were overwritten by the
            # master's older .cdb a few seconds later, so some cases saw them
            # and some did not (64 to 97 worker failures, 2026-10-28). Compile
            # on the master first and wait for text and .cdb alike.
            dexec(writer, 'sh', '-c', 'for f in %s; do rm -f $f.cdb; done' % ' '.join(paths), check=False)
            reload_ruleset(writer)
            if not wait_list_synced(writer, name, paths + [q + '.cdb' for q in paths]):
                say('%s: test lists did not reach %s in time' % (writer, name))
        reload_ruleset(name)
    for k, body in lists.items():
        path = '%s/etc/lists/%s' % (OSSEC, k)
        dexec(writer, 'sh', '-c', '(test -f %s && cp -p %s %s.gatebak || : > %s.gatenew); cat >> %s; '
              'chown wazuh:wazuh %s' % (path, path, path, path, path, path), data=body)
    settle()
    try:
        return fn()
    finally:
        for path in paths:
            # the restored text keeps its old mtime, older than the .cdb built
            # with the test entries: without removing the .cdb the next reload
            # would keep serving them (that leaked jt-ioc's test addresses)
            dexec(writer, 'sh', '-c', 'if [ -f %s.gatebak ]; then mv -f %s.gatebak %s; touch %s; else rm -f %s; fi; '
                  'rm -f %s.cdb %s.gatenew' % (path, path, path, path, path, path, path), check=False)
        settle()


def run_replay_script(name, packs, tag):
    r = dexec(name, OSSEC + '/framework/python/bin/python3', '-c', REPLAY, json.dumps(sorted(packs)),
              TOOL_DIR + '/tests/pack_cases', str(LOGTEST_THREADS), check=False, timeout=6 * 3600)
    if RAW_DIR:
        with open(os.path.join(RAW_DIR, 'replay-%s.jsonl' % tag.replace(' ', '-')), 'a') as fh:
            fh.write(r.stdout)
    got, how = {}, {}
    for line in r.stdout.splitlines():
        try:
            d = json.loads(line)
            got[(d['pack'], d['i'])] = tuple(d['got'])
            how[d['how']] = how.get(d['how'], 0) + 1
        except ValueError:
            pass
    return got, how


_VERSIONS = {}


def manager_version(name):
    """(major, minor, patch) of the manager in container `name`, cached."""
    if name not in _VERSIONS:
        out = dexec(name, 'cat', '/var/ossec/bin/wazuh-control', check=False)
        m = re.search(r'WAZUH_VERSION="?v?(\d+)\.(\d+)\.(\d+)', getattr(out, 'stdout', '') or '')
        if not m:
            out = dexec(name, '/var/ossec/bin/wazuh-control', 'info', check=False)
            m = re.search(r'WAZUH_VERSION="?v?(\d+)\.(\d+)\.(\d+)', getattr(out, 'stdout', '') or '')
        _VERSIONS[name] = tuple(int(x) for x in m.groups()) if m else (99, 0, 0)
    return _VERSIONS[name]


def too_old_for(name, case):
    """A case may name the oldest manager it applies to ("min_wazuh": "4.14"):
    one that expects a built-in rule ID or field that older rulesets lack.
    Skipped there, and counted as skipped, not passed."""
    want = case.get('min_wazuh')
    if not want:
        return False
    need = tuple(int(x) for x in str(want).split('.')) + (0, 0)
    return manager_version(name) < need[:3]


def judge_pack(name, pack, data, got, fim, state):
    res = {'passed': 0, 'total': 0, 'failures': [], 'socket_only': 0, 'skipped': 0,
           'case_lists': sorted((data.get('sandbox_lists') or {}).keys())}
    for i, case in enumerate(data['cases'] + data.get('sequences', []), 1):
        if too_old_for(name, case):
            res['skipped'] += 1
            continue
        older = case.get('on_older') or {}
        if older.get('wazuh_below') and manager_version(name) < (
                tuple(int(x) for x in str(older['wazuh_below']).split('.')) + (0, 0))[:3]:
            # what an older ruleset gives instead (a compatibility twin, say);
            # it already accounts for every pack being installed
            case = dict(case, with_all_packs={k: v for k, v in older.items() if k != 'wazuh_below'})
        if 'fim' in case:
            if not fim:
                continue
            spec = dict(case['fim'], before=case['before']) if case.get('before') else case['fim']
            g = (sb.fim_case(name, spec, str(case['expect_rule']) != 'none') or [('none', 0, '')])[-1]
            if not judge(case, g):
                time.sleep(3)          # under load an alert can be late; one retry
                g = (sb.fim_case(name, spec, str(case['expect_rule']) != 'none') or [('none', 0, '')])[-1]
        else:
            g = got.get((pack, i), ('missing', 0, ''))
            if not judge(case, g) and state['fallback_left'] > 0:
                # the binary path pack_sandbox uses, before calling it a failure;
                # each costs a full ruleset load, so only a few
                before = case.get('before', [])
                if not any(isinstance(b, dict) for b in before):
                    state['fallback_left'] -= 1
                    lines = list(before) + [case['log']] * int(case.get('repeat', 1))
                    b = sb.logtest(name, lines, case.get('location'))
                    if b and judge(case, b[-1]):
                        res['socket_only'] += 1
                        g = b[-1]
        res['total'] += 1
        if judge(case, g):
            res['passed'] += 1
        else:
            res['failures'].append({'i': i, 'want': [str(case['expect_rule']), case.get('expect_level')],
                                    'got': list(g), 'note': (case.get('note') or '')[:160],
                                    'kind': 'fim' if 'fim' in case else 'log'})
    return res


def replay(name, only, fim=True, tag='', list_writer=None):
    """Every case against the manager holding all packs.

    Pass 1: the packs whose case files add no test-only list entries, all in
    one go. Pass 2: each pack that does, with its own entries loaded and the
    ruleset reloaded around it. Returns {pack: {'passed', 'total', 'failures'}}.
    """
    tag = tag or name
    cases = load_cases(only)
    plain = [p for p, d in cases.items() if not d.get('sandbox_lists')]
    listed = [p for p, d in cases.items() if d.get('sandbox_lists')]
    state = {'fallback_left': 25}
    result, sessions = {}, {}
    got, how = run_replay_script(name, plain, tag)
    sessions.update(how)
    for pack in plain:
        result[pack] = judge_pack(name, pack, cases[pack], got, fim, state)
    for pack in listed:
        def one(pack=pack):
            g, h = run_replay_script(name, [pack], tag)
            for k, v in h.items():
                sessions[k] = sessions.get(k, 0) + v
            return judge_pack(name, pack, cases[pack], g, fim, state)
        result[pack] = with_case_lists(name, cases[pack], one, list_writer)
    say('%s replay: %d/%d cases' % (tag, sum(v['passed'] for v in result.values()),
                                    sum(v['total'] for v in result.values())))
    result['_sessions'] = {'passed': 0, 'total': 0, 'failures': [], 'socket_only': 0, 'how': sessions}
    return result


# --------------------------------------------------------------------------
# Container life cycle
# --------------------------------------------------------------------------

API_RESTART = r"""
for p in $(ps -eo pid,args | awk '$3 ~ /wazuh_apid\.py$/ {print $1}'); do kill -9 $p; done
sleep 2
/var/ossec/bin/wazuh-apid >/dev/null 2>&1
for i in $(seq 1 60); do
  c=$(curl -sk -o /dev/null -w "%{http_code}" -u wazuh:wazuh -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true")
  [ "$c" = 200 ] && echo ready && exit 0
  sleep 3
done
echo "api not ready: $c"
"""


def api_ready(name):
    """The image runs Wazuh under s6; wazuh-control restart leaves the old API
    bound to 55000 and the new one's process pool broken (every request 500).
    A container artefact, not a manager one: kill every API process, start one."""
    r = dexec(name, 'sh', data=API_RESTART, check=False, timeout=400)
    if 'ready' not in r.stdout:
        raise RuntimeError('Wazuh API did not come back in %s: %s' % (name, r.stdout[-300:]))


def start(name, image, hostname=None, network=None):
    run(['docker', 'rm', '-f', name], check=False)
    cmd = ['docker', 'run', '-d', '--name', name, '--label', 'jtgate=1']
    if hostname:
        cmd += ['--hostname', hostname]
    if network:
        cmd += ['--network', network]
    cid = run(cmd + [image]).stdout.strip()
    sb.wait_ready(name, seconds=400)
    sb.slim(name)
    api_ready(name)
    return cid


def remove(name):
    run(['docker', 'rm', '-f', name], check=False)


def conf_edit(name, fn):
    conf = dexec(name, 'cat', OSSEC + '/etc/ossec.conf').stdout
    new = fn(conf)
    if new != conf:
        dexec(name, 'sh', '-c', 'cat > %s/etc/ossec.conf' % OSSEC, data=new)


def restart(name):
    dexec(name, OSSEC + '/bin/wazuh-control', 'restart', timeout=600)
    sb.wait_ready(name, seconds=400)
    api_ready(name)


def ruleset_check(name):
    r = dexec(name, OSSEC + '/bin/wazuh-analysisd', '-t', check=False, timeout=600)
    bad = [l for l in (r.stdout + r.stderr).splitlines() if re.search(r'ERROR|CRITICAL|WARNING', l)]
    return {'ok': r.returncode == 0 and not bad, 'rc': r.returncode, 'problems': bad[:40]}


def prepare_for_replay(name, cases):
    """What pack_sandbox install does around the files: quiet levels logged
    (FIM cases are judged from alerts.json) and a case file's test-only list
    entries (a site's allowlist) appended."""
    conf_edit(name, lambda c: re.sub(r'<log_alert_level>\d+</log_alert_level>',
                                     '<log_alert_level>1</log_alert_level>', c, count=1))
    # a new logtest session loads the whole ruleset (about 6 s of CPU with every
    # pack): sessions that must start clean run side by side
    conf_edit(name, lambda c: re.sub(r'(<rule_test>(?:(?!</rule_test>).)*?<threads>)\d+(</threads>)',
                                     r'\g<1>%d\2' % LOGTEST_THREADS, c, count=1, flags=re.S))
    # the case files' test-only list entries are loaded per pack by replay():
    # loaded together, jt-ioc's documentation addresses turned every other
    # pack's test login from those addresses into a threat-list hit


# --------------------------------------------------------------------------
# Checks after an install or update
# --------------------------------------------------------------------------

MITRE_IDS = r'''
import sqlite3, json
db = sqlite3.connect('/var/ossec/var/db/mitre.db')
tables = [r[0] for r in db.execute("select name from sqlite_master where type='table'")]
ids = set()
for t in tables:
    cols = [r[1] for r in db.execute('pragma table_info("%s")' % t)]
    if 'external_id' in cols:
        for (v,) in db.execute('select external_id from "%s"' % t):
            if v: ids.add(v)
v = ''
if 'metadata' in tables:
    try:
        v = dict(db.execute('select key, value from metadata').fetchall()).get('mitre_version', '')
    except Exception:
        pass
print(json.dumps({'ids': sorted(ids), 'version': v}))
'''


def pack_mitre_ids(only):
    used = {}
    for path in glob.glob(os.path.join(ROOT, 'packs', '*', 'rules', '*.xml')):
        pack = path.split(os.sep)[-3]
        if only and pack not in only:
            continue
        with open(path, encoding='utf-8') as fh:
            for mid in re.findall(r'<id>(T\d{4}(?:\.\d{3})?)</id>', fh.read()):
                used.setdefault(mid, set()).add(pack)
    return used


def post_install_checks(name, packs_state, install_results, only, version):
    checks = {}
    checks['ruleset'] = ruleset_check(name)
    want = set(only) if only else {p['id'] for p in packs_state}
    not_current = [{'pack': p['id'], 'status': p.get('version_status'), 'installed': p.get('installed_version'),
                    'catalogue': p.get('version')}
                   for p in packs_state if p['id'] in want and p.get('version_status') != 'current']
    checks['all_current'] = {'ok': not not_current, 'problems': not_current}
    # agent groups: the tool makes the directory; Wazuh has to know the group too
    groups = dexec(name, OSSEC + '/bin/agent_groups', '-l', '-q', check=False).stdout
    expected_groups = {}
    for pid in want:
        with open(os.path.join(ROOT, 'packs', pid, 'manifest.json'), encoding='utf-8') as fh:
            g = (json.load(fh).get('agent_group') or {}).get('name')
        if g:
            expected_groups[pid] = g
    missing_groups = [{'pack': p, 'group': g} for p, g in sorted(expected_groups.items())
                      if not re.search(r'(^|\s)%s\b' % re.escape(g), groups)]
    checks['groups_registered'] = {'ok': not missing_groups, 'problems': missing_groups}
    # schedules the install reported must exist
    sched_problems = []
    for res in install_results:
        for job in (res.get('body') or {}).get('scheduled') or []:
            cron = '/etc/cron.d/jt-' + re.sub(r'[^A-Za-z0-9_-]', '-', res['pack'])
            r = dexec(name, 'sh', '-c', 'grep -F %s %s' % (sbq(job['script']), cron), check=False)
            if r.returncode != 0:
                sched_problems.append({'pack': res['pack'], 'script': job['script'], 'cron_file': cron,
                                       'error': 'reported as scheduled, not in the cron file'})
    checks['schedules_written'] = {'ok': not sched_problems, 'problems': sched_problems}
    # scripts must run with the manager's system python (what the cron line names)
    py = dexec(name, 'sh', '-c', '/usr/bin/python3 -V 2>&1 || echo none', check=False).stdout.strip()
    script_problems = []
    scripts = dexec(name, 'sh', '-c', 'ls %s/etc/jt-packs/bin/ 2>/dev/null' % OSSEC, check=False).stdout.split()
    for s in scripts:
        path = '%s/etc/jt-packs/bin/%s' % (OSSEC, s)
        if s.endswith('.py'):
            r = dexec(name, 'sh', '-c', '/usr/bin/python3 -m py_compile %s && /usr/bin/python3 %s --help >/dev/null'
                      % (path, path), check=False, timeout=120)
            if r.returncode != 0:
                script_problems.append({'script': s, 'python': py, 'error': (r.stdout + r.stderr)[-400:]})
    checks['scripts_run'] = {'ok': not script_problems, 'python': py, 'problems': script_problems}
    # MITRE: an ID the version's database lacks costs a warning on every alert
    m = json.loads(dexec(name, OSSEC + '/framework/python/bin/python3', '-c', MITRE_IDS).stdout)
    known = set(m['ids'])
    unknown = [{'id': mid, 'packs': sorted(p)} for mid, p in sorted(pack_mitre_ids(only).items()) if mid not in known]
    checks['mitre_ids'] = {'ok': not unknown, 'mitre_version': m['version'], 'known': len(known),
                           'problems': unknown}
    return checks


def sbq(s):
    return "'" + s.replace("'", "'\\''") + "'"


def install_order(only):
    """Partners named by a case file first (a correlating pack after the packs it
    correlates), jt-account-guard last; otherwise alphabetical."""
    packs = sorted(d for d in os.listdir(os.path.join(ROOT, 'packs'))
                   if os.path.isfile(os.path.join(ROOT, 'packs', d, 'manifest.json')))
    if only:
        packs = [p for p in packs if p in only]
    late = [p for p in packs if p == 'jt-account-guard']
    return [p for p in packs if p not in late] + late


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

def scenario_fresh(version, only, workdir, keep):
    name = 'jtgate-fresh-' + version.replace('.', '-')
    tgz = os.path.join(workdir, 'tool-cp310.tgz')
    res = {'scenario': 'fresh-' + version, 'image': 'wazuh/wazuh-manager:' + version}
    try:
        say('%s: starting' % name)
        start(name, res['image'])
        res['cron_dir_in_image'] = dexec(name, 'sh', '-c', 'test -d /etc/cron.d && echo yes || echo no').stdout.strip()
        # a packaged manager (deb/rpm) has cron; the container image does not
        dexec(name, 'mkdir', '-p', '/etc/cron.d')
        put_tool(name, tgz)
        order = install_order(only)
        out = driver(name, 'install', {'packs': order, 'version': version})
        res['install'] = [{'pack': r['pack'], 'status': r['status'],
                           'error': (r['body'] or {}).get('error'), 'message': (r['body'] or {}).get('message', '')[:300]}
                          for r in out['results']]
        res['install_ok'] = all(r['status'] == 200 for r in out['results'])
        res['checks'] = post_install_checks(name, out['packs'], out['results'], only, version)
        cases = load_cases(only)
        prepare_for_replay(name, cases)
        restart(name)
        res['replay'] = replay(name, only, tag=name)
    except Exception as e:
        res['fatal'] = str(e)[-3000:]
    finally:
        if not keep:
            remove(name)
    return res


def scenario_no_cron(version, workdir, keep):
    """Official container image: no /etc/cron.d. A scheduled pack must not be
    reported as scheduled when nothing was written."""
    name = 'jtgate-nocron'
    res = {'scenario': 'no-cron', 'image': 'wazuh/wazuh-manager:' + version}
    try:
        start(name, res['image'])
        has = dexec(name, 'sh', '-c', 'test -d /etc/cron.d && echo yes || echo no').stdout.strip()
        put_tool(name, os.path.join(workdir, 'tool-cp310.tgz'))
        out = driver(name, 'install', {'packs': ['jt-ioc'], 'version': version})
        r = out['results'][0]
        body = r['body'] or {}
        files = dexec(name, 'sh', '-c', 'ls /etc/cron.d 2>/dev/null', check=False).stdout.split()
        res.update({'cron_dir': has, 'status': r['status'], 'reported_scheduled': body.get('scheduled'),
                    'message': body.get('message', '')[:400], 'cron_files': files})
        # Claiming a schedule that was not written fails. Saying so, with the
        # line to add by hand (written: false since v1.23.3), passes.
        claimed = [j for j in (body.get('scheduled') or []) if j.get('written', True)]
        res['ok'] = not (claimed and not files) and (
            files or 'could NOT schedule' in (body.get('message') or ''))
    except Exception as e:
        res['fatal'] = str(e)[-3000:]
    finally:
        if not keep:
            remove(name)
    return res


def scenario_upgrade(version, from_tag, only, workdir, keep):
    name = 'jtgate-upgrade'
    res = {'scenario': 'upgrade', 'from': from_tag, 'image': 'wazuh/wazuh-manager:' + version}
    old_tree = tempfile.mkdtemp(prefix='jtgate-old-')
    try:
        raw = subprocess.run(['git', '-C', os.path.join(ROOT, 'github'), 'archive', '--format=tar', from_tag,
                              'lib', 'packs', 'wazuh_agent_mgr.py'], capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
            tf.extractall(old_tree)
        old_tgz = os.path.join(workdir, 'tool-old.tgz')
        bundle(old_tree, 'cp310', old_tgz)
        old_packs = sorted(d for d in os.listdir(os.path.join(old_tree, 'packs'))
                           if os.path.isfile(os.path.join(old_tree, 'packs', d, 'manifest.json')))
        if only:
            old_packs = [p for p in old_packs if p in only]
        late = [p for p in old_packs if p == 'jt-account-guard']
        old_order = [p for p in old_packs if p not in late] + late
        say('%s: starting (packs of %s first)' % (name, from_tag))
        start(name, res['image'])
        dexec(name, 'mkdir', '-p', '/etc/cron.d')
        put_tool(name, old_tgz)
        out = driver(name, 'install', {'packs': old_order, 'version': version})
        res['old_install'] = [{'pack': r['pack'], 'status': r['status'], 'error': (r['body'] or {}).get('error')}
                              for r in out['results']]
        res['old_install_ok'] = all(r['status'] == 200 for r in out['results'])
        res['old_ruleset'] = ruleset_check(name)
        # the new release of the tool, then every pack updated
        put_tool(name, os.path.join(workdir, 'tool-cp310.tgz'))
        up = driver(name, 'update', {'version': version})
        res['update'] = [{'pack': r['pack'], 'from': r['from'], 'to': r['to'], 'status': r['status'],
                          'error': (r['body'] or {}).get('error'),
                          'message': (r['body'] or {}).get('message', '')[:300]} for r in up['results']]
        res['update_ok'] = all(r['status'] == 200 for r in up['results'])
        new_packs = [p for p in install_order(only) if p not in old_packs]
        if new_packs:
            ni = driver(name, 'install', {'packs': new_packs, 'version': version})
            res['new_installs'] = [{'pack': r['pack'], 'status': r['status'], 'error': (r['body'] or {}).get('error')}
                                   for r in ni['results']]
            res['update_ok'] = res['update_ok'] and all(r['status'] == 200 for r in ni['results'])
            state = ni['packs']
            results = up['results'] + ni['results']
        else:
            state, results = up['packs'], up['results']
        res['checks'] = post_install_checks(name, state, results, only, version)
        cases = load_cases(only)
        prepare_for_replay(name, cases)
        restart(name)
        res['replay'] = replay(name, only, tag=name)
    except Exception as e:
        res['fatal'] = str(e)[-3000:]
    finally:
        shutil.rmtree(old_tree, ignore_errors=True)
        if not keep:
            remove(name)
    return res


# The worker steps in the packs' setup guides are written for a person. These
# patterns are the forms they use; a line matching none is reported as manual.
SCP = re.compile(r'^scp\s+(?:-\S+\s+)*((?:/\S+\s+)+)<worker>:(\S+)\s*(?:#.*)?$')
SSH = re.compile(r"""^ssh\s+<worker>\s+(['"])(.*)\1\s*(?:#.*)?$""")
ON_WORKER_REDIRECT = re.compile(r'^(.*>\s*/etc/cron\.d/\S+)\s*#\s*on the worker\s*$')
CRON_FILE_COMMENT = re.compile(r'^#\s*on the worker,?\s*(/etc/cron\.d/\S+)\s*$')
CRON_LINE = re.compile(r'^[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+root\s+\S+')
LIST_DECL = re.compile(r'^<list>(etc/lists/[^<]+)</list>$')


def worker_steps():
    """[(pack, title, code)] for every manager step that talks about workers."""
    out = []
    for path in sorted(glob.glob(os.path.join(ROOT, 'packs', '*', 'manifest.json'))):
        with open(path, encoding='utf-8') as fh:
            m = json.load(fh)
        for s in m.get('setup') or []:
            code = s.get('code') or ''
            if s.get('platform') == 'manager' and ('<worker>' in code or 'on the worker' in code):
                out.append((m['id'], s.get('title', ''), code))
    return out


def carry_out_worker_steps(master, worker, only):
    log, manual, list_lines = [], [], []
    for pack, title, code in worker_steps():
        if only and pack not in only:
            continue
        cron_target = None
        cron_body = []
        for raw in code.splitlines():
            line = raw.strip()
            if not line:
                continue
            m = SCP.match(line)
            if m:
                dest = m.group(2)
                for src in m.group(1).split():
                    target = dest + os.path.basename(src) if dest.endswith('/') else dest
                    data = dexec(master, 'cat', src, check=False)
                    if data.returncode != 0:
                        log.append({'pack': pack, 'step': title, 'line': line, 'ok': False,
                                    'error': 'source missing on the master: %s' % src})
                        continue
                    mode = dexec(master, 'stat', '-c', '%a', src).stdout.strip()
                    dexec(worker, 'sh', '-c', 'mkdir -p "$(dirname %s)" && cat > %s && chmod %s %s'
                          % (sbq(target), sbq(target), mode, sbq(target)), data=data.stdout)
                    log.append({'pack': pack, 'step': title, 'line': line, 'ok': True})
                continue
            m = SSH.match(line)
            if m:
                r = dexec(worker, 'sh', '-c', m.group(2), check=False)
                log.append({'pack': pack, 'step': title, 'line': line, 'ok': r.returncode == 0,
                            'error': (r.stdout + r.stderr)[-300:] if r.returncode else None})
                continue
            m = ON_WORKER_REDIRECT.match(line)
            if m:
                r = dexec(worker, 'sh', '-c', m.group(1), check=False)
                log.append({'pack': pack, 'step': title, 'line': line, 'ok': r.returncode == 0,
                            'error': (r.stdout + r.stderr)[-300:] if r.returncode else None})
                continue
            m = CRON_FILE_COMMENT.match(line)
            if m:
                cron_target = m.group(1)
                continue
            if cron_target and CRON_LINE.match(line):
                cron_body.append(line)
                continue
            m = LIST_DECL.match(line)
            if m:
                list_lines.append((pack, m.group(1)))
                continue
            if line.startswith('#'):
                continue
            manual.append({'pack': pack, 'step': title, 'line': line})
        if cron_target and cron_body:
            dexec(worker, 'sh', '-c', 'cat > %s && chmod 644 %s' % (sbq(cron_target), sbq(cron_target)),
                  data='\n'.join(cron_body) + '\n')
            log.append({'pack': pack, 'step': title, 'line': 'cron file %s (%d lines)' % (cron_target, len(cron_body)),
                        'ok': True})
    return log, manual, list_lines


def scenario_cluster(version, only, workdir, keep):
    master, worker = 'jtgate-master', 'jtgate-worker'
    res = {'scenario': 'cluster', 'image': 'wazuh/wazuh-manager:' + version}
    try:
        run(['docker', 'network', 'create', NETWORK], check=False)
        say('cluster: starting master and worker')
        start(master, res['image'], hostname='jtgate-master', network=NETWORK)
        start(worker, res['image'], hostname='jtgate-worker', network=NETWORK)

        def cluster_block(node, kind):
            return ('<cluster>\n    <name>jtgate</name>\n    <node_name>%s</node_name>\n'
                    '    <node_type>%s</node_type>\n    <key>%s</key>\n    <port>1516</port>\n'
                    '    <bind_addr>0.0.0.0</bind_addr>\n    <nodes>\n        <node>jtgate-master</node>\n'
                    '    </nodes>\n    <hidden>no</hidden>\n    <disabled>no</disabled>\n  </cluster>'
                    % (node, kind, CLUSTER_KEY))
        for n, node, kind in ((master, 'master', 'master'), (worker, 'worker', 'worker')):
            conf_edit(n, lambda c, node=node, kind=kind: re.sub(r'<cluster>.*?</cluster>', cluster_block(node, kind),
                                                                c, count=1, flags=re.S))
            dexec(n, 'mkdir', '-p', '/etc/cron.d')
            restart(n)
        end = time.time() + 300
        nodes = ''
        while time.time() < end:
            nodes = dexec(master, OSSEC + '/bin/cluster_control', '-l', check=False).stdout
            if 'worker' in nodes and 'master' in nodes:
                break
            time.sleep(5)
        res['cluster_nodes'] = nodes.strip()
        if 'worker' not in nodes:
            raise RuntimeError('worker never joined the cluster:\n' + nodes)
        put_tool(master, os.path.join(workdir, 'tool-cp310.tgz'))
        put_tool(worker, os.path.join(workdir, 'tool-cp310.tgz'))   # only the case files are used there
        out = driver(master, 'install', {'packs': install_order(only), 'version': version})
        res['install'] = [{'pack': r['pack'], 'status': r['status'], 'error': (r['body'] or {}).get('error'),
                           'undeclared': (r['body'] or {}).get('message', '').count('could NOT be declared')}
                          for r in out['results']]
        res['install_ok'] = all(r['status'] == 200 for r in out['results'])
        declared = sorted({l for r in out['results'] for l in ((r['body'] or {}).get('declared_lists') or [])})
        # wait for the cluster to copy rules, decoders and lists to the worker
        probe = '%s/etc/rules/zzzz-132700-jt_account_guard_rules.xml' % OSSEC
        end = time.time() + 600
        while time.time() < end:
            m = dexec(master, 'sh', '-c', 'cd %s/etc && find rules decoders lists -type f ! -name "*.cdb" | sort | xargs md5sum' % OSSEC,
                      check=False).stdout
            w = dexec(worker, 'sh', '-c', 'cd %s/etc && find rules decoders lists -type f ! -name "*.cdb" | sort | xargs md5sum' % OSSEC,
                      check=False).stdout
            if m == w:
                break
            time.sleep(10)
        res['files_synced'] = (m == w)
        if m != w:
            ms, ws = set(m.splitlines()), set(w.splitlines())
            res['sync_diff'] = sorted(x.split()[-1] for x in ms ^ ws)[:40]
        wconf = dexec(worker, 'cat', OSSEC + '/etc/ossec.conf').stdout
        res['lists_declared_by_tool_on_worker'] = {
            'ok': all(('<list>%s</list>' % l) in wconf for l in declared),
            'missing': [l for l in declared if ('<list>%s</list>' % l) not in wconf]}
        log, manual, list_lines = carry_out_worker_steps(master, worker, only)
        res['worker_steps'] = log
        res['worker_steps_manual'] = manual
        res['worker_steps_list_lines'] = [{'pack': p, 'list': l, 'already_declared': ('<list>%s</list>' % l) in wconf}
                                          for p, l in list_lines]
        # every scheduled script on the master must exist and be scheduled on the worker,
        # unless it is a master-only job (documented as such in the guides)
        mcron = dexec(master, 'sh', '-c', 'cat /etc/cron.d/jt-* 2>/dev/null', check=False).stdout
        wcron = dexec(worker, 'sh', '-c', 'cat /etc/cron.d/* 2>/dev/null', check=False).stdout
        mscripts = sorted(set(re.findall(r'/var/ossec/etc/jt-packs/bin/(\S+)', mcron)))
        wscripts = dexec(worker, 'sh', '-c', 'ls %s/etc/jt-packs/bin 2>/dev/null' % OSSEC, check=False).stdout.split()
        res['worker_scripts'] = [{'script': s, 'on_worker': s in wscripts,
                                  'scheduled_on_worker': ('/var/ossec/etc/jt-packs/bin/' + s) in wcron}
                                 for s in mscripts]
        res['worker_ruleset'] = ruleset_check(worker)
        cases = load_cases(only)
        for n in (master, worker):
            prepare_for_replay(n, cases)
            restart(n)
        res['replay_master'] = replay(master, only, fim=False, tag='cluster master')
        res['replay_worker'] = replay(worker, only, fim=False, tag='cluster worker', list_writer=master)
    except Exception as e:
        res['fatal'] = str(e)[-3000:]
    finally:
        if not keep:
            remove(master)
            remove(worker)
            run(['docker', 'network', 'rm', NETWORK], check=False)
    return res


# --------------------------------------------------------------------------
# Verdict and report
# --------------------------------------------------------------------------

def failed_items(res):
    """Human-readable failures of one scenario result."""
    out = []
    if res.get('fatal'):
        out.append('fatal: ' + res['fatal'].splitlines()[0][:300])
    for key in ('install', 'old_install', 'update', 'new_installs'):
        for r in res.get(key) or []:
            if r.get('status') != 200:
                out.append('%s %s: HTTP %s %s' % (key, r['pack'], r.get('status'), (r.get('error') or '')[:200]))
    for name, chk in (res.get('checks') or {}).items():
        if not chk.get('ok'):
            out.append('check %s: %s' % (name, json.dumps(chk.get('problems'))[:600]))
    for key in ('replay', 'replay_master', 'replay_worker'):
        for pack, r in sorted((res.get(key) or {}).items()):
            if r['failures']:
                out.append('%s %s: %d/%d failed, e.g. case %s want %s got %s'
                           % (key, pack, len(r['failures']), r['total'], r['failures'][0]['i'],
                              r['failures'][0]['want'], r['failures'][0]['got'][:2]))
    if res.get('scenario') == 'no-cron' and not res.get('ok', True):
        out.append('install reported %s as scheduled with no cron file written' % res.get('reported_scheduled'))
    if res.get('scenario') == 'cluster':
        if res.get('files_synced') is False:
            out.append('cluster: rules/decoders/lists differ on the worker: %s' % res.get('sync_diff'))
        lst = res.get('lists_declared_by_tool_on_worker') or {}
        if lst and not lst.get('ok'):
            out.append('cluster: lists not declared on the worker by the tool: %s' % lst.get('missing'))
        for s in res.get('worker_steps') or []:
            if not s['ok']:
                out.append('worker step %s: %s -> %s' % (s['pack'], s['line'][:120], s.get('error')))
        for s in res.get('worker_scripts') or []:
            if not (s['on_worker'] and s['scheduled_on_worker']):
                out.append('worker: %s on_worker=%s scheduled=%s' % (s['script'], s['on_worker'], s['scheduled_on_worker']))
        wr = res.get('worker_ruleset') or {}
        if wr and not wr.get('ok'):
            out.append('worker ruleset: %s' % wr.get('problems')[:5])
    return out


def summary_md(results, versions, from_tag):
    lines = ['# Pack release gate %s' % datetime.datetime.now().strftime('%Y-%m-%d %H:%M'), '',
             'versions: %s; upgrade from %s' % (', '.join(versions), from_tag), '',
             '| scenario | verdict | replay | notes |', '|---|---|---|---|']
    for r in results:
        fails = failed_items(r)
        rp = r.get('replay') or r.get('replay_master') or {}
        rep = '%d/%d' % (sum(v['passed'] for v in rp.values()), sum(v['total'] for v in rp.values())) if rp else '-'
        skipped = sum(v.get('skipped', 0) for v in rp.values()) if rp else 0
        if skipped:
            rep += ' (%d skipped: min_wazuh)' % skipped
        lines.append('| %s | %s | %s | %s |' % (r['scenario'], 'PASS' if not fails else 'FAIL (%d)' % len(fails), rep,
                                               (fails[0][:120] if fails else '')))
    lines.append('')
    for r in results:
        fails = failed_items(r)
        if fails:
            lines.append('## %s' % r['scenario'])
            lines += ['- ' + f for f in fails]
            lines.append('')
        if r.get('worker_steps_manual'):
            lines.append('### %s: worker steps not automated (written for a person)' % r['scenario'])
            lines += ['- %s: `%s`' % (m['pack'], m['line'][:160]) for m in r['worker_steps_manual']]
            lines.append('')
    return '\n'.join(lines) + '\n'


def leftover_mounts():
    """Our own leaked containerd mounts: a Wazuh rootfs no container uses."""
    found = []
    for d in glob.glob('/tmp/containerd-mount*'):
        if os.path.isdir(os.path.join(d, 'var', 'ossec')):
            found.append(d)
    return found


def cmd_run(a):
    versions = a.versions.split(',') if a.versions else DEFAULT_VERSIONS
    only = set(a.only.split(',')) if a.only else set()
    skip = set(a.skip.split(',')) if a.skip else set()
    workdir = a.resume or os.path.join(ROOT, 'temp', 'pack-gate', datetime.datetime.now().strftime('%Y%m%d-%H%M'))
    os.makedirs(workdir, exist_ok=True)
    global RAW_DIR
    RAW_DIR = workdir
    tags = run(['git', '-C', os.path.join(ROOT, 'github'), 'tag', '--sort=-v:refname']).stdout.split()
    from_tag = a.from_tag
    if not from_tag:
        # the newest tag of the previous minor release: what a customer most
        # plausibly still runs when this one comes out
        cur = re.search(r'__version__\s*=\s*"([^"]+)"', open(os.path.join(ROOT, 'lib', '__init__.py')).read()).group(1)
        major, minor = cur.split('.')[:2]
        prev = [t for t in tags if re.match(r'^v%s\.%d\.\d+$' % (major, int(minor) - 1), t)]
        from_tag = prev[0] if prev else tags[1]
    say('gate: versions %s, upgrade from %s, report in %s' % (versions, from_tag, workdir))
    bundle(ROOT, 'cp310', os.path.join(workdir, 'tool-cp310.tgz'))
    for v in versions:
        img = 'wazuh/wazuh-manager:' + v
        if run(['docker', 'image', 'inspect', img], check=False).returncode != 0:
            say('pulling %s' % img)
            run(['docker', 'pull', '-q', img], timeout=3600)

    def done(scn):
        return os.path.isfile(os.path.join(workdir, scn + '.json'))

    def save(res):
        with open(os.path.join(workdir, res['scenario'] + '.json'), 'w', encoding='utf-8') as fh:
            json.dump(res, fh, indent=1, default=str)
        say('%s: %s' % (res['scenario'], 'PASS' if not failed_items(res) else 'FAIL (%d)' % len(failed_items(res))))

    jobs = []
    if 'fresh' not in skip:
        jobs += [('fresh-' + v, (lambda v=v: scenario_fresh(v, only, workdir, a.keep))) for v in versions]
    latest = versions[-1]
    if 'no-cron' not in skip:
        jobs.append(('no-cron', lambda: scenario_no_cron(latest, workdir, a.keep)))
    if 'upgrade' not in skip:
        jobs.append(('upgrade', lambda: scenario_upgrade(latest, from_tag, only, workdir, a.keep)))
    if 'cluster' not in skip:
        jobs.append(('cluster', lambda: scenario_cluster(latest, only, workdir, a.keep)))
    jobs = [j for j in jobs if not done(j[0])]
    # at most four containers at once: the cluster takes two
    sem = threading.Semaphore(4)

    def worker_fn(scn, fn):
        need = 2 if scn == 'cluster' else 1
        for _ in range(need):
            sem.acquire()
        try:
            save(fn())
        except Exception as e:
            save({'scenario': scn, 'fatal': str(e)})
        finally:
            for _ in range(need):
                sem.release()
    threads = [threading.Thread(target=worker_fn, args=j) for j in jobs]
    for t in threads:
        t.start()
        time.sleep(20)              # stagger image start-up
    for t in threads:
        t.join()
    results = []
    for f in sorted(glob.glob(os.path.join(workdir, '*.json'))):
        with open(f, encoding='utf-8') as fh:
            results.append(json.load(fh))
    md = summary_md(results, versions, from_tag)
    with open(os.path.join(workdir, 'SUMMARY.md'), 'w', encoding='utf-8') as fh:
        fh.write(md)
    print(md)
    mounts = leftover_mounts()
    if mounts:
        print('leftover Wazuh overlay mounts (check with lsof +D, then umount + rmdir):', mounts)
    return 1 if any(failed_items(r) for r in results) else 0


def cmd_clean(_a):
    ids = run(['docker', 'ps', '-aq', '--filter', 'label=jtgate=1']).stdout.split()
    if ids:
        run(['docker', 'rm', '-f'] + ids, check=False)
    run(['docker', 'network', 'rm', NETWORK], check=False)
    print('removed %d container(s)' % len(ids))
    return 0


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('--versions')
    r.add_argument('--only')
    r.add_argument('--skip')
    r.add_argument('--from-tag')
    r.add_argument('--keep', action='store_true')
    r.add_argument('--resume')
    sub.add_parser('clean')
    a = ap.parse_args()
    sys.exit({'run': cmd_run, 'clean': cmd_clean}[a.cmd](a))
