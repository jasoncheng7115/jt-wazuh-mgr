#!/usr/bin/env python3
"""Test a rule pack in a throwaway Wazuh manager container, never on a real one.

    tools/pack_sandbox.py up <pack-id>        start jtsbx-<pack-id> (wazuh/wazuh-manager)
    tools/pack_sandbox.py install <pack-id>   copy the pack in, declare its lists, check, restart
    tools/pack_sandbox.py test <pack-id>      run tests/pack_cases/<pack-id>.json through logtest
    tools/pack_sandbox.py down <pack-id>      remove the container
    tools/pack_sandbox.py slim <pack-id>      shrink a container started before `up` did it

A pack is tested on a live manager until now, and one syntax error there is
one restart away from a manager that does not come back. The container gives
every pack its own analysisd, so several can be developed side by side.

Case file format, tests/pack_cases/<pack-id>.json:
    {"pack": "<id>", "sandbox_lists": {"<list>": "key:value\n"},
     "cases": [{"log": "...", "location": "/var/log/x.log",
      "expect_rule": "131201", "expect_level": 5, "repeat": 1, "note": "..."}]}
expect_rule "none" means no rule above level 0 may match. repeat sends the
line that many times in one logtest session (for frequency rules) and judges
the last event.
"""

import json
import os
import re
import subprocess
import sys
import time

IMAGE = os.environ.get('JT_SANDBOX_IMAGE', 'wazuh/wazuh-manager:4.14.7')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OSSEC = '/var/ossec'


def run(cmd, data=None, check=True):
    r = subprocess.run(cmd, input=data, capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit('command failed: %s' % ' '.join(cmd))
    return r


def name_of(pack):
    if not re.match(r'^[a-z0-9][a-z0-9._-]{0,63}$', pack):
        raise SystemExit('invalid pack id')
    return 'jtsbx-' + pack


def wait_ready(name, seconds=180):
    end = time.time() + seconds
    while time.time() < end:
        r = run(['docker', 'exec', name, OSSEC + '/bin/wazuh-control', 'status'], check=False)
        if 'wazuh-analysisd is running' in r.stdout:
            break
        time.sleep(3)
    else:
        raise SystemExit('analysisd did not start in %s' % name)
    # "running" comes before logtest answers: the first cases after a restart
    # used to come back as "no match".
    while time.time() < end:
        r = run(['docker', 'exec', '-i', name, OSSEC + '/bin/wazuh-logtest'],
                data='jt sandbox readiness probe\n', check=False)
        if 'Phase 1: Completed pre-decoding' in r.stdout + r.stderr:
            return
        time.sleep(2)
    raise SystemExit('logtest did not answer in %s' % name)


def slim(name):
    """Switch off what rule tests never use and that fills the disk.

    On first start the manager image unpacks its vulnerability feed (a 3 GB
    tar plus the database built from it) and queues events for an indexer it
    does not have: 9 to 14 GB per container. Ten sandboxes side by side filled
    the root disk of a shared machine. Analysis, decoders, rules and logtest do
    not depend on either.
    """
    conf = run(['docker', 'exec', name, 'cat', OSSEC + '/etc/ossec.conf']).stdout
    for block in ('vulnerability-detection', 'indexer'):
        # Confined to the block: once it already says "no", an unconfined .*?
        # ran on to the next <enabled>yes in the file and switched logtest off.
        conf = re.sub(r'(<%s>(?:(?!</%s>).)*?<enabled>)yes(</enabled>)' % (block, block),
                      r'\1no\2', conf, count=1, flags=re.S)
    run(['docker', 'exec', '-i', name, 'sh', '-c', 'cat > %s/etc/ossec.conf' % OSSEC], data=conf)
    run(['docker', 'exec', name, 'sh', '-c',
         'rm -rf %s/tmp/vd_* %s/queue/vd/* %s/queue/indexer/*' % (OSSEC, OSSEC, OSSEC)], check=False)
    run(['docker', 'exec', name, OSSEC + '/bin/wazuh-control', 'restart'])
    wait_ready(name)


def up(pack):
    name = name_of(pack)
    run(['docker', 'rm', '-f', name], check=False)
    run(['docker', 'run', '-d', '--name', name, IMAGE])
    wait_ready(name)
    slim(name)
    print('%s is running' % name)


def install(pack):
    name = name_of(pack)
    pdir = os.path.join(ROOT, 'packs', pack)
    with open(os.path.join(pdir, 'manifest.json'), encoding='utf-8') as fh:
        manifest = json.load(fh)
    lists = []
    for entry in manifest.get('files', []):
        sub = {'rule': 'rules', 'list': 'lists'}.get(entry['type'], 'decoders')
        dest = OSSEC + '/' + entry['dest']
        run(['docker', 'cp', os.path.join(pdir, sub, entry['name']), '%s:%s' % (name, dest)])
        run(['docker', 'exec', name, 'chown', 'wazuh:wazuh', dest])
        if entry['type'] == 'list' and entry.get('declare'):
            lists.append(entry['dest'])
    conf = run(['docker', 'exec', name, 'cat', OSSEC + '/etc/ossec.conf']).stdout
    for rel in lists:
        tag = '<list>%s</list>' % rel
        if tag not in conf:
            conf = conf.replace('</ruleset>', '  %s\n  </ruleset>' % tag, 1)
    run(['docker', 'exec', '-i', name, 'sh', '-c', 'cat > %s/etc/ossec.conf' % OSSEC], data=conf)
    # Entries a case file wants in a list for the test only (a site's allowlist).
    cases_path = os.path.join(ROOT, 'tests', 'pack_cases', pack + '.json')
    if os.path.isfile(cases_path):
        with open(cases_path, encoding='utf-8') as fh:
            extra = json.load(fh).get('sandbox_lists') or {}
        for list_name, body in extra.items():
            if not re.match(r'^[A-Za-z0-9._-]+$', list_name):
                raise SystemExit('invalid list name in sandbox_lists')
            run(['docker', 'exec', '-i', name, 'sh', '-c',
                 'cat >> %s/etc/lists/%s' % (OSSEC, list_name)], data=body)
    check = run(['docker', 'exec', name, OSSEC + '/bin/wazuh-analysisd', '-t'], check=False)
    # Warnings fail too: a clean manager prints none, and the ones a pack causes
    # mean part of it is ignored (an if_matched_sid with a list of IDs drops the
    # whole rule with nothing but a warning).
    bad = [l for l in (check.stdout + check.stderr).splitlines()
           if re.search(r'ERROR|CRITICAL|WARNING', l)]
    if check.returncode != 0 or bad:
        print('\n'.join(bad) or check.stderr)
        raise SystemExit('ruleset check failed')
    run(['docker', 'exec', name, OSSEC + '/bin/wazuh-control', 'restart'])
    wait_ready(name)
    print('installed %s %s (%d lists declared), ruleset check passed'
          % (pack, manifest.get('version', ''), len(lists)))


def logtest(name, lines, location=None):
    cmd = ['docker', 'exec', '-i', name, OSSEC + '/bin/wazuh-logtest']
    if location:
        cmd += ['-l', location]
    r = run(cmd, data='\n'.join(lines) + '\n', check=False)
    out = r.stdout + r.stderr          # wazuh-logtest prints its results on stderr
    events = out.split('**Phase 1: Completed pre-decoding.')[1:]
    results = []
    for ev in events:
        phase3 = ev.split('**Phase 3: Completed filtering (rules).')
        if len(phase3) < 2:
            results.append(('none', 0, ''))
            continue
        rid = re.search(r"\tid: '(\d+)'", phase3[1])
        lvl = re.search(r"\tlevel: '(\d+)'", phase3[1])
        desc = re.search(r"\tdescription: '(.*)'", phase3[1])
        results.append((rid.group(1) if rid else 'none', int(lvl.group(1)) if lvl else 0,
                        desc.group(1) if desc else ''))
    return results


def test(pack):
    name = name_of(pack)
    with open(os.path.join(ROOT, 'tests', 'pack_cases', pack + '.json'), encoding='utf-8') as fh:
        cases = json.load(fh)['cases']
    failed = 0
    for i, case in enumerate(cases, 1):
        lines = [case['log']] * int(case.get('repeat', 1))
        results = logtest(name, lines, case.get('location'))
        got_rule, got_level, desc = results[-1] if results else ('none', 0, '')
        want_rule, want_level = str(case['expect_rule']), case.get('expect_level')
        if want_rule == 'none':
            ok = got_level == 0
        else:
            ok = got_rule == want_rule and (want_level is None or got_level == want_level)
        failed += not ok
        print('%s %2d  want %-7s L%-3s got %-7s L%-3s %s'
              % ('ok  ' if ok else 'FAIL', i, want_rule, want_level if want_level is not None else '-',
                 got_rule, got_level, (desc or case.get('note', ''))[:90]))
    print('\n%d of %d cases passed' % (len(cases) - failed, len(cases)))
    return 1 if failed else 0


def down(pack):
    run(['docker', 'rm', '-f', name_of(pack)], check=False)
    print('removed %s' % name_of(pack))


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ('up', 'install', 'test', 'down', 'slim'):
        raise SystemExit(__doc__)
    action, pack_id = sys.argv[1], sys.argv[2]
    actions = {'up': up, 'install': install, 'test': test, 'down': down,
               'slim': lambda p: slim(name_of(p))}
    sys.exit(actions[action](pack_id) or 0)
