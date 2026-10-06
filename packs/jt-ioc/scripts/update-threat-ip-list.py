#!/usr/bin/env python3
"""Build the jason_tools_threat_ip CDB list from public IP threat-intel feeds.

Runs from cron. Everything it touches is an absolute path derived from this
file's own location or from --wazuh-path, and nothing depends on the working
directory: the previous version of this job used relative paths, cron ran it
without a cd, and it failed silently for ten and a half months while the list
it feeds sat frozen and thirty rules matched nothing.

Standard library only, so it runs on a manager with no pip packages installed.

  update-threat-ip-list.py [--wazuh-path /var/ossec] [--dry-run] [--force]

Exit status is 0 only if the list was rebuilt or was already current. Any feed
failing is reported but does not by itself fail the run; a feed that fails
leaves its previous copy in place rather than truncating the list.
"""

import argparse
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

# Each feed carries a minimum interval so a frequent cron schedule does not
# hammer a source that only publishes daily.
#
# Feeds are removed when they die rather than left to fail forever. The previous
# configuration still listed maltrail's mass_scanner.txt, which upstream has
# withdrawn; every run logged a 404 that nobody read, because the message carried
# no word anyone greps for.
FEEDS = {
    'blocklistde_all': {
        'url': 'http://lists.blocklist.de/lists/all.txt', 'interval': 14400},
    'firehol_net_ua': {
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_net_ua.ipset',
        'interval': 14400},
    'firehol_de_apache': {
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de_apache.ipset',
        'interval': 14400},
    'firehol_de_bots': {
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de_bots.ipset',
        'interval': 14400},
    'firehol_de_bruteforce': {
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de_bruteforce.ipset',
        'interval': 14400},
    'firehol_de_mail': {
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de_mail.ipset',
        'interval': 14400},
    'firehol_de_imap': {
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de_imap.ipset',
        'interval': 14400},
    'firehol_de_ssh': {
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de_ssh.ipset',
        'interval': 14400},
    'firehol_ciarmy': {
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/iblocklist_ciarmy_malicious.netset',
        'interval': 43200},
    'cins_army': {
        'url': 'https://cinsscore.com/list/ci-badguys.txt', 'interval': 86400},
    'darklist_de': {
        'url': 'https://iplists.firehol.org/files/darklist_de.netset', 'interval': 86400},
    'matthewroberts': {
        'url': 'https://www.matthewroberts.io/api/threatlist/latest', 'interval': 43200},
    # Tor exit nodes are a deliberate inclusion, not an oversight. Tor traffic is
    # not malicious in itself, and a site that expects it should drop this feed
    # rather than live with the alerts. It is listed last so it is easy to find.
    'tor_exit_nodes': {
        'url': 'https://torstatus.rueckgr.at/ip_list_all.php/Tor_ip_list_ALL.csv',
        'interval': 14400},
}

LIST_NAME = 'jason_tools_threat_ip'
UA = 'jt-wazuh-mgr/ioc-updater (+https://github.com/jasoncheng7115/jt-wazuh-mgr)'

# Never block these, whatever a feed says. A public feed listing a root DNS
# server or a CDN edge has happened before, and a blocklist that takes the
# network down is worse than no blocklist.
ALWAYS_EXCLUDE = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4',
    '240.0.0.0/4', '255.255.255.255/32',
    '1.1.1.1/32', '8.8.8.8/32', '8.8.4.4/32', '9.9.9.9/32',
] + [
    # Cloudflare's published edge ranges. A request that arrives through the CDN
    # carries the edge's address in the proxy field and the visitor's in another;
    # a feed listing an edge address flagged every visitor behind it.
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
]

# One feed entry may not expand into more keys than this. A /8 is one key; a /12
# is sixteen; nothing legitimate in a threat feed needs more.
MAX_EXPANSION = 65536

IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')


def log(msg):
    sys.stdout.write('%s %s\n' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg))
    sys.stdout.flush()


def load_exclusions(path):
    """Site exclusions, one IP or CIDR per line, plus the built-in reserved ranges."""
    nets, count = [], 0
    for entry in ALWAYS_EXCLUDE:
        nets.append(ipaddress.ip_network(entry, strict=False))
    if os.path.isfile(path):
        with open(path, encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip()
                if not line:
                    continue
                try:
                    nets.append(ipaddress.ip_network(line, strict=False))
                    count += 1
                except ValueError:
                    log('  exclusion file: ignoring unparseable entry %r' % line[:40])
    log('exclusions: %d built-in reserved ranges, %d from %s'
        % (len(ALWAYS_EXCLUDE), count, path))
    return nets


def excluded(net, exclusions):
    return any(net.subnet_of(e) if net.version == e.version else False for e in exclusions)


def cdb_keys(net):
    """The keys a CDB list needs so that address_match_key finds this network.

    address_match_key looks the address up whole, then cut back to each octet
    boundary: 203.0.113.7, then 203.0.113., 203.0., 203. -- and nothing else. A
    key written as a CIDR, "203.0.113.0/24", is therefore never found. Until 1.3
    the list held 1,276 of those, each one a network the rules could not see.

    Networks on an octet boundary become one prefix key; others are expanded to
    the next boundary down; /25 to /31 become their individual addresses.
    Returns None when a single entry would expand past MAX_EXPANSION.
    """
    if net.version != 4:
        return [str(net.network_address)] if net.prefixlen == 128 else []
    plen = net.prefixlen
    if plen == 32:
        return [str(net.network_address)]
    target = 8 if plen <= 8 else 16 if plen <= 16 else 24 if plen <= 24 else 32
    if (1 << (target - plen)) > MAX_EXPANSION:
        return None
    if target == 32:
        return [str(a) for a in net]
    keep = target // 8
    return ['.'.join(str(sub.network_address).split('.')[:keep]) + '.'
            for sub in net.subnets(new_prefix=target)]


def reload_ruleset(wazuh):
    """Ask this node's analysisd to reload, which recompiles every CDB list.

    Writing the text file changes nothing by itself: analysisd reads the compiled
    .cdb, rebuilt only on a reload. Before 1.3 the list was rewritten every six
    hours and compiled once a night, and the cluster's nodes ran different lists.
    This is the same call the API's reload makes, sent to the local socket.
    """
    python = os.path.join(wazuh, 'framework', 'python', 'bin', 'python3')
    if not os.path.isfile(python):
        log('cannot reload: %s not found (not a manager?)' % python)
        return False
    code = ('import asyncio\n'
            'from wazuh.core.analysis import send_reload_ruleset_msg as s\n'
            'r = asyncio.run(s({"module": "api"}))\n'
            'print("ok" if r.success else "failed", "; ".join(r.warnings or r.errors or []))\n')
    import subprocess
    try:
        out = subprocess.run([python, '-c', code], capture_output=True, text=True, timeout=180)
    except Exception as e:
        log('ruleset reload failed: %s' % e)
        return False
    result = (out.stdout or '').strip().splitlines()
    result = result[-1] if result else (out.stderr or '').strip()[-200:]
    log('ruleset reload: %s' % result)
    return result.startswith('ok')


def changed_lists(wazuh, since):
    """Files under etc/lists modified after `since`, and the newest mtime seen.

    Comparing a list's text with its .cdb is not enough on a worker: the cluster
    copies the master's compiled .cdb along with the text, so the two arrive
    with the same timestamp while analysisd still holds the old list in memory.
    And a list that is not declared in ossec.conf is never compiled at all, so
    a text-newer-than-cdb test would reload every five minutes, forever.
    What matters is whether anything changed since this node last reloaded.
    """
    lists = os.path.join(wazuh, 'etc', 'lists')
    changed, newest = [], 0.0
    for name in sorted(os.listdir(lists)) if os.path.isdir(lists) else []:
        path = os.path.join(lists, name)
        # Only the text. A reload recompiles every .cdb and so moves its mtime;
        # counting those would make each reload trigger the next.
        if name.endswith(('.tmp', '.cdb')) or not os.path.isfile(path):
            continue
        mtime = os.path.getmtime(path)
        newest = max(newest, mtime)
        if mtime > since + 0.001:
            changed.append(name)
    return changed, newest


def fetch(url, dest, timeout=60):
    """Download to a temporary file and rename, so a failure never truncates."""
    tmp = dest + '.tmp'
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        body = resp.read()
    body.decode('utf-8')  # a feed that is not text is a feed that changed shape
    with open(tmp, 'wb') as fh:
        fh.write(body)
    os.replace(tmp, dest)
    return len(body)


def parse_feed(path):
    """Pull IPv4 addresses and CIDRs out of a feed, whatever else is on the line."""
    found = set()
    with open(path, encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            line = line.split('#', 1)[0].split(';', 1)[0].strip()
            if not line:
                continue
            token = line.split(',')[0].split('\t')[0].split()[0] if line.split() else ''
            if not token or not IPV4_RE.match(token):
                continue
            try:
                found.add(ipaddress.ip_network(token, strict=False))
            except ValueError:
                continue
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--wazuh-path', default='/var/ossec')
    ap.add_argument('--dry-run', action='store_true',
                    help='build the list but do not replace the installed one')
    ap.add_argument('--force', action='store_true',
                    help='ignore the per-feed interval and download everything')
    ap.add_argument('--reload-if-stale', action='store_true',
                    help='download nothing; reload this node if any file under etc/lists '
                         'changed since the last reload this mode made. For cluster workers, '
                         'which receive the lists from the master but are not reloaded by it')
    ap.add_argument('--no-reload', action='store_true',
                    help='write the list but leave the reload to someone else')
    args = ap.parse_args()

    wazuh = os.path.abspath(args.wazuh_path)
    if args.reload_if_stale:
        marker = os.path.join(wazuh, 'etc', 'jt-packs', 'ioc-cache', 'last-list-reload')
        try:
            with open(marker, encoding='utf-8') as fh:
                since = float(fh.read().strip() or 0)
        except (OSError, ValueError):
            since = 0.0          # first run: reload once to start from a known state
        changed, newest = changed_lists(wazuh, since)
        if not changed:
            return 0
        log('lists changed since the last reload: %s' % ', '.join(changed[:6])
            + (' (+%d more)' % (len(changed) - 6) if len(changed) > 6 else ''))
        if not reload_ruleset(wazuh):
            return 1
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        with open(marker, 'w', encoding='utf-8') as fh:
            fh.write(repr(newest) + '\n')
        return 0

    listfile = os.path.join(wazuh, 'etc', 'lists', LIST_NAME)
    workdir = os.path.join(wazuh, 'etc', 'jt-packs', 'ioc-cache')
    statefile = os.path.join(workdir, 'feed-state.json')
    exclusions_file = os.path.join(workdir, 'exclusions.txt')

    if not os.path.isdir(os.path.dirname(listfile)):
        log('ERROR: %s does not exist -- is --wazuh-path right?' % os.path.dirname(listfile))
        return 2
    os.makedirs(workdir, exist_ok=True)

    state = {}
    if os.path.isfile(statefile):
        try:
            with open(statefile, encoding='utf-8') as fh:
                state = json.load(fh)
        except Exception:
            log('feed state unreadable, treating every feed as due')

    now = int(time.time())
    downloaded = skipped = failed = 0
    for name, spec in sorted(FEEDS.items()):
        cache = os.path.join(workdir, name + '.txt')
        age = now - int(state.get(name, 0))
        if not args.force and os.path.isfile(cache) and age < spec['interval']:
            skipped += 1
            continue
        try:
            size = fetch(spec['url'], cache)
            state[name] = now
            downloaded += 1
            log('fetched %-24s %8d bytes' % (name, size))
        except Exception as e:
            failed += 1
            have = 'previous copy kept' if os.path.isfile(cache) else 'NO local copy'
            log('FAILED  %-24s %s (%s)' % (name, str(e)[:60], have))

    with open(statefile, 'w', encoding='utf-8') as fh:
        json.dump(state, fh)
    log('feeds: %d downloaded, %d still fresh, %d failed' % (downloaded, skipped, failed))

    exclusions = load_exclusions(exclusions_file)
    # The value records which feeds listed the address. A constant would fit the
    # CDB just as well, but knowing an address came from six independent feeds
    # rather than one changes how an analyst reads the alert.
    nets, per_feed, sources = set(), {}, {}
    for name in sorted(FEEDS):
        cache = os.path.join(workdir, name + '.txt')
        if not os.path.isfile(cache):
            continue
        got = parse_feed(cache)
        per_feed[name] = len(got)
        nets |= got
        for n in got:
            sources.setdefault(n, []).append(name)

    kept = {n for n in nets if not excluded(n, exclusions)}
    dropped = len(nets) - len(kept)
    log('parsed %d unique entries from %d feeds, %d dropped by exclusions'
        % (len(nets), len(per_feed), dropped))

    if not kept:
        log('ERROR: nothing survived parsing; refusing to replace the installed list')
        return 1

    # A collapse in size usually means a feed changed format rather than the
    # internet becoming safe. Refuse rather than silently gutting detection.
    if os.path.isfile(listfile):
        with open(listfile, encoding='utf-8', errors='ignore') as fh:
            previous = sum(1 for line in fh if line.strip())
        if previous and len(kept) < previous * 0.5:
            log('ERROR: new list has %d entries against %d before, a drop of more than '
                'half. Refusing to replace it. Run with --force after checking the feeds.'
                % (len(kept), previous))
            return 1

    # Keys are quoted and values name the contributing feeds, matching the format
    # already proven against a live manager. Wazuh strips the quotes when it
    # compiles the CDB; changing the shape of a list that 31 rules read is not
    # something to do on the assumption that another shape would also work.
    keys, oversized = {}, 0
    for n in kept:
        expanded = cdb_keys(n)
        if expanded is None:
            oversized += 1
            continue
        for key in expanded:
            merged = keys.setdefault(key, [])
            for feed in sources.get(n, ['threat_feed']):
                if feed not in merged:
                    merged.append(feed)
    if oversized:
        log('skipped %d entries that would expand past %d keys each' % (oversized, MAX_EXPANSION))
    log('%d feed entries became %d list keys' % (len(kept), len(keys)))
    body = ''.join('"%s":%s\n' % (k, ','.join(v[:4])) for k, v in sorted(keys.items()))
    if args.dry_run:
        log('dry run: would write %d entries to %s' % (len(kept), listfile))
        return 0

    tmp = listfile + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(body)
    os.replace(tmp, listfile)
    try:
        import grp
        import pwd
        os.chown(listfile, pwd.getpwnam('wazuh').pw_uid, grp.getgrnam('wazuh').gr_gid)
    except Exception:
        pass
    os.chmod(listfile, 0o660)
    log('wrote %d keys to %s' % (len(keys), listfile))
    if args.no_reload:
        log('--no-reload: the manager compiles the CDB on the next ruleset reload')
        return 0
    return 0 if reload_ruleset(wazuh) else 1


if __name__ == '__main__':
    sys.exit(main())
