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
]

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
    args = ap.parse_args()

    wazuh = os.path.abspath(args.wazuh_path)
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
    body = ''.join('"%s":%s\n' % (str(n).replace('/32', ''), ','.join(sources.get(n, ['threat_feed'])[:4]))
                   for n in sorted(kept, key=str))
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
    log('wrote %d entries to %s' % (len(kept), listfile))
    log('the manager compiles the CDB on the next ruleset reload')
    return 0


if __name__ == '__main__':
    sys.exit(main())
