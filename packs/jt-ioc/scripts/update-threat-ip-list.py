#!/usr/bin/env python3
"""Build the jason_tools_threat_ip CDB lists from public IP threat-intel feeds.

Runs from cron. Everything it touches is an absolute path derived from
--wazuh-path, and nothing depends on the working directory: the job this
replaced used relative paths, cron ran it without a cd, and it failed silently
for ten and a half months while the list sat frozen and thirty rules matched
nothing. Standard library only.

  update-threat-ip-list.py [--wazuh-path /var/ossec] [--dry-run] [--force]
                           [--no-reload] [--reload-if-stale] [--skip-download]

Two lists, because a CDB value cannot carry the confidence: Wazuh's
address_match_key_value lookup is inverted in 4.x (lists_list.c returns a match
when the value does NOT match; wazuh/wazuh#8269, open since 2021, re-measured on
4.14.7 on 2026-10-11).

  jason_tools_threat_ip       every address a feed lists (rules: low confidence)
  jason_tools_threat_ip_high  listed by two independent providers, or by a
                              curated source (Spamhaus DROP; ThreatFox and Feodo
                              when enabled). Tor exits alone never qualify.

Measured on 2026-10-11 against the 1.4 list (280,554 addresses): 91 per cent
came from a single provider, 72 per cent from blocklist.net.ua alone (most of
it bans months old), 5.1 per cent were published research scanners, 5,488 were
Tor relays that are not exits, and the darklist.de feed had not changed since
August 2023 but still contributed /15 and /16 networks.

Site settings: <wazuh>/etc/jt-packs/jt-ioc.conf, "key = value" lines, never
written by the installer (keys in read_conf). Site exclusions:
<wazuh>/etc/jt-packs/ioc-cache/exclusions.txt, one IP or CIDR per line.

A list that silently stops updating looks exactly like one that works, so every
failure also goes to the manager's own event queue, where rules 906090-906093
turn it into an alert.

Exit status is 0 when the lists were rebuilt or nothing was due.
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

LIST_NAME = 'jason_tools_threat_ip'
HIGH_LIST = 'jason_tools_threat_ip_high'
CONF_NAME = 'jt-ioc.conf'
PLACEHOLDER = 'PLACEHOLDER-FILLED-BY-THE-UPDATER'
UA = 'jt-wazuh-mgr/ioc-updater (+https://github.com/jasoncheng7115/jt-wazuh-mgr)'

# kind: "vote"    an abuse or attack feed; two different providers make an entry high
#       "curated" one listing is enough for high (criminal networks, confirmed C2)
#       "anon"    an anonymiser (Tor exits): listed, never high on its own
# default: whether it runs without a setting in jt-ioc.conf ("<id> = yes|no").
# Terms checked 2026-10-11; the pack ships no feed data, each site downloads.
FEEDS = {
    'blocklist_de': {
        'kind': 'vote', 'default': True, 'interval': 4 * 3600, 'parser': 'plain',
        # Attackers reported to blocklist.de in the last 48 hours, regenerated
        # every 30 minutes; all.txt already holds the per-service lists.
        'urls': ['https://lists.blocklist.de/lists/all.txt']},
    'cins': {
        'kind': 'vote', 'default': True, 'interval': 12 * 3600, 'parser': 'plain',
        # CINS Army (Sentinel IPS sensors), capped at 15,000.
        'urls': ['https://cinsscore.com/list/ci-badguys.txt']},
    'net_ua': {
        'kind': 'vote', 'default': True, 'interval': 12 * 3600, 'parser': 'net_ua',
        # The source CSV (IP;BAN_DATE;UNBAN_DATE;REASON) rather than FireHOL's
        # mirror, which drops the date: of 224k bans only 80k were less than
        # 30 days old on 2026-10-11 (net_ua_max_days).
        'urls': ['https://blocklist.net.ua/blocklist.csv']},
    'et_compromised': {
        'kind': 'vote', 'default': True, 'interval': 24 * 3600, 'parser': 'plain',
        # Proofpoint ET Open: compromised hosts seen attacking. A vote, not
        # curated: compromised hosts are often shared web hosting.
        'urls': ['https://rules.emergingthreats.net/blockrules/compromised-ips.txt']},
    'spamhaus_drop': {
        'kind': 'curated', 'default': True, 'interval': 24 * 3600, 'parser': 'spamhaus',
        # Networks hijacked or run by criminals; EDROP was merged into DROP on
        # 2024-04-10. Free of charge under https://www.spamhaus.org/drop/terms/.
        'urls': ['https://www.spamhaus.org/drop/drop_v4.json']},
    'tor_exit': {
        'kind': 'anon', 'default': True, 'interval': 4 * 3600, 'parser': 'plain',
        # Exits only. Until 1.5 the list held every relay (6,673 against 1,185
        # exits); a relay that is not an exit never originates your traffic.
        'urls': ['https://torstatus.rueckgr.at/ip_list_exit.php/Tor_ip_list_EXIT.csv',
                 'https://check.torproject.org/torbulkexitlist']},
    'threatfox': {
        'kind': 'curated', 'default': False, 'interval': 6 * 3600, 'parser': 'threatfox',
        'abuse_ch': True, 'may_be_empty': True,
        # abuse.ch: free for non-commercial use, a paid subscription for
        # organisations with profit motives (https://abuse.ch/terms-of-use/).
        'urls': ['https://threatfox.abuse.ch/export/csv/ip-port/recent/']},
    'feodo': {
        'kind': 'curated', 'default': False, 'interval': 6 * 3600, 'parser': 'plain',
        'abuse_ch': True, 'may_be_empty': True,
        # One entry on 2026-10-11 (most of the botnets it tracked were taken down).
        'urls': ['https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt']},
    'dshield': {
        'kind': 'vote', 'default': False, 'interval': 24 * 3600, 'parser': 'dshield',
        # Top 20 scanning /24 networks of the last three days; CC BY-NC-SA 2.5.
        'urls': ['https://feeds.dshield.org/block.txt']},
    'matthewroberts': {
        'kind': 'vote', 'default': False, 'interval': 24 * 3600, 'parser': 'plain',
        # Describes itself as an aggressive aggregate of other blocklists (34 %
        # of it was CINS on 2026-10-11), so it is not an independent vote.
        'urls': ['https://www.matthewroberts.io/api/threatlist/latest']},
}

# Published source ranges of research scanners (MISP warninglists, CC0). They
# scan everything and log in nowhere: 39 per cent of CINS, two thirds of the
# addresses one site's firewall blocked most often. These 29 lists covered 98
# per cent of the overlap with the 1.4 list.
SCANNER_URL = 'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/%s/list.json'
SCANNER_LISTS = (
    'hunter-scanning', 'palo-alto-networks-cortex-xpanse', 'infrawatch-scanning', 'shadowserver',
    'shadowserver-nt-scanning', 'binaryedge-scanning', 'censys-scanning', 'onyphe-nt-scanning',
    'onyphe-scanner', 'stretchoid-scanning', 'stretchoid-nt-scanning', 'bitsight-scanning',
    'alphastrike-scanning', 'alphastrike-research-nt-scanning', 'quake-scanning',
    'deepfield-scanning', 'rapid7-scanning', 'modat-nt-scanning', 'modat-scanner',
    'internetmeasurementresearch-scanning', 'leakix-scanning', 'fofa-scanning', 'netscout-scanning',
    'internettl-scanning', 'shodan-scanning', 'shodan-nt-scanning', 'mandiantasm-scanning',
    'criminalip-scanning', 'rootevidence-scanning',
)
SCANNER_INTERVAL = 24 * 3600

# Cache files of feeds that 1.4 used and 1.5 dropped; removed so nothing parses
# them again (darklist.de stopped in 2023, the Tor file held every relay).
OBSOLETE_CACHE = (
    'blocklistde_all.txt', 'firehol_net_ua.txt', 'firehol_de_apache.txt', 'firehol_de_bots.txt',
    'firehol_de_bruteforce.txt', 'firehol_de_mail.txt', 'firehol_de_imap.txt', 'firehol_de_ssh.txt',
    'firehol_ciarmy.txt', 'cins_army.txt', 'darklist_de.txt', 'tor_exit_nodes.txt',
)

# Never listed, whatever a feed says.
ALWAYS_EXCLUDE = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4',
    '240.0.0.0/4', '255.255.255.255/32',
    '1.1.1.1/32', '1.0.0.1/32', '8.8.8.8/32', '8.8.4.4/32', '9.9.9.9/32', '149.112.112.112/32',
    '208.67.222.222/32', '208.67.220.220/32',
] + [
    # Cloudflare's published edge ranges: an edge address in a proxy field
    # flagged every visitor behind it.
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
]

MAX_EXPANSION = 65536       # keys one feed entry may become
MIN_PREFIX = 8              # nothing in a threat feed is larger than a /8 (DROP's largest: /12)
MIN_FEED_RATIO = 0.5        # a feed that shrinks below half its last good size is broken
SHRINK_ACCEPT_AFTER = 3     # ...unless it does so this many downloads in a row
MAX_GROWTH = 3.0            # a list that triples is more likely a broken feed
GROWTH_FLOOR = 1000         # ...once it has some size: a handful of keys may grow freely
STALE_HOURS_DEFAULT = 48
STALE_REPORT_EVERY = 6 * 3600
RETRY_DELAYS = (30, 120)

IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')

_QUEUE = None
_SECRET = None


def log(msg):
    if _SECRET:
        msg = msg.replace(_SECRET, '***')
    sys.stdout.write('%s %s\n' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg))
    sys.stdout.flush()


def report_failure(kind, message):
    """Log a failure and send it to the manager's event queue.

    kind is "failed", "stale", "feed" or "refused"; rules 906090-906093 tell
    them apart by that word. Only a local root process can write that socket.
    """
    text = 'ERROR %s: %s' % (kind, message)
    log(text)
    if not _QUEUE:
        return
    if _SECRET:
        text = text.replace(_SECRET, '***')
    payload = '1:jt-ioc:jt-ioc: %s' % re.sub(r'\s+', ' ', text)[:500]
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(_QUEUE)
        sock.send(payload.encode('utf-8', 'replace'))
        sock.close()
    except (OSError, socket.error):
        pass        # the log line above still reaches the cron log


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

def read_conf(wazuh):
    """etc/jt-packs/jt-ioc.conf, one "key = value" per line. Keys:

      <feed id> = yes|no   switch a feed on or off (ids: see FEEDS; off by
                           default: threatfox, feodo, dshield, matthewroberts)
      <feed id>_url        replace a feed's download URL
      auth_key             abuse.ch Auth-Key (https://auth.abuse.ch/), sent as an
                           "Auth-Key" header to threatfox and feodo only
      threatfox_min_confidence   default 75
      net_ua_max_days      bans older than this are ignored (default 30; 0 = all)
      high_min_votes       independent providers that make an entry high (default 2)
      research_scanners    no: keep published research scanners in the lists
      mapped_v6_keys       no: do not add ::ffff:a.b.c.d keys
      stale_hours          report a list older than this (default 48)
    """
    settings = {}
    path = os.path.join(wazuh, 'etc', 'jt-packs', CONF_NAME)
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                settings[key.strip().lower()] = value.strip()
        if settings.get('auth_key') and os.stat(path).st_mode & 0o077:
            log('warning: %s holds an Auth-Key and is readable by others; chmod 600 it' % path)
    except OSError:
        pass
    return settings


def _yes(value):
    return str(value or '').strip().lower() in ('1', 'yes', 'true', 'on')


def _no(value):
    return str(value or '').strip().lower() in ('0', 'no', 'false', 'off')


def _int(value, default):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def enabled_feeds(settings):
    out = []
    for name, spec in sorted(FEEDS.items()):
        value = settings.get(name)
        on = spec['default'] if value is None else _yes(value)
        if on:
            out.append(name)
    return out


# --------------------------------------------------------------------------
# Parsing (pure functions: paths in, sets of networks out)
# --------------------------------------------------------------------------

def _net(token):
    token = token.strip().strip('"')
    if not IPV4_RE.match(token):
        return None
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def parse_plain(path):
    """IPv4 addresses and CIDRs, one per line, whatever follows on the line."""
    found = set()
    with open(path, encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            line = line.split('#', 1)[0].split(';', 1)[0].strip()
            if not line:
                continue
            token = re.split(r'[\s,]', line, 1)[0]
            net = _net(token)
            if net:
                found.add(net)
    return found


def parse_net_ua(path, max_days=30, now=None):
    """blocklist.net.ua's CSV: IP;BAN_DATE;UNBAN_DATE;REASON, dates as epoch seconds."""
    now = now or time.time()
    found = set()
    with open(path, encoding='utf-8', errors='replace', newline='') as fh:
        for row in csv.reader(fh, delimiter=';'):
            if len(row) < 2:
                continue
            net = _net(row[0])
            if not net:
                continue
            if max_days:
                try:
                    if now - int(row[1]) > max_days * 86400:
                        continue
                except ValueError:
                    continue
            found.add(net)
    return found


def parse_spamhaus(path):
    """drop_v4.json: one JSON object per line, {"cidr": ..., "sblid": ...}."""
    found = set()
    with open(path, encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith('{'):
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            net = _net(str(rec.get('cidr', '')))
            if net:
                found.add(net)
    return found


def parse_threatfox(path, min_confidence=75):
    """ThreatFox ip:port CSV export; keeps indicators at or above min_confidence."""
    found = set()
    cols = None
    with open(path, encoding='utf-8', errors='ignore', newline='') as fh:
        for line in fh:
            if line.startswith('#'):
                head = line.lstrip('#').strip()
                if 'ioc_value' in head:
                    cols = [c.strip().strip('"') for c in head.split(',')]
                continue
            if not line.strip():
                continue
            row = [c.strip().strip('"') for c in next(csv.reader([line], skipinitialspace=True))]
            if not cols or len(row) < len(cols):
                continue
            rec = dict(zip(cols, row))
            try:
                if int(rec.get('confidence_level') or 0) < min_confidence:
                    continue
            except ValueError:
                continue
            net = _net(rec.get('ioc_value', '').rsplit(':', 1)[0])
            if net:
                found.add(net)
    return found


def parse_dshield(path):
    """DShield block.txt: start, end, prefix length, tab separated."""
    found = set()
    with open(path, encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            if line.startswith('#') or not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) >= 3 and _net(parts[0]) and parts[2].strip().isdigit():
                net = _net('%s/%s' % (parts[0].strip(), parts[2].strip()))
                if net:
                    found.add(net)
    return found


def parse_feed(name, path, settings):
    parser = FEEDS[name]['parser']
    if parser == 'net_ua':
        return parse_net_ua(path, _int(settings.get('net_ua_max_days'), 30))
    if parser == 'spamhaus':
        return parse_spamhaus(path)
    if parser == 'threatfox':
        return parse_threatfox(path, _int(settings.get('threatfox_min_confidence'), 75))
    if parser == 'dshield':
        return parse_dshield(path)
    return parse_plain(path)


def parse_scanner_list(path):
    """A MISP warninglist (JSON with a "list" of CIDRs); IPv4 entries only."""
    with open(path, encoding='utf-8', errors='ignore') as fh:
        data = json.load(fh)
    found = set()
    for entry in data.get('list') or []:
        try:
            net = ipaddress.ip_network(str(entry).strip(), strict=False)
        except ValueError:
            continue
        if net.version == 4:
            found.add(net)
    return found


# --------------------------------------------------------------------------
# Building the lists
# --------------------------------------------------------------------------

class NetIndex(object):
    """Membership of an address or network in a set of IPv4 networks."""

    def __init__(self, nets):
        self.by_len = {}
        for n in nets:
            self.by_len.setdefault(n.prefixlen, set()).add(int(n.network_address))
        self.lens = sorted(self.by_len)

    def covers(self, net):
        """True if some network of the index contains `net` entirely."""
        x = int(net.network_address)
        for p in self.lens:
            if p > net.prefixlen:
                break
            if ((x >> (32 - p)) << (32 - p) if p else 0) in self.by_len[p]:
                return True
        return False

    def overlaps(self, net):
        """True if `net` contains or is contained in some network of the index."""
        if self.covers(net):
            return True
        lo, hi = int(net.network_address), int(net.broadcast_address)
        for p in self.lens:
            if p <= net.prefixlen:
                continue
            if any(lo <= a <= hi for a in self.by_len[p]):
                return True
        return False


def cdb_keys(net):
    """The keys address_match_key can find for this network.

    address_match_key looks the address up whole, then cut back to each octet
    boundary: 203.0.113.7, 203.0.113., 203.0., 203. -- and nothing else. A key
    written as a CIDR is never found. Networks on an octet boundary become one
    prefix key; others are expanded to the next boundary down; /25 to /31
    become their addresses. None when an entry would expand past MAX_EXPANSION
    or is larger than a /8.
    """
    if net.version != 4:
        return []
    plen = net.prefixlen
    if plen < MIN_PREFIX:
        return None
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


def build_lists(feed_nets, settings, exclusions=(), scanners=()):
    """feed_nets: {feed id: set of networks}. Returns (main, high, stats).

    main and high map a CDB key to the sorted providers that listed it. An
    entry is high when a curated feed lists it, or at least high_min_votes
    "vote" feeds do; Tor exits are listed but never high on their own.
    Exclusions and published research scanners are removed from both; a
    listed network that merely overlaps an exclusion is dropped whole, because
    its prefix key would match the excluded addresses too.
    """
    min_votes = max(1, _int(settings.get('high_min_votes'), 2))
    excl = NetIndex(exclusions)
    scan = NetIndex(scanners)
    providers = {}
    for name, nets in feed_nets.items():
        for n in nets:
            providers.setdefault(n, set()).add(name)
    stats = {'entries': len(providers), 'excluded': 0, 'scanners': 0, 'oversized': 0}
    main, high = {}, {}
    for net, names in providers.items():
        if excl.overlaps(net):
            stats['excluded'] += 1
            continue
        if scanners and scan.covers(net):
            stats['scanners'] += 1
            continue
        keys = cdb_keys(net)
        if keys is None:
            stats['oversized'] += 1
            continue
        kinds = [FEEDS[n]['kind'] for n in names]
        is_high = 'curated' in kinds or kinds.count('vote') >= min_votes
        for key in keys:
            main.setdefault(key, set()).update(names)
            if is_high:
                high.setdefault(key, set()).update(names)
    # an address listed once by itself and once inside a network: merge the votes
    for key, names in main.items():
        if key in high:
            continue
        kinds = [FEEDS[n]['kind'] for n in names]
        if 'curated' in kinds or kinds.count('vote') >= min_votes:
            high[key] = set(names)
    if not _no(settings.get('mapped_v6_keys')):
        # srcip from Java applications and Proxmox's pvedaemon reads
        # "::ffff:203.0.113.7"; the lookup walks prefixes ending in "." so the
        # mapped form of every key works with the same rules.
        for table in (main, high):
            for key in list(table):
                table['::ffff:' + key] = table[key]
    stats['main'] = len(main)
    stats['high'] = len(high)
    return main, high, stats


def render(keys):
    if not keys:
        return '%s:placeholder\n' % PLACEHOLDER
    return ''.join('"%s":%s\n' % (k, ','.join(sorted(v))) for k, v in sorted(keys.items()))


def count_keys(path):
    """Keys in an installed list; 0 for a missing list or the shipped placeholder."""
    n = 0
    try:
        with open(path, encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                if line.strip() and not line.startswith(PLACEHOLDER) and not line.startswith('#'):
                    n += 1
    except OSError:
        pass
    return n


def write_list(path, body, workdir):
    """Atomic: written in the cache directory and moved in.

    Not etc/lists/<name>.tmp: that is the file analysisd itself writes while
    compiling the list (lists_make.c), so a reload during the write collided.
    """
    tmp = os.path.join(workdir, os.path.basename(path) + '.new')
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(body)
    try:
        os.replace(tmp, path)
    except OSError:
        # cache directory on another file system: stage next to the list under a
        # name the cluster skips (.tmp) and the compiler never uses
        alt = path + '.jt-new.tmp'
        with open(alt, 'w', encoding='utf-8') as fh:
            fh.write(body)
        os.replace(alt, path)
        os.remove(tmp)
    try:
        import grp
        import pwd
        os.chown(path, pwd.getpwnam('wazuh').pw_uid, grp.getgrnam('wazuh').gr_gid)
    except Exception:
        pass
    os.chmod(path, 0o660)


# --------------------------------------------------------------------------
# Downloads
# --------------------------------------------------------------------------

class Refused(Exception):
    """The source answered and said no (401/403): retrying will not help."""


def _download(url, dest, headers, timeout):
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    tmp = dest + '.part'
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp, open(tmp, 'wb') as fh:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                fh.write(chunk)
    except urllib.error.HTTPError as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        if e.code in (401, 403):
            raise Refused('HTTP %d' % e.code)
        raise
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    with open(tmp, 'rb') as fh:
        head = fh.read(512).lower()
    if b'<html' in head or b'<!doctype' in head:
        os.remove(tmp)
        raise ValueError('an HTML page instead of a list')
    os.replace(tmp, dest)
    return os.path.getsize(dest)


def fetch(urls, dest, headers, timeout=120, delays=RETRY_DELAYS):
    """Try each URL (mirrors) with retries; the old copy stays until one succeeds."""
    last = None
    for url in urls:
        for attempt in range(len(delays) + 1):
            try:
                return _download(url, dest, headers, timeout)
            except Refused:
                raise
            except Exception as e:
                last = e
                if attempt < len(delays):
                    time.sleep(delays[attempt])
    raise last or ValueError('no URL')


# --------------------------------------------------------------------------
# State and modes
# --------------------------------------------------------------------------

def load_state(path):
    try:
        with open(path, encoding='utf-8') as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return {'feeds': {}}
    if 'feeds' not in state:
        # 1.4 kept {feed: last download time}; those feeds are gone or renamed.
        # 1.5 lists are smaller by design, so the first run skips the shrink guard.
        state = {'feeds': {}, 'upgraded_from': '1.4'}
    return state


def save_state(path, state):
    with open(path + '.new', 'w', encoding='utf-8') as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(path + '.new', path)


def check_stale(listfile, settings, now=None):
    """Report a list nothing has refreshed for stale_hours. True if stale."""
    now = now or time.time()
    limit = _int(settings.get('stale_hours'), STALE_HOURS_DEFAULT) * 3600
    placeholder = count_keys(listfile) == 0
    try:
        changed = os.path.getmtime(listfile)
    except OSError:
        changed = 0
    if not placeholder and changed and now - changed <= limit:
        return False
    what = ('still holds the placeholder the pack ships' if placeholder
            else 'has not been refreshed for %.0f h' % ((now - changed) / 3600))
    report_failure('stale', '%s %s (limit %d h); new threat addresses are not being matched'
                   % (os.path.basename(listfile), what, limit // 3600))
    return True


def changed_lists(wazuh, since):
    """Files under etc/lists modified after `since`, and the newest mtime seen.

    On a worker the cluster copies the master's compiled .cdb along with the
    text, so the two arrive together while analysisd still holds the old list;
    what matters is whether anything changed since this node last reloaded.
    """
    lists = os.path.join(wazuh, 'etc', 'lists')
    changed, newest = [], 0.0
    for name in sorted(os.listdir(lists)) if os.path.isdir(lists) else []:
        path = os.path.join(lists, name)
        # Only the text: a reload recompiles every .cdb and so moves its mtime.
        if name.endswith(('.tmp', '.cdb')) or not os.path.isfile(path):
            continue
        mtime = os.path.getmtime(path)
        newest = max(newest, mtime)
        if mtime > since + 0.001:
            changed.append(name)
    return changed, newest


def reload_ruleset(wazuh):
    """Ask this node's analysisd to reload, which recompiles every CDB list."""
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
        out = subprocess.run([python, '-c', code], capture_output=True, text=True, timeout=300)
    except Exception as e:
        log('ruleset reload failed: %s' % e)
        return False
    result = (out.stdout or '').strip().splitlines()
    result = result[-1] if result else (out.stderr or '').strip()[-200:]
    log('ruleset reload: %s' % result)
    return result.startswith('ok')


def reload_if_stale(wazuh, settings):
    """For cluster workers: reload when a list has arrived; report a stale one."""
    workdir = os.path.join(wazuh, 'etc', 'jt-packs', 'ioc-cache')
    marker = os.path.join(workdir, 'last-list-reload')
    try:
        with open(marker, encoding='utf-8') as fh:
            since = float(fh.read().strip() or 0)
    except (OSError, ValueError):
        since = 0.0          # first run: reload once to start from a known state
    rc = 0
    changed, newest = changed_lists(wazuh, since)
    if changed:
        log('lists changed since the last reload: %s' % ', '.join(changed[:6])
            + (' (+%d more)' % (len(changed) - 6) if len(changed) > 6 else ''))
        if reload_ruleset(wazuh):
            os.makedirs(workdir, exist_ok=True)
            with open(marker, 'w', encoding='utf-8') as fh:
                fh.write(repr(newest) + '\n')
        else:
            rc = 1
    stamp = os.path.join(workdir, 'last-stale-report')
    try:
        last = os.path.getmtime(stamp)
    except OSError:
        last = 0
    listfile = os.path.join(wazuh, 'etc', 'lists', LIST_NAME)
    if os.path.isfile(listfile) and time.time() - last >= STALE_REPORT_EVERY:
        if check_stale(listfile, settings):
            os.makedirs(workdir, exist_ok=True)
            with open(stamp, 'w') as fh:
                fh.write('%d\n' % time.time())
    return rc


def update_feeds(workdir, names, settings, state, force=False, skip_download=False, now=None):
    """Download what is due. Returns {feed: set of networks} and the failures.

    A feed whose download fails, or whose new copy parses to less than half
    its last good size, keeps its previous copy: one broken source must not
    quietly take its addresses out of the list.
    """
    now = now or int(time.time())
    nets, failures = {}, []
    headers = {'User-Agent': UA}
    for name in names:
        spec = FEEDS[name]
        cache = os.path.join(workdir, name + '.txt')
        rec = state['feeds'].setdefault(name, {})
        urls = [settings[name + '_url']] if settings.get(name + '_url') else spec['urls']
        due = force or not os.path.isfile(cache) or now - int(rec.get('fetched', 0)) >= spec['interval']
        if due and not skip_download:
            h = dict(headers)
            if spec.get('abuse_ch') and settings.get('auth_key'):
                h['Auth-Key'] = settings['auth_key']
            new = cache + '.new'
            try:
                size = fetch(urls, new, h)
                got = parse_feed(name, new, settings)
                good = int(rec.get('count') or 0)
                if not got and not (spec.get('may_be_empty') and size > 0):
                    raise ValueError('the download holds no IPv4 entries (format changed?)')
                if good and len(got) < good * MIN_FEED_RATIO:
                    rec['shrunk'] = int(rec.get('shrunk') or 0) + 1
                    if rec['shrunk'] < SHRINK_ACCEPT_AFTER:
                        raise ValueError('%d entries against %d last time' % (len(got), good))
                    log('%s: accepted a smaller list after %d downloads in a row' % (name, rec['shrunk']))
                os.replace(new, cache)
                rec.update({'fetched': now, 'count': len(got), 'fails': 0, 'shrunk': 0})
                log('fetched %-16s %9d bytes, %7d entries' % (name, size, len(got)))
            except Refused as e:
                failures.append(('refused', name, str(e)))
                rec['fails'] = int(rec.get('fails') or 0) + 1
            except Exception as e:
                failures.append(('feed', name, str(e)[:120]))
                rec['fails'] = int(rec.get('fails') or 0) + 1
            finally:
                if os.path.exists(new):
                    os.remove(new)
        if os.path.isfile(cache):
            try:
                nets[name] = parse_feed(name, cache, settings)
            except Exception as e:
                failures.append(('feed', name, 'cached copy unreadable: %s' % str(e)[:80]))
    return nets, failures


def update_scanners(workdir, state, force=False, skip_download=False, now=None):
    now = now or int(time.time())
    sdir = os.path.join(workdir, 'scanners')
    os.makedirs(sdir, exist_ok=True)
    rec = state.setdefault('scanners', {})
    due = force or now - int(rec.get('fetched', 0)) >= SCANNER_INTERVAL
    ok = failed = 0
    if due and not skip_download:
        for name in SCANNER_LISTS:
            dest = os.path.join(sdir, name + '.json')
            try:
                fetch([SCANNER_URL % name], dest, {'User-Agent': UA}, timeout=60, delays=(10,))
                parse_scanner_list(dest)
                ok += 1
            except Exception as e:
                failed += 1
                log('scanner list %s: %s (previous copy kept)' % (name, str(e)[:80]))
        rec.update({'fetched': now, 'ok': ok, 'failed': failed})
    nets = set()
    for name in SCANNER_LISTS:
        path = os.path.join(sdir, name + '.json')
        if os.path.isfile(path):
            try:
                nets |= parse_scanner_list(path)
            except Exception:
                pass
    return nets, (due and not skip_download and ok == 0)


def load_exclusions(path):
    nets = [ipaddress.ip_network(e, strict=False) for e in ALWAYS_EXCLUDE]
    count = 0
    if os.path.isfile(path):
        with open(path, encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip()
                if not line:
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    log('  exclusion file: ignoring unparseable entry %r' % line[:40])
                    continue
                if net.version == 4:
                    nets.append(net)
                    count += 1
    log('exclusions: %d built in, %d from %s' % (len(ALWAYS_EXCLUDE), count, path))
    return nets


def main():
    global _QUEUE, _SECRET
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--wazuh-path', default='/var/ossec')
    ap.add_argument('--dry-run', action='store_true',
                    help='build the lists but do not replace the installed ones')
    ap.add_argument('--force', action='store_true',
                    help='download every feed now and skip the size guards')
    ap.add_argument('--reload-if-stale', action='store_true',
                    help='download nothing; reload this node if any file under etc/lists '
                         'changed since the last reload this mode made, and report a list '
                         'the master stopped refreshing. For cluster workers')
    ap.add_argument('--no-reload', action='store_true',
                    help='write the lists but leave the reload to someone else')
    ap.add_argument('--skip-download', action='store_true',
                    help='rebuild from the cached downloads only')
    args = ap.parse_args()

    wazuh = os.path.abspath(args.wazuh_path)
    settings = read_conf(wazuh)
    _SECRET = settings.get('auth_key') or None
    queue = os.path.join(wazuh, 'queue', 'sockets', 'queue')
    _QUEUE = queue if not args.dry_run and os.path.exists(queue) else None

    if args.reload_if_stale:
        return reload_if_stale(wazuh, settings)

    listfile = os.path.join(wazuh, 'etc', 'lists', LIST_NAME)
    highfile = os.path.join(wazuh, 'etc', 'lists', HIGH_LIST)
    workdir = os.path.join(wazuh, 'etc', 'jt-packs', 'ioc-cache')
    statefile = os.path.join(workdir, 'feed-state.json')
    if not os.path.isdir(os.path.dirname(listfile)):
        log('ERROR: %s does not exist -- is --wazuh-path right?' % os.path.dirname(listfile))
        return 2
    os.makedirs(workdir, exist_ok=True)
    for old in OBSOLETE_CACHE:
        try:
            os.remove(os.path.join(workdir, old))
        except OSError:
            pass

    state = load_state(statefile)
    names = enabled_feeds(settings)
    if any(FEEDS[n].get('abuse_ch') for n in names) and not settings.get('auth_key'):
        log('note: abuse.ch documents an Auth-Key as required (auth_key in %s)' % CONF_NAME)
    nets, failures = update_feeds(workdir, names, settings, state, args.force, args.skip_download)
    scanners = set()
    if not _no(settings.get('research_scanners')):
        scanners, scan_failed = update_scanners(workdir, state, args.force, args.skip_download)
        if scan_failed:
            failures.append(('feed', 'research scanner ranges',
                             'no MISP warninglist could be downloaded; previous copies kept'))
    save_state(statefile, state)
    for kind, name, why in failures:
        if kind == 'refused':
            report_failure('refused', 'abuse.ch refused the %s download (%s). Set auth_key in '
                           'etc/jt-packs/%s; the previous copy is used' % (name, why, CONF_NAME))
        else:
            report_failure('feed', '%s: %s; its previous copy is used' % (name, why))

    if not nets:
        report_failure('failed', 'no feed has a usable copy; the installed lists are unchanged')
        check_stale(listfile, settings)
        return 1
    exclusions = load_exclusions(os.path.join(workdir, 'exclusions.txt'))
    main_keys, high_keys, stats = build_lists(nets, settings, exclusions, scanners)
    log('%d entries from %d feeds (%s); %d excluded, %d research scanners, %d oversized; '
        '%d keys, %d high-confidence keys'
        % (stats['entries'], len(nets), ', '.join('%s %d' % (n, len(v)) for n, v in sorted(nets.items())),
           stats['excluded'], stats['scanners'], stats['oversized'], stats['main'], stats['high']))

    if not main_keys:
        report_failure('failed', 'the new list would be empty; the installed lists are unchanged')
        check_stale(listfile, settings)
        return 1
    previous = count_keys(listfile)
    if state.get('upgraded_from'):
        log('first run after upgrading from %s: the size guard is skipped once' % state['upgraded_from'])
    elif previous and not args.force:
        if len(main_keys) < previous * 0.5:
            report_failure('failed', 'the new list has %d keys against %d before, a drop of more than '
                           'half; refusing to replace it (check the feeds, then run with --force)'
                           % (len(main_keys), previous))
            check_stale(listfile, settings)
            return 1
        if previous >= GROWTH_FLOOR and len(main_keys) > previous * MAX_GROWTH:
            report_failure('failed', 'the new list has %d keys against %d before, more than %.0f '
                           'times; refusing to replace it (check the feeds, then run with --force)'
                           % (len(main_keys), previous, MAX_GROWTH))
            check_stale(listfile, settings)
            return 1
    if args.dry_run:
        log('dry run: would write %d keys to %s and %d to %s'
            % (len(main_keys), listfile, len(high_keys), highfile))
        return 0

    write_list(highfile, render(high_keys), workdir)
    write_list(listfile, render(main_keys), workdir)
    state['last_success'] = int(time.time())
    state.pop('upgraded_from', None)
    save_state(statefile, state)
    log('wrote %d keys to %s, %d to %s' % (len(main_keys), listfile, len(high_keys), highfile))
    if args.no_reload:
        log('--no-reload: the manager compiles the lists on the next ruleset reload')
        return 0
    if reload_ruleset(wazuh):
        return 0
    report_failure('failed', 'the lists were written but the ruleset reload failed; the compiled '
                   'lists in use are the previous ones until the next reload')
    return 1


if __name__ == '__main__':
    sys.exit(main())
