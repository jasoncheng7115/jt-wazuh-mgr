#!/usr/bin/env python3
"""jt-waf-block: a fail2ban action that blocks an address at the reverse proxy, through jt-waf-mgr.

Copyright Jason Tools Co., Ltd. / AGPL-3.0-or-later. Part of the jt-fail2ban rule pack (jt-wazuh-mgr).

A service behind a reverse proxy (webmail behind nginx, for example) never sees the attacker's
packets, so fail2ban's local firewall actions cannot stop them. This asks jt-waf-mgr's temporary
IP block API (jt-waf-mgr 0.4.24 or later, POST/DELETE /api/v1/blocks) to put the address on the
proxy's nginx deny list instead. The service and the proxy talk directly; Wazuh only watches.

  jt-waf-block ban   <ip> --source <host/jail> [--ttl SECONDS] [--reason TEXT]
  jt-waf-block unban <ip> --source <host/jail>
  jt-waf-block check                      # settings, token file and API reachable (no change)

Settings: /etc/jt-waf-block.conf (KEY=value lines):
  url = https://waf.example.org/api/v1     jt-waf-mgr's API
  token_file = /etc/jt-waf-block.token     the API token (scope blocks:write), root-owned, mode 600
  ca_file =                                optional CA bundle for the API's certificate
  timeout = 10
The token is read from the file on every call and is never written to a log or a command line.

Private, loopback and other non-public addresses are skipped (exit 0): jt-waf-mgr refuses them
anyway, and an internal user mistyping a password must not end up on the proxy's list.
Every outcome is written to syslog under the program name jt-waf-block (the pack's rules
131074-131077 read it). On failure the exit status is non-zero, so fail2ban also reports
"execute ban failed" (rule 131025: the address is NOT blocked).
"""
import argparse
import ipaddress
import json
import os
import ssl
import stat
import sys
import syslog
import urllib.error
import urllib.parse
import urllib.request

CONF = os.environ.get('JT_WAF_BLOCK_CONF', '/etc/jt-waf-block.conf')
SOURCE_OK = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:@/+-')
TTL_MIN, TTL_MAX = 60, 7 * 86400


def log(level, text):
    syslog.openlog('jt-waf-block', 0, syslog.LOG_AUTH)
    syslog.syslog(level, text)
    print(text, file=sys.stderr)


def settings():
    conf = {'url': '', 'token_file': '/etc/jt-waf-block.token', 'ca_file': '', 'timeout': '10'}
    with open(CONF, encoding='utf-8') as fh:
        for line in fh:
            line = line.split('#', 1)[0].strip()
            if '=' in line:
                key, value = (x.strip() for x in line.split('=', 1))
                if key in conf:
                    conf[key] = value
    if not conf['url'].startswith('https://'):
        raise SystemExit('jt-waf-block: url in %s must be https://' % CONF)
    return conf


def token(path):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise SystemExit('jt-waf-block: %s must be a regular file' % path)
    if st.st_uid != 0 or st.st_mode & 0o077:
        raise SystemExit('jt-waf-block: %s must be owned by root, mode 600' % path)
    with open(path, encoding='utf-8') as fh:
        value = fh.read().strip()
    if not value or any(c.isspace() for c in value):
        raise SystemExit('jt-waf-block: %s is empty or malformed' % path)
    return value


def call(conf, method, path, body=None):
    ctx = ssl.create_default_context(cafile=conf['ca_file'] or None)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(conf['url'].rstrip('/') + path, data=data, method=method, headers={
        'Authorization': 'Bearer ' + token(conf['token_file']),
        'Content-Type': 'application/json', 'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=float(conf['timeout']), context=ctx) as resp:
            return resp.status, json.loads(resp.read() or b'{}')
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read() or b'{}')
        except ValueError:
            detail = {}
        return e.code, detail


def code_of(detail):
    if isinstance(detail, dict):
        err = detail.get('error')
        if isinstance(err, dict):
            return str(err.get('code') or err.get('message') or '')[:80]
        return str(err or detail.get('code') or '')[:80]
    return ''


def main(argv=None):
    ap = argparse.ArgumentParser(description='fail2ban action: block an address at the reverse proxy via jt-waf-mgr')
    ap.add_argument('command', choices=('ban', 'unban', 'check'))
    ap.add_argument('ip', nargs='?')
    ap.add_argument('--source', default='')
    ap.add_argument('--ttl', type=int, default=86400)
    ap.add_argument('--reason', default='fail2ban')
    a = ap.parse_args(argv)
    conf = settings()
    if a.command == 'check':
        token(conf['token_file'])
        status, detail = call(conf, 'GET', '/blocks?state=active')
        print('jt-waf-block: API answered HTTP %d %s' % (status, code_of(detail)))
        return 0 if status in (200, 403) else 1      # 403: the token may lack blocks:read, still reachable
    try:
        ip = ipaddress.ip_address((a.ip or '').strip())
    except ValueError:
        log(syslog.LOG_ERR, 'ERROR %s: not an address: %r' % (a.command, (a.ip or '')[:60]))
        return 2
    if not ip.is_global:
        log(syslog.LOG_INFO, 'INFO %s %s skipped: not a public address' % (a.command, ip))
        return 0
    source = a.source[:64]
    if not source or set(source) - SOURCE_OK:
        log(syslog.LOG_ERR, 'ERROR %s %s: bad source %r' % (a.command, ip, source))
        return 2
    try:
        if a.command == 'ban':
            ttl = TTL_MAX if a.ttl <= 0 else min(max(a.ttl, TTL_MIN), TTL_MAX)   # fail2ban -1 = permanent
            reason = ' '.join(a.reason.split())[:300] or 'fail2ban'
            status, detail = call(conf, 'POST', '/blocks', {'ip': str(ip), 'ttl': ttl, 'source': source,
                                                            'reason': reason})
            ok = status in (200, 201)
        else:
            status, detail = call(conf, 'DELETE', '/blocks/%s?source=%s' % (
                urllib.parse.quote(str(ip), safe=''), urllib.parse.quote(source, safe='')))
            ok = status in (200, 204, 404)
    except (OSError, ValueError, ssl.SSLError) as e:
        log(syslog.LOG_ERR, 'ERROR %s %s source=%s: jt-waf-mgr unreachable (%s)' % (
            a.command, ip, source, type(e).__name__))
        return 1
    except SystemExit as e:                                  # token file problems
        log(syslog.LOG_ERR, 'ERROR %s %s source=%s: %s' % (a.command, ip, source, e))
        return 1
    if ok:
        log(syslog.LOG_NOTICE, 'INFO %s %s source=%s: done (HTTP %d)' % (a.command, ip, source, status))
        return 0
    log(syslog.LOG_ERR, 'ERROR %s %s source=%s: jt-waf-mgr answered HTTP %d %s' % (
        a.command, ip, source, status, code_of(detail)))
    return 1


if __name__ == '__main__':
    sys.exit(main())
