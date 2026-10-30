#!/usr/bin/env python3
# jt-nextcloud-names - Nextcloud account ids to names, for the alert digest
# Part of the jt-nextcloud rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
"""Write the names of Nextcloud's accounts for jt-alert-digest's account names map.

Nextcloud connected to an LDAP directory gives each directory user an internal
id, by default the entry's UUID ("3094106c-645c-103a-832e-5343dab4befe"), and
that id is what its logs, and therefore this pack's alerts, name. A rule cannot
look a value up, so jt-alert-digest (1.14 and later) does it when it writes a
notification, from an optional map of "id: name" lines. This script keeps
Nextcloud's part of that map:

    <wazuh>/etc/jt-packs/jt-alert-digest-names.d/nextcloud

from the OCS provisioning API (GET /ocs/v1.php/cloud/users, paged, then
/ocs/v1.php/cloud/users/<id> for the display name and e-mail address). Only
accounts whose id differs from their name are written: a local account such
as "admin" needs no translation.

Settings, in <wazuh>/etc/jt-packs/jt-nextcloud.conf ("key = value"):

    url = https://cloud.example.com
    user = <an administrator's login>
    app_password_file = /var/ossec/etc/jt-packs/jt-nextcloud-app-password
    ca_file = <optional: a CA bundle for a private CA>
    tls_verify = yes

The app password (Nextcloud: Personal settings, Security, "Create new app
password") is read from a root-only regular file and is never written to a
log, a message or an event. Without the settings file the script does nothing,
so installing the pack schedules nothing that fails.

The file is written in full and renamed into place, so the digest never reads
half of it. A run that fails keeps the previous file, and so does a run whose
answer has fewer than half the names of the previous file (a directory that
was not reachable from Nextcloud for a moment would otherwise empty the map);
--force writes it anyway. A failure is written to the manager's event queue
(rule 131783, level 5); after three days without a successful run it is
131784 (level 7).

Every manager node reads its own map, so run this on every node (as the
digest itself runs on every node).

    jt-nextcloud-names.py --wazuh-path /var/ossec            normal run (cron)
    jt-nextcloud-names.py --wazuh-path /var/ossec --once     the same, now, with a summary
    jt-nextcloud-names.py --wazuh-path /var/ossec --check    settings and login only
    jt-nextcloud-names.py --wazuh-path /var/ossec --dry-run  fetch and count, write nothing

Runs on the system python3 (3.8 or later), standard library only.
"""

import argparse
import base64
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode, urlsplit

VERSION = '1.0'
PROG = 'jt-nextcloud-names'
LOCATION = 'jt-nextcloud-names'
FIELD = 'jt_nextcloud_names'
STALE_AFTER = 3 * 86400      # without a successful run: 131784 instead of 131783
PAGE = 500                   # users asked for per page of the list
MAX_USERS = 100000
MAX_BODY = 16 << 20
NAME_MAX = 120
SHRINK = 0.5                 # fewer names than this share of the previous file: keep the file
SETTINGS = ('url', 'user', 'app_password_file', 'ca_file', 'tls_verify')
SYSTEM_CA_BUNDLES = ('/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt',
                     '/etc/ssl/ca-bundle.pem', '/etc/ssl/cert.pem')

NOW = None                   # the tests pin the clock here


def now():
    return time.time() if NOW is None else NOW


def log(msg):
    sys.stdout.write('%s %s: %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now())),
                                      PROG, msg))
    sys.stdout.flush()


class Failure(Exception):
    """What went wrong, in words that never carry the app password."""


# ---------------------------------------------------------------- files

def open_checked(path, setting, private):
    """A regular file, not reached through a symbolic link, owned by root;
    private: readable by root only, else writable by root only."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise Failure('%s %s cannot be read: %s' % (setting, path, exc.strerror or exc))
    if stat.S_ISLNK(info.st_mode):
        raise Failure('%s %s is a symbolic link; name the file itself' % (setting, path))
    if not stat.S_ISREG(info.st_mode):
        raise Failure('%s %s is not a regular file' % (setting, path))
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError:
        raise Failure('%s %s cannot be read' % (setting, path))
    fh = os.fdopen(fd, 'rb')
    info = os.fstat(fh.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) \
            or info.st_mode & (0o077 if private else 0o022):
        fh.close()
        if private:
            raise Failure('%s %s must belong to root and be readable by root only (chmod 600)'
                          % (setting, path))
        raise Failure('%s %s must belong to root and be writable by root only (chmod 644 or 600)'
                      % (setting, path))
    return fh


def read_settings(path):
    """{key: value} from the settings file; None when there is no such file."""
    if not os.path.lexists(path):
        return None
    with open_checked(path, 'settings file', private=False) as fh:
        try:
            text = fh.read(1 << 16).decode('utf-8')
        except UnicodeDecodeError:
            raise Failure('settings file %s is not UTF-8 text' % path)
    settings = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        settings[key.strip().lower()] = value.strip()
    return settings


def read_password(path):
    with open_checked(path, 'app_password_file', private=True) as fh:
        try:
            line = fh.readline(4096).decode('utf-8')
        except UnicodeDecodeError:
            raise Failure('app_password_file %s cannot be read' % path)
    password = re.split(r'[\r\n]', line, maxsplit=1)[0].strip()
    if not re.match(r'^[\x21-\x7e]{8,256}$', password):
        raise Failure('app_password_file %s does not hold an app password on its first line' % path)
    return password


def yes(value):
    value = value.strip().lower()
    if value in ('yes', 'on', 'true', '1'):
        return True
    if value in ('no', 'off', 'false', '0'):
        return False
    raise ValueError(value)


def options(settings, wazuh):
    """(options, warnings); raises Failure for a setting that makes a run impossible."""
    warnings = ['unknown setting %r ignored' % k for k in sorted(settings) if k not in SETTINGS]
    o = {}
    url = (settings.get('url') or '').strip().rstrip('/')
    try:
        parts = urlsplit(url)
        host = parts.hostname or ''
    except ValueError:
        parts, host = None, ''
    if not parts or not host or parts.query or parts.fragment or '@' in parts.netloc \
            or re.search(r'\s', url) or not (parts.scheme == 'https' or (
                parts.scheme == 'http' and host in ('127.0.0.1', 'localhost', '::1'))):
        # the app password travels with every request
        raise Failure('url must be the https:// address of Nextcloud, for example '
                      'https://cloud.example.com')
    o['url'], o['host'] = url, host
    o['user'] = (settings.get('user') or '').strip()
    if not o['user'] or ':' in o['user'] or re.search(r'[\x00-\x1f]', o['user']):
        raise Failure('user must be the login of a Nextcloud administrator')
    o['password_file'] = settings.get('app_password_file') or \
        os.path.join(wazuh, 'etc', 'jt-packs', 'jt-nextcloud-app-password')
    o['verify'] = True
    if settings.get('tls_verify'):
        try:
            o['verify'] = yes(settings['tls_verify'])
        except ValueError:
            raise Failure('tls_verify must be yes or no')
    o['ca_file'] = settings.get('ca_file') or None
    if o['ca_file'] and not os.access(o['ca_file'], os.R_OK):
        raise Failure('ca_file %s cannot be read' % o['ca_file'])
    return o, warnings


# ---------------------------------------------------------------- the OCS API

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the Authorization header to wherever it points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'redirect refused', headers, fp)


def tls_context(o):
    if o.get('verify', True):
        context = ssl.create_default_context(cafile=o.get('ca_file'))
        if not o.get('ca_file') and not context.cert_store_stats().get('x509_ca'):
            # Wazuh's own framework python has an empty CA store
            for bundle in SYSTEM_CA_BUNDLES:
                if os.path.isfile(bundle):
                    try:
                        context.load_verify_locations(cafile=bundle)
                        break
                    except (ssl.SSLError, OSError):
                        continue
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class Api(object):

    def __init__(self, o, password):
        self.o = o
        self.secrets = [password, base64.b64encode(('%s:%s' % (o['user'], password))
                                                   .encode('utf-8')).decode('ascii')]
        self.auth = 'Basic ' + self.secrets[1]
        handlers = [_NoRedirect()]
        if o['url'].startswith('https:'):
            handlers.append(urllib.request.HTTPSHandler(context=tls_context(o)))
        self.opener = urllib.request.build_opener(*handlers)
        self.requests = 0

    def clean(self, text):
        text = str(text)
        for secret in self.secrets:
            if secret:
                text = text.replace(secret, '[redacted]')
        return ' '.join(text.split())[:300]

    def get(self, path, params):
        """The ocs.data of one request; Failure, or LookupError for a missing user."""
        url = self.o['url'] + path + '?' + urlencode(dict(params, format='json'))
        request = urllib.request.Request(url, method='GET')
        request.add_header('Authorization', self.auth)
        request.add_header('OCS-APIRequest', 'true')
        request.add_header('Accept', 'application/json')
        request.add_header('User-Agent', '%s/%s' % (PROG, VERSION))
        self.requests += 1
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(MAX_BODY + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise LookupError(path)
            what = {401: 'the login or app password was refused',
                    403: 'the account is not allowed to list users (it must be an administrator)'}
            raise Failure(self.clean('%s: HTTP %d: %s' % (self.o['host'], exc.code,
                                                          what.get(exc.code, exc.reason))))
        except urllib.error.URLError as exc:
            raise Failure(self.clean('%s: %s' % (self.o['host'], exc.reason)))
        except (OSError, ValueError) as exc:
            raise Failure(self.clean('%s: %s: %s' % (self.o['host'], type(exc).__name__, exc)))
        if len(raw) > MAX_BODY:
            raise Failure('%s: an answer larger than %d MB' % (self.o['host'], MAX_BODY >> 20))
        try:
            ocs = json.loads(raw.decode('utf-8', 'replace'))['ocs']
            meta, data = ocs['meta'], ocs.get('data')
            code = int(meta.get('statuscode', 0))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise Failure('%s: the answer is not an OCS JSON document (is url the address of '
                          'Nextcloud?)' % self.o['host'])
        if code in (100, 200):
            return data
        if code in (404, 998):
            raise LookupError(path)
        what = {997: 'the login or app password was refused',
                403: 'the account is not allowed to list users (it must be an administrator)'}
        raise Failure(self.clean('%s: OCS status %d: %s' % (self.o['host'], code,
                                                            what.get(code) or meta.get('message') or '')))

    def users(self):
        """Every account id, a page at a time."""
        found, seen, offset = [], set(), 0
        while True:
            data = self.get('/ocs/v1.php/cloud/users', {'limit': PAGE, 'offset': offset})
            page = data.get('users') if isinstance(data, dict) else None
            if isinstance(page, dict):
                page = list(page)
            if not isinstance(page, list):
                raise Failure('%s: the user list has an unexpected shape' % self.o['host'])
            new = [str(u) for u in page if str(u) not in seen]
            seen.update(new)
            found.extend(new)
            if len(found) > MAX_USERS:
                raise Failure('%s: more than %d users' % (self.o['host'], MAX_USERS))
            if len(page) < PAGE or not new:
                return found
            offset += len(page)

    def details(self, uid):
        """(display name, e-mail address) of one account; LookupError if it is gone."""
        data = self.get('/ocs/v1.php/cloud/users/' + quote(uid, safe=''), {})
        if not isinstance(data, dict):
            raise LookupError(uid)
        name = data.get('displayname') or data.get('display-name') or ''
        return str(name or ''), str(data.get('email') or '')


# ---------------------------------------------------------------- the names file

def clean(value):
    out = []
    for char in str(value):
        kind = unicodedata.category(char)
        if kind in ('Cc', 'Zl', 'Zp'):
            out.append(' ')
        elif kind not in ('Cf', 'Cs', 'Co'):
            out.append(char)
    text = ' '.join(''.join(out).split())
    return text if len(text) <= NAME_MAX else text[:NAME_MAX - 3] + '...'


def entry(uid, display, email):
    """The "id: name" line for one account, or None when it needs none."""
    if not uid or ':' in uid or uid.startswith('#') or uid != uid.strip() \
            or any(unicodedata.category(c)[0] == 'C' for c in uid):
        return None             # the map's format cannot hold it
    display, email = clean(display), clean(email)
    name = display or email
    if not name or name.casefold() == uid.casefold():
        return None
    if email and email.casefold() != name.casefold():
        name = clean('%s (%s)' % (name, email))
    return '%s: %s' % (uid, name)


def count_entries(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            return sum(1 for line in fh if line.strip() and not line.startswith('#') and ':' in line)
    except OSError:
        return 0


def write_names(path, lines, source):
    """Written in full beside the old file (hidden, so the digest skips it) and renamed over it."""
    folder = os.path.dirname(path)
    if os.path.islink(folder):
        raise Failure('%s is a symbolic link' % folder)
    if not os.path.isdir(folder):
        os.makedirs(folder, 0o700)
    tmp = os.path.join(folder, '.' + os.path.basename(path) + '.tmp')
    if os.path.lexists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write('# Written by %s %s from %s at %s; the next run replaces this file.\n'
                 % (PROG, VERSION, source, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now()))))
        fh.write('# Nextcloud accounts whose id differs from their name, as "id: name".\n')
        for line in lines:
            fh.write(line + '\n')
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------- state and events

def load_state(path):
    try:
        with open(path, encoding='utf-8') as fh:
            state = json.load(fh)
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(state, fh, sort_keys=True)
    os.replace(tmp, path)


def send(queue, event):
    """One JSON event as the manager's own (location jt-nextcloud-names)."""
    msg = '1:%s:%s' % (LOCATION, json.dumps({FIELD: event}, sort_keys=True, separators=(',', ':')))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.connect(queue)
        s.send(msg.encode('utf-8'))
    finally:
        s.close()


def iso(epoch):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(epoch)) if epoch else 'never'


# ---------------------------------------------------------------- runs

def fetch(o, password, progress=None):
    """(lines, users, skipped) from the API."""
    api = Api(o, password)
    uids = api.users()
    lines, skipped = [], 0
    for index, uid in enumerate(uids):
        try:
            display, email = api.details(uid)
        except LookupError:
            skipped += 1        # deleted between the list and this request
            continue
        line = entry(uid, display, email)
        if line:
            lines.append(line)
        if progress and index and index % 500 == 0:
            progress('%d of %d users read' % (index, len(uids)))
    if uids and skipped > max(10, len(uids) // 10):
        raise Failure('%s: %d of %d users could not be read' % (o['host'], skipped, len(uids)))
    return sorted(lines), len(uids), skipped


def check(paths, settings, wazuh):
    print('%s %s' % (PROG, VERSION))
    print('  settings: %s' % paths['settings'])
    if settings is None:
        print('  not configured: create %s (url, user, app_password_file)' % paths['settings'])
        return 1
    try:
        o, warnings = options(settings, wazuh)
    except Failure as exc:
        print('  PROBLEM: %s' % exc)
        return 1
    for warning in warnings:
        print('  warning: %s' % warning)
    print('  Nextcloud: %s as %s%s' % (o['url'], o['user'],
                                       '' if o['verify'] else ', certificate NOT verified'))
    try:
        password = read_password(o['password_file'])
        print('  app password: %s (root only)' % o['password_file'])
    except Failure as exc:
        print('  PROBLEM: %s' % exc)
        return 1
    names = paths['names']
    if os.path.exists(names):
        age = (now() - os.stat(names).st_mtime) / 86400.0
        print('  names file: %s, %d entries, written %.1f days ago' % (names, count_entries(names), age))
    else:
        print('  names file: %s (not written yet)' % names)
    state = load_state(paths['state'])
    print('  last success: %s%s' % (iso(state.get('last_success')),
                                     ('; failing since %s' % iso(state['first_failure']))
                                     if state.get('first_failure') else ''))
    api = Api(o, password)
    try:
        data = api.get('/ocs/v1.php/cloud/users', {'limit': 1, 'offset': 0})
    except (Failure, LookupError) as exc:
        print('  PROBLEM: %s' % (exc if isinstance(exc, Failure) else 'the user list was not found'))
        return 1
    if not isinstance(data, dict) or not isinstance(data.get('users'), (list, dict)):
        print('  PROBLEM: the user list has an unexpected shape')
        return 1
    print('  result: Nextcloud accepted the login and lists users')
    return 0


def run(args):
    wazuh = os.path.abspath(args.wazuh_path)
    paths = {'settings': os.path.join(wazuh, 'etc', 'jt-packs', 'jt-nextcloud.conf'),
             'names': os.path.join(wazuh, 'etc', 'jt-packs', 'jt-alert-digest-names.d', 'nextcloud'),
             'state': os.path.join(wazuh, 'var', 'jt-nextcloud-names.state'),
             'queue': os.path.join(wazuh, 'queue', 'sockets', 'queue')}
    try:
        settings = read_settings(paths['settings'])
    except Failure as exc:
        if args.check:
            print('  PROBLEM: %s' % exc)
            return 1
        return failed(paths, args, str(exc))
    if args.check:
        return check(paths, settings, wazuh)
    if settings is None:
        if args.once or args.dry_run:
            print('not configured: create %s (see the pack\'s setup guide)' % paths['settings'])
        return 0
    try:
        o, warnings = options(settings, wazuh)
        for warning in warnings:
            log(warning)
        password = read_password(o['password_file'])
        lines, total, skipped = fetch(o, password, log if (args.once or args.dry_run) else None)
    except Failure as exc:
        return failed(paths, args, str(exc))
    previous = count_entries(paths['names'])
    if args.dry_run:
        print('%d users in Nextcloud, %d whose id differs from their name%s; the file has %d now; '
              'nothing written' % (total, len(lines), (', %d gone while reading' % skipped)
                                   if skipped else '', previous))
        return 0
    if previous >= 20 and len(lines) < previous * SHRINK and not args.force:
        return failed(paths, args, '%s returned %d names where the file has %d; the file was kept '
                      '(run with --force if accounts were really removed)'
                      % (o['host'], len(lines), previous))
    try:
        write_names(paths['names'], lines, o['host'])
    except (OSError, Failure) as exc:
        return failed(paths, args, 'cannot write %s: %s' % (paths['names'], getattr(exc, 'strerror', None) or exc))
    state = load_state(paths['state'])
    if state.get('first_failure'):
        log('working again after failing since %s' % iso(state['first_failure']))
    save_state(paths['state'], {'last_success': now(), 'entries': len(lines), 'users': total,
                                'version': VERSION})
    log('%d users, %d names written to %s%s' % (total, len(lines), paths['names'],
                                               (', %d gone while reading' % skipped) if skipped else ''))
    return 0


def failed(paths, args, problem):
    """Keep the previous file; 131783, or 131784 once nothing has succeeded for three days."""
    log('FAILED: %s' % problem)
    if args.dry_run:
        return 1
    state = load_state(paths['state'])
    t = now()
    first = state.get('first_failure') or t
    since = state.get('last_success') or first
    stale = t - since >= STALE_AFTER
    event = {'event': 'stale' if stale else 'failed', 'detail': problem[:300],
             'last_success': iso(state.get('last_success')), 'age_days': int((t - since) // 86400),
             'file': paths['names']}
    try:
        send(paths['queue'], event)
    except OSError as exc:
        log('cannot write to the analysisd queue: %s' % (exc.strerror or exc))
    state['first_failure'] = first
    try:
        save_state(paths['state'], state)
    except OSError as exc:
        log('cannot save %s: %s' % (paths['state'], exc.strerror or exc))
    return 1


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--wazuh-path', default='/var/ossec')
    ap.add_argument('--once', action='store_true', help='run now, as cron would, and show progress')
    ap.add_argument('--check', action='store_true',
                    help='show the settings and try the login; write and send nothing')
    ap.add_argument('--dry-run', action='store_true', help='fetch and count; write and send nothing')
    ap.add_argument('--force', action='store_true',
                    help='write the file even if it has far fewer names than the previous one')
    ap.add_argument('--version', action='version', version='%s %s' % (PROG, VERSION))
    return ap.parse_args(argv)


def main(argv=None):
    return run(parse_args(argv))


if __name__ == '__main__':
    sys.exit(main())
