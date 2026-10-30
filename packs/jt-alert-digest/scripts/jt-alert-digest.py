#!/usr/bin/env python3
"""Turn Wazuh's alert mail into something a person can read.

wazuh-maild sends one notification per alert in "log format": the raw
full_log, followed by every decoded field printed a second time, with an
hour's alerts concatenated into a single message. Measured on a live
manager, one such message ran to seventeen notifications and several
thousand lines, and the genuine detection in it sat below fourteen alerts
from a build host. Nobody reads that, which means the channel exists but
carries nothing.

This groups alerts that share a rule and an agent, keeps the few fields
that identify what happened, and sends one message per run. The same
seventeen notifications become about forty lines.

Mail settings come from the manager's own ossec.conf: smtp_server,
email_from and email_to from <global>, email_alert_level from <alerts>.
They are already set there for wazuh-maild, so this needs no configuration
of its own and cannot drift away from it. Optional per-node settings
(submission port, STARTTLS, authentication, dashboard link, repeat hold,
daily summary) live in etc/jt-packs/jt-alert-digest.conf, a file that
installing or updating the pack never writes.

The position in the alert file is kept by inode and dated file name, so a
rotation at midnight is followed into the rotated (and later compressed)
file instead of jumping to the start of the new one. A send that fails
leaves the position alone, so the next run retries rather than losing the
alerts. The first run ever records the end of the file and sends nothing,
because mailing the whole backlog is not a useful way to start.

The message is sent as HTML with a plain text alternative. That is not
decoration: the first version aligned its fields with spaces, and every
mail client rewrapped the long lines and destroyed the alignment, which
left it no easier to read than what it replaced. A table holds its shape.

A notifier cannot announce its own failure by mail, so failures go into
the manager's event queue as JSON, where rules 131110-131116 turn them into
console alerts: when a failure starts or changes, then hourly, and at a
higher level once alerts have reached nobody for two hours.

Optionally the same digest is also posted to chat: Zulip, Microsoft Teams,
Telegram, Slack, Discord, Mattermost, LINE, or as JSON to any webhook (all
from the settings file). Each channel keeps its own position in the alert
file, so an outage of one cannot lose or repeat another's messages.

Where an alert names an account by an internal id (an LDAP entry's UUID in
Nextcloud, a SID in Windows), an optional account names map shows the
person instead (1.14, names_file; see "Account names" below).

Once this is delivering, turn wazuh-maild off, or both will send: set
<email_notification> to no and stop that daemon. Do not raise
email_alert_level for that purpose; this script reads it too.

Runs on the manager's own python3 (3.8 or later), standard library only.
"""

import argparse
import base64
import copy
import fcntl
import gzip
import hashlib
import hmac
import http.client
import json
import os
import re
import smtplib
import socket
import ssl
import stat
import subprocess
import sys
import time
import traceback
import unicodedata
import urllib.error
import urllib.request
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.parse import quote, urlencode, urlsplit

VERSION = "1.14"
DEFAULT_WAZUH = "/var/ossec"
MAX_GROUPS = 40        # how many rule/agent groups one message details
MAX_SAMPLES = 3        # how many instances are kept per group
MAX_ALERTS = 5000      # alerts taken into one run; the rest wait for the next
MAX_FIELD = 200        # longest single value printed
HTML_BUDGET = 80000    # Gmail cuts a message off at 102 KB of HTML
CHUNK = 1 << 20        # bytes read from an alert file at a time
LOG_CAP = 1 << 20      # the cron log is trimmed back to half of this
STALE_AFTER = 2 * 3600     # undelivered this long: escalate
REPORT_EVERY = 3600        # an unchanged failure is reported again hourly
ESCALATE_EVERY = 6 * 3600  # and its escalation every six hours
TRACK_FOR = 90 * 86400     # how long a (rule, agent) pair counts as known
LEARN_FOR = 86400          # no NEW badges during the first day of tracking
STOP_GRACE = 15 * 60       # an agent restart takes less than this
# Agent lifecycle, recognised by the event text rather than the rule ID: a site
# rule can take the event over (on one manager an override of 503 meant no
# "started" was ever seen, and 43 agents restarted on purpose were listed as
# stopped), and a new agent's first start is 501, not 503.
AGENT_EVENT = re.compile(r"\bAgent (started|stopped|disconnected): '([^']+)'")
REDACTED = "[redacted]"

SEVERITY = {12: "[HIGH]", 13: "[HIGH]", 14: "[CRITICAL]", 15: "[CRITICAL]"}
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# Mail clients strip <style> blocks unpredictably, so every rule is inlined.
# The palette is fixed rather than theme-aware for the same reason: a client
# that inverts colours for dark mode does so to whatever is declared, and a
# half-declared palette is what produces unreadable mail.
INK = "#16191d"
MUTED = "#6b7280"
FAINT = "#9aa1ab"
LINE = "#e3e6ea"
PANEL = "#f6f7f9"
NEWBADGE = "#1d4ed8"
BAND = {12: "#c2410c", 13: "#b91c1c", 14: "#991b1b", 15: "#7f1d1d"}
MONO = ("ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, "
        "'Liberation Mono', monospace")
SANS = ("-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, "
        "'Helvetica Neue', Arial, sans-serif")

NOW = None             # the tests pin the clock here


def now():
    return time.time() if NOW is None else NOW


def log(message):
    """One dated line in the cron log, for a change of state rather than every run."""
    sys.stdout.write("%s jt-alert-digest: %s\n"
                     % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now())), message))
    sys.stdout.flush()


# --------------------------------------------------------------------------
# Configuration, read from the manager rather than duplicated here
# --------------------------------------------------------------------------

def read_site_settings(wazuh):
    """Site settings that survive updating the pack.

    etc/jt-packs/jt-alert-digest.conf, one "key = value" per line. Installing
    or updating the pack rewrites its cron entry from the manifest, so an
    argument added to that line by hand would be lost; this file is never
    written by the installer. Each node has its own (etc/jt-packs is not
    synchronised by the cluster). The keys are listed in KNOWN_SETTINGS.
    """
    settings = {}
    path = os.path.join(wazuh, "etc", "jt-packs", "jt-alert-digest.conf")
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                settings[key.strip().lower()] = value.strip()
    except OSError:
        pass
    return settings


def _blocks(body, tag):
    return re.findall(r"<%s(?:\s[^>]*)?>(.*?)</%s>" % (tag, tag), body, flags=re.S)


def _values(blocks, tag):
    found = []
    for block in blocks:
        for value in re.findall(r"<%s>(.*?)</%s>" % (tag, tag), block, flags=re.S):
            value = value.strip()
            if value:
                found.append(value)
    return found


def dedupe(values):
    seen, out = set(), []
    for value in values:
        if value.lower() not in seen:
            seen.add(value.lower())
            out.append(value)
    return out


class ConfigUnreadable(Exception):
    pass


def read_global_config(wazuh):
    """Pull the mail settings out of ossec.conf.

    ossec.conf is not a single XML document: it is a sequence of top level
    <ossec_config> blocks, so an XML parser rejects it. The settings wanted
    here are flat text, and a targeted scan is both simpler and immune to
    the parts of the file this has no business reading.

    Each value is taken from the block Wazuh itself reads it from. 1.3 took
    email_to from anywhere in the file, which also collected the recipients
    of every <reports> and <email_alerts> block: those people then received
    every digest.
    """
    path = os.path.join(wazuh, "etc", "ossec.conf")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
    except OSError as exc:
        raise ConfigUnreadable("cannot read %s: %s" % (path, exc.strerror or exc))

    # Comments may contain example settings; remove them before scanning.
    body = re.sub(r"<!--.*?-->", "", body, flags=re.S)
    glob = _blocks(body, "global")
    alerts = _blocks(body, "alerts")
    cluster = _blocks(body, "cluster")

    def first(blocks, tag):
        found = _values(blocks, tag)
        return found[0] if found else None

    level = 12
    for raw in (first(alerts, "email_alert_level"), first(glob, "email_alert_level")):
        if raw is not None:
            try:
                level = int(raw)
                break
            except ValueError:
                pass

    node_name, node_type = None, None
    if cluster and (first(cluster, "disabled") or "no").lower() != "yes":
        node_name = first(cluster, "node_name")
        node_type = first(cluster, "node_type")

    return {
        "smtp_server": first(glob, "smtp_server"),
        "email_from": first(glob, "email_from"),
        "email_to": dedupe(_values(glob, "email_to")),
        "reply_to": first(glob, "email_reply_to"),
        "idsname": first(glob, "email_idsname"),
        "level": level,
        "node": node_name or socket.gethostname(),
        "node_type": (node_type or ("standalone" if not node_name else "")).lower(),
    }


KNOWN_SETTINGS = ("dashboard", "smtp_server", "smtp_port", "tls", "tls_verify",
                  "tls_ca_file", "smtp_user", "smtp_password_file", "sendmail_args",
                  "level", "to", "exclude_rules", "exclude_agents", "repeat",
                  "daily", "max_per_hour", "link", "names_file")
TLS_MODES = ("none", "may", "required", "verify", "implicit")

# The threat-hunting events view of a 4.9+ dashboard, filtered to one rule,
# one agent and the minutes around the group. Same shape as the deep link in
# Wazuh's own 4.14 integration examples.
AUTO_LINK = ("{base}/app/threat-hunting#/overview/?tab=general&tabView=events"
             "&_a=(filters:!(),query:(language:kuery,query:'rule.id:{rule_id}'))"
             "&_g=(filters:!(),refreshInterval:(pause:!t,value:0),"
             "time:(from:'{from}',to:'{to}'))&agentId={agent_id}")


def split_list(value):
    return [v for v in re.split(r"[\s,;]+", value or "") if v]


def _yes(value):
    value = value.strip().lower()
    if value in ("yes", "on", "true", "1"):
        return True
    if value in ("no", "off", "false", "0"):
        return False
    raise ValueError(value)


def _duration(value):
    match = re.match(r"^\s*(\d+)\s*([mh]?)\s*$", value.lower())
    if not match:
        raise ValueError(value)
    return int(match.group(1)) * (3600 if match.group(2) == "h" else 60)


def _time_of_day(value):
    value = value.strip().lower()
    if value in ("off", "no", "none"):
        return None
    match = re.match(r"^(\d{1,2}):(\d{2})$", value)
    if not match or int(match.group(1)) > 23 or int(match.group(2)) > 59:
        raise ValueError(value)
    return (int(match.group(1)), int(match.group(2)))


def open_checked(path, setting, private=True):
    """(file object, None), or (None, problem) naming the file.

    A regular file, opened without following a symbolic link (whoever can
    change the link chooses what is read), that belongs to root. private: no
    one else may read it (a password, key or webhook address); otherwise no one
    else may write it (the account names map, which is not secret but decides
    what a reader is told). The checks are made on the file actually opened,
    not on the name.
    """
    try:
        info = os.lstat(path)
    except OSError as exc:
        return None, "%s %s cannot be read: %s" % (setting, path, exc.strerror or exc)
    if stat.S_ISLNK(info.st_mode):
        return None, "%s %s is a symbolic link; name the file itself" % (setting, path)
    if not stat.S_ISREG(info.st_mode):
        return None, "%s %s is not a regular file" % (setting, path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None, "%s %s cannot be read" % (setting, path)
    fh = None
    try:
        fh = os.fdopen(fd, "rb")
        info = os.fstat(fh.fileno())
    except OSError:
        if fh is None:
            os.close(fd)
        else:
            fh.close()
        return None, "%s %s cannot be read" % (setting, path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) \
            or info.st_mode & (0o077 if private else 0o022):
        fh.close()
        if private:
            return None, ("%s %s must belong to root and be readable by "
                          "root only (chmod 600)" % (setting, path))
        return None, ("%s %s must belong to root and be writable by root only "
                      "(chmod 644 or 600)" % (setting, path))
    return fh, None


def read_secret(path, setting="smtp_password_file"):
    """A password, key, token or webhook address, only from a file nobody but
    root can read, and never through a symbolic link.

    The value itself never appears in a message: the problems name the file.
    """
    fh, problem = open_checked(path, setting)
    if problem:
        return None, problem
    try:
        with fh:
            secret = re.split(r"[\r\n]", fh.readline().decode("utf-8"), maxsplit=1)[0]
    except (OSError, UnicodeDecodeError):
        return None, "%s %s cannot be read" % (setting, path)
    if not secret:
        return None, "%s %s is empty" % (setting, path)
    return secret, None


def dashboard_base(url):
    """https://host[:port][/prefix] of a dashboard URL, for building links."""
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    path = parts.path or ""
    prefix = path[:path.find("/app/")] if "/app/" in path else ""
    return "%s://%s%s" % (parts.scheme, parts.netloc, prefix.rstrip("/"))


def build_options(site, config, args=None):
    """What this run will do: the site file over ossec.conf, the command line over both.

    Returns (options, fatal, warnings). fatal lists what makes delivery
    impossible (reported by rule 131116); warnings list settings that were
    ignored, with the default used instead.
    """
    fatal, warnings = [], []
    o = {}
    for key in sorted(site):
        if key not in KNOWN_SETTINGS and key not in ZULIP_KEYS and key not in CHAT_KEYS:
            warnings.append("unknown setting %r ignored" % key)

    o["dashboard"] = (getattr(args, "dashboard", None) or site.get("dashboard") or "").strip() or None

    server = (site.get("smtp_server") or config.get("smtp_server") or "").strip()
    o["server"] = server
    tls = (site.get("tls") or "none").strip().lower()
    if tls not in TLS_MODES:
        fatal.append("tls = %s is not one of: %s" % (tls, ", ".join(TLS_MODES)))
    o["tls"] = tls
    verify = tls == "verify"
    if site.get("tls_verify"):
        try:
            verify = _yes(site["tls_verify"]) or tls == "verify"
        except ValueError:
            fatal.append("tls_verify must be yes or no")
    if verify and tls in ("none", "may"):
        fatal.append("tls_verify = yes needs tls = required or implicit")
    o["verify"] = verify
    o["ca_file"] = site.get("tls_ca_file") or None
    if o["ca_file"] and not os.access(o["ca_file"], os.R_OK):
        fatal.append("tls_ca_file %s cannot be read" % o["ca_file"])
    port = 465 if tls == "implicit" else 25
    if site.get("smtp_port"):
        try:
            port = int(site["smtp_port"])
        except ValueError:
            port = -1
        if not 0 < port < 65536:
            fatal.append("smtp_port = %s is not a port number" % site["smtp_port"])
            port = 25
    o["port"] = port

    o["user"] = site.get("smtp_user") or None
    o["password"] = None
    secret_file = site.get("smtp_password_file")
    if server.startswith("/"):
        if not (os.path.isfile(server) and os.access(server, os.X_OK)):
            fatal.append("smtp_server %s is not an executable program" % server)
        if tls != "none" or o["user"]:
            warnings.append("tls and smtp_user do not apply when smtp_server is a program")
    elif not server:
        fatal.append("no smtp_server in <global> of ossec.conf")
    elif o["user"] or secret_file:
        if not o["user"]:
            fatal.append("smtp_password_file is set but smtp_user is not")
        elif not secret_file:
            fatal.append("smtp_user is set but smtp_password_file is not")
        elif tls not in ("required", "verify", "implicit"):
            # smtplib would send the password in clear text to any server that
            # offers AUTH before STARTTLS, so this refuses rather than trusting it.
            fatal.append("a password is only sent over TLS: set tls = required, verify or implicit")
        else:
            secret, problem = read_secret(secret_file)
            if problem:
                fatal.append(problem)
            o["password"] = secret

    o["sendmail_args"] = split_list(site.get("sendmail_args"))
    for token in o["sendmail_args"]:
        if not re.match(r"^[-\w.=@:/+]+$", token):
            fatal.append("sendmail_args contains %r" % token)
            o["sendmail_args"] = []
            break

    o["email_from"] = config.get("email_from")
    if not o["email_from"]:
        fatal.append("no email_from in <global> of ossec.conf")
    recipients = list(getattr(args, "to", None) or []) or split_list(site.get("to")) \
        or list(config.get("email_to") or [])
    o["to"] = dedupe(recipients)
    if not o["to"]:
        fatal.append("no email_to in <global> of ossec.conf")
    o["reply_to"] = config.get("reply_to")
    o["idsname"] = config.get("idsname")

    level, forced = config.get("level", 12), False
    if site.get("level"):
        try:
            value = int(site["level"])
            if not 0 <= value <= 16:
                raise ValueError(value)
            level, forced = value, True
        except ValueError:
            warnings.append("level = %s ignored" % site["level"])
    if getattr(args, "level", None) is not None:
        level, forced = args.level, True
    o["level"], o["forced"] = level, forced

    o["exclude_rules"] = set()
    for value in split_list(site.get("exclude_rules")):
        if value.isdigit():
            o["exclude_rules"].add(value)
        else:
            warnings.append("exclude_rules entry %r is not a rule id" % value)
    o["exclude_agents"] = set(split_list(site.get("exclude_agents")))

    o["repeat"] = 3600
    if site.get("repeat"):
        try:
            o["repeat"] = _duration(site["repeat"])
        except ValueError:
            warnings.append("repeat = %s ignored, using 60 minutes" % site["repeat"])
    o["daily"] = (8, 0)
    if site.get("daily"):
        try:
            o["daily"] = _time_of_day(site["daily"])
        except ValueError:
            warnings.append("daily = %s ignored, using 08:00" % site["daily"])
    o["max_per_hour"] = 0
    if site.get("max_per_hour"):
        try:
            o["max_per_hour"] = max(0, int(site["max_per_hour"]))
        except ValueError:
            warnings.append("max_per_hour = %s ignored" % site["max_per_hour"])

    o["base"] = dashboard_base(o["dashboard"]) if o["dashboard"] else ""
    raw = (site.get("link") or "auto").strip()
    if raw.lower() in ("off", "no", "none"):
        o["link"] = None
    elif raw.lower() == "auto":
        o["link"] = AUTO_LINK if o["base"] else None
    elif re.match(r"^https?://", raw):
        o["link"] = raw
    else:
        warnings.append("link must be off, auto or an http(s) URL template")
        o["link"] = None
    o["zulip"], o["zulip_fatal"] = build_zulip_options(site, warnings)
    # Every configured chat or webhook channel, Zulip first as in 1.5-1.12.
    o["channels"] = []
    if o["zulip"]:
        o["channels"].append(ZulipChannel(o["zulip"], o["zulip_fatal"]))
    for name, cls in CHANNEL_CLASSES.items():
        c, cfatal = build_chat_options(site, name, warnings)
        if c:
            o["channels"].append(cls(c, cfatal))
    return o, fatal, warnings


# --------------------------------------------------------------------------
# Secrets: nothing the digest prints should carry one
# --------------------------------------------------------------------------

_SECRET_WORDS = (r"password|passwd|passphrase|secret|client_secret|consumer_secret|"
                 r"token|access_token|id_token|refresh_token|auth_token|api_key|apikey|"
                 r"api-key|x-api-key|private_key|aws_secret_access_key")
_QUERY_WORDS = _SECRET_WORDS + r"|pwd|pass|code|state|sig|signature|sid|session|sessionid|key"

# Ideas from the OWASP Logging Cheat Sheet (what never belongs in a log) and
# SigmaHQ's command-line credential rules; patterns written for this script.
REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
     "[redacted private key]"),
    (re.compile(r"(?i)\b((?:proxy-)?authorization\s*[:=]\s*[\"']?)"
                r"(?:(basic|bearer|digest|negotiate|ntlm|token)\s+)?[^\s\"',;]+"),
     lambda m: m.group(1) + ((m.group(2) + " ") if m.group(2) else "") + REDACTED),
    (re.compile(r"(?i)\b((?:set-)?cookie\s*[:=]\s*)[^\r\n\"]+"), r"\1" + REDACTED),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+@"), r"\1" + REDACTED + "@"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), REDACTED),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9\-._~+/]{8,}=*"), r"\1" + REDACTED),
    (re.compile(r"(?i)([?&;](?:%s)=)[^&\s#\"']+" % _QUERY_WORDS), r"\1" + REDACTED),
    (re.compile(r"(?i)([\"']?\b(?:%s)\b[\"']?(?:\s*=(?=[^\s&])|\s+=\s+|\s*:\s*))([\"']?)"
                r"[^\s\"',;&}]+" % _SECRET_WORDS), r"\1\2" + REDACTED),
    (re.compile(r"(?i)((?:^|[\s\"'])(?:--?|/)(?:[a-z0-9]+[-_])*(?:password|passwd|pwd|pw|pass|"
                r"passphrase|secret|token|authtoken|apikey|api-key|api_key)(?:[:=]|\s+)[\"']?)"
                r"[^\s\"']+"), r"\1" + REDACTED),
    (re.compile(r"(?i)(/user:\S+\s+)(?![/-])(\S+)"), r"\1" + REDACTED),
    (re.compile(r"(?i)(\bnet1?(?:\.exe)?\s+use\s+(?:[a-z]:\s+)?\\\\\S+\s+)(?![/-])(\S+)"),
     r"\1" + REDACTED),
    (re.compile(r"(?i)(\bmysql(?:dump|admin)?\b[^|;\n]*?\s-p)(?=\S)[^\s\"']+"), r"\1" + REDACTED),
    (re.compile(r"(?i)(\bsshpass\b(?:\s+-[a-zA-Z]\S*)*?\s+-p\s*)\S+"), r"\1" + REDACTED),
    (re.compile(r"(?i)(ConvertTo-SecureString\s+(?:-String\s+)?)([\"'])(.*?)\2"),
     r"\1\2" + REDACTED + r"\2"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), REDACTED),
    (re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"), REDACTED),
]


def redact(value):
    """Mask credentials in anything that goes into a message.

    Only the copy in the mail changes; the alert in Wazuh is untouched. A
    command line or a request URL is attacker-influenced text, and the mail
    goes to mailboxes with a wider audience than the manager's console.
    """
    text = str(value)
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


# --------------------------------------------------------------------------
# Reading the alert files
# --------------------------------------------------------------------------

DATED = re.compile(r"^ossec-alerts-(\d{2})(?:-(\d{3}))?\.json(\.gz)?$")
LEVEL_HINT = re.compile(rb'"rule":\s*\{\s*"level":\s*(\d+)')
MAIL_HINT = re.compile(rb'"mail":\s*true')
# Lines worth parsing below the mail level: agent lifecycle events, by their
# text (see AGENT_EVENT), whatever rule they ended up under.
HEALTH_HINT = re.compile(rb"Agent (?:started|stopped|disconnected): '")


def dated_key(rel):
    """'2026/Oct/ossec-alerts-10-002.json' -> (2026, 9, 10, 2), else None.

    analysisd names the day's file ossec-alerts-DD.json and, with
    rotate_interval or max_output_size, continues in -001, -002 ... .
    """
    parts = (rel or "").split("/")
    if len(parts) != 3 or not parts[0].isdigit() or parts[1] not in MONTHS:
        return None
    match = DATED.match(parts[2])
    if not match or match.group(3):
        return None
    return (int(parts[0]), MONTHS.index(parts[1]), int(match.group(1)), int(match.group(2) or 0))


def list_dated(alerts_dir):
    """Every dated alert file as {rel: {"key", "plain", "gz"}}, rel without .gz."""
    found = {}
    try:
        years = os.listdir(alerts_dir)
    except OSError:
        return found
    for year in years:
        if not year.isdigit():
            continue
        try:
            months = os.listdir(os.path.join(alerts_dir, year))
        except OSError:
            continue
        for month in months:
            if month not in MONTHS:
                continue
            try:
                names = os.listdir(os.path.join(alerts_dir, year, month))
            except OSError:
                continue
            for name in names:
                match = DATED.match(name)
                if not match:
                    continue
                rel = "%s/%s/%s" % (year, month, name[:-3] if match.group(3) else name)
                entry = found.setdefault(rel, {"key": dated_key(rel), "plain": False, "gz": False})
                entry["gz" if match.group(3) else "plain"] = True
    return found


def find_by_inode(alerts_dir, ino, dev=None, hint=None):
    """The dated name of the file with this inode, or None.

    alerts.json is a hard link to the day's file (getloglocation.c: unlink,
    then link), so the inode is what says which file was being read.
    """
    candidates = [hint] if hint else []
    for when in (now(), now() - 86400):
        lt = time.localtime(when)
        month = "%d/%s" % (lt.tm_year, MONTHS[lt.tm_mon - 1])
        try:
            names = sorted(os.listdir(os.path.join(alerts_dir, month)), reverse=True)
        except OSError:
            continue
        candidates.extend("%s/%s" % (month, n) for n in names
                          if DATED.match(n) and not n.endswith(".gz"))
    checked = set()
    for rel in candidates:
        if rel in checked:
            continue
        checked.add(rel)
        try:
            other = os.stat(os.path.join(alerts_dir, rel))
        except OSError:
            continue
        if other.st_ino == ino and dev in (None, other.st_dev):
            return rel
    for rel, entry in sorted(list_dated(alerts_dir).items(),
                             key=lambda kv: kv[1]["key"], reverse=True):
        if rel in checked or not entry["plain"]:
            continue
        try:
            other = os.stat(os.path.join(alerts_dir, rel))
        except OSError:
            continue
        if other.st_ino == ino and dev in (None, other.st_dev):
            return rel
    return None


def resolve(alerts_dir, rel):
    """(path, compressed) of a dated file, plain or as monitord left it, or None."""
    if not rel:
        return None
    plain = os.path.join(alerts_dir, rel)
    if os.path.isfile(plain):
        return plain, False
    if os.path.isfile(plain + ".gz"):
        return plain + ".gz", True
    return None


def open_segment(path, compressed):
    return gzip.open(path, "rb") if compressed else open(path, "rb")


def at_line_start(path, compressed, offset):
    if offset == 0:
        return True
    try:
        with open_segment(path, compressed) as fh:
            fh.seek(offset - 1)
            return fh.read(1) == b"\n"
    except (OSError, EOFError):
        return False


def first_stamp(path, compressed):
    """Epoch of the first alert in a file, or None when it is empty or unreadable."""
    try:
        with open_segment(path, compressed) as fh:
            line = fh.readline(1 << 16)
        return parse_ts(json.loads(line.decode("utf-8", "replace")).get("timestamp"))
    except (OSError, EOFError, ValueError, AttributeError):
        return None


def stat_alerts(path):
    """os.stat of alerts.json, waiting out the instant of the daily rotation.

    analysisd unlinks alerts.json and links the new day's file in its place,
    so for a moment at midnight the name does not exist.
    """
    try:
        return os.stat(path)
    except FileNotFoundError:
        time.sleep(1)
        return os.stat(path)


def end_position(alerts_path):
    """The end of the last complete line: where a first run starts."""
    info = stat_alerts(alerts_path)
    rel = find_by_inode(os.path.dirname(alerts_path), info.st_ino, info.st_dev)
    offset = info.st_size
    if offset:
        with open(alerts_path, "rb") as fh:
            block = min(offset, 65536)
            fh.seek(offset - block)
            tail = fh.read(block)
        cut = tail.rfind(b"\n")
        if cut >= 0:
            offset = offset - block + cut + 1
    return {"ino": info.st_ino, "dev": info.st_dev, "path": rel, "offset": offset}


def _segment(path, rel, compressed, offset, current, ino=None, dev=None, size=None):
    return {"path": path, "rel": rel, "gz": compressed, "offset": offset,
            "current": current, "ino": ino, "dev": dev, "size": size}


def plan(alerts_path, position):
    """Which byte ranges of which files hold the alerts not yet read.

    Returns (segments, lost). lost lists reasons alerts were skipped for
    good; each becomes one rule 131113 alert.

    1.3 kept a bare byte offset and treated a smaller alerts.json as "rotated,
    start at 0", so everything written between its last run and midnight was
    never read, and on a node that could not deliver, the whole day's backlog
    went with it. Here the old file is finished first, then any whole files
    rotated in between (several days of failing, or size rotation), then the
    current one.
    """
    alerts_dir = os.path.dirname(alerts_path)
    info = stat_alerts(alerts_path)
    cur_rel = find_by_inode(alerts_dir, info.st_ino, info.st_dev, position.get("path"))
    # The inode alone is not an identity: once monitord has compressed and
    # deleted a rotated file, the filesystem may give its inode number to a
    # later day's file (seen in testing on ext4). Inode and dated name together are.
    same = position.get("ino") == info.st_ino and position.get("dev") in (None, info.st_dev) \
        and (not position.get("path") or not cur_rel or position.get("path") == cur_rel)
    current = _segment(alerts_path, cur_rel, False, 0, True, info.st_ino, info.st_dev, info.st_size)
    offset = int(position.get("offset") or 0)
    lost = []

    if position.get("legacy"):
        # A 1.3 state: a number, no inode. It belongs to the file that was
        # current when the state was last written: the newest dated file whose
        # first alert is older than the state file. A line boundary at that
        # offset in today's file proves nothing (alert lines are similar in
        # length), so the time decides, not the offset.
        written = position.get("mtime")
        owner = cur_rel
        if written and cur_rel:
            dated = sorted((e["key"], rel) for rel, e in list_dated(alerts_dir).items()
                           if e["key"] and e["key"] <= dated_key(cur_rel))
            owner = None
            for _, rel in reversed(dated):
                found = resolve(alerts_dir, rel)
                started = first_stamp(found[0], found[1]) if found else None
                if started is not None and started <= written + 1:
                    owner = rel
                    break
            if owner is None:
                lost.append("the alert file the 1.3 read position (byte %d) was written for is "
                            "gone" % offset)
                return [current], lost
        if owner == cur_rel:
            if offset <= info.st_size and at_line_start(alerts_path, False, offset):
                current["offset"] = offset
                return [current], lost
        else:
            found = resolve(alerts_dir, owner)
            if found and at_line_start(found[0], found[1], offset):
                return plan(alerts_path, {"ino": None, "dev": None, "path": owner,
                                          "offset": offset})
        lost.append("the read position 1.3 kept (byte %d) does not fall on a line in the alert "
                    "file it was written for" % offset)
        return [current], lost

    if same:
        if offset > info.st_size:
            lost.append("alerts.json is smaller than the read position (%d of %d bytes): it was "
                        "truncated outside Wazuh" % (info.st_size, offset))
            offset = 0
        current["offset"] = offset
        return [current], lost

    segments = []
    old_rel = position.get("path")
    found = resolve(alerts_dir, old_rel)
    if found is None and position.get("ino") and not old_rel:
        hint = find_by_inode(alerts_dir, position["ino"], position.get("dev"))
        if hint:
            old_rel, found = hint, resolve(alerts_dir, hint)
    if found:
        segments.append(_segment(found[0], old_rel, found[1], offset, False,
                                 position.get("ino"), position.get("dev")))
    elif offset > 0 or (position.get("size") or 0) > offset:
        # An empty file is removed at rotation (openlog: ftell == 0 -> unlink),
        # so a missing file is only a loss when it had content.
        lost.append("the rotated alert file %s is gone, so the alerts written after byte %d "
                    "of it were not read" % (old_rel or "(name unknown)", offset))
    old_key, cur_key = dated_key(old_rel), dated_key(cur_rel)
    if old_key and cur_key:
        for rel, entry in sorted(list_dated(alerts_dir).items(), key=lambda kv: kv[1]["key"]):
            if old_key < entry["key"] < cur_key:
                between = resolve(alerts_dir, rel)
                if between:
                    segments.append(_segment(between[0], rel, between[1], 0, False))
    segments.append(current)
    return segments, lost


def where(segment, offset):
    position = {"ino": segment["ino"], "dev": segment["dev"], "path": segment["rel"], "offset": offset}
    if segment.get("size") is not None:
        position["size"] = max(segment["size"], offset)
    return position


# Which agent an address belongs to, learnt from the "agent" object of every
# alert line read (also the lines below the mail level, by a cheap match), so
# that a source address in a message can name the machine: an alert about an
# internal address guessing logins says 192.168.1.10, the reader wants to know
# which host that is. Kept in var/jt-alert-digest.agents, beside the state.
AGENT_HINT = re.compile(rb'"agent":\s*\{\s*"id":\s*"(\d{3,})",\s*"name":\s*"([^"\\]{1,128})",\s*"ip":\s*"([0-9A-Fa-f:.]{3,45})"')
AGENTS = {}
AGENTS_CHANGED = [False]
AGENTS_MAX = 5000


def learn_agent(raw):
    found = AGENT_HINT.search(raw, 0, 4000)
    if not found or found.group(1) == b"000":
        return
    address = found.group(3).decode("ascii", "replace")
    if address in ("127.0.0.1", "::1"):
        return
    name = found.group(2).decode("utf-8", "replace")
    if AGENTS.get(address) != name and (address in AGENTS or len(AGENTS) < AGENTS_MAX):
        AGENTS[address] = name
        AGENTS_CHANGED[0] = True


def host_label(address):
    """'192.0.2.10 (web1)' when the address is a known agent's, else the address."""
    text = str(address or "")
    name = AGENTS.get(text)
    return "%s (%s)" % (text, name) if name and name != text else text


def load_agents(path):
    AGENTS.clear()
    AGENTS_CHANGED[0] = False
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return
    if isinstance(data, dict):
        for k, v in list(data.items())[:AGENTS_MAX]:
            if isinstance(k, str) and isinstance(v, str):
                AGENTS[k] = v


def save_agents(path):
    if not AGENTS_CHANGED[0]:
        return
    tmp = path + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(AGENTS, fh, sort_keys=True)
        os.replace(tmp, path)
        AGENTS_CHANGED[0] = False
    except OSError:
        pass


# --------------------------------------------------------------------------
# Account names (1.14): show a person where an alert names an internal id
# --------------------------------------------------------------------------
#
# A directory-backed service often logs an account by an internal id rather
# than the login: Nextcloud on an LDAP directory uses the entry's UUID
# ("3094106c-645c-103a-832e-5343dab4befe"), Windows sometimes gives only a SID.
# A rule cannot look a value up, so the digest does it where it prints: an
# optional map from id to the name to show, kept by the site (or written by a
# script such as jt-nextcloud's jt-nextcloud-names.py).
#
# The map only changes how a value is shown. Groups, holds, NEW badges, the
# state file and the alerts in Wazuh are unchanged, the webhook gets the name
# in an added field beside the untouched value, and the id stays visible
# ("Alice (3094106c...)", "Alice (...-1104)") with the raw log under it.
# Only exact matches are replaced: a whole account value, or a UUID or SID
# token standing on its own; never a part of a longer word. Names come from a
# directory anyone with an account there may edit, so they are cleaned of
# control characters here and escaped like any other alert text per channel.

NAMES_FILE = os.path.join("etc", "jt-packs", "jt-alert-digest-names")
NAMES_DIR = NAMES_FILE + ".d"
NAMES_MAX_BYTES = 8 << 20     # one file
NAMES_MAX = 200000            # entries over all files
NAMES_MAX_FILES = 100         # files read from one directory
NAME_MAX = 120                # longest name shown
NAMES_SKIP = ("~", ".tmp", ".swp", ".bak", ".old", ".orig", ".rpmnew", ".rpmsave",
              ".dpkg-old", ".dpkg-new", ".dpkg-dist", ".dpkg-tmp")
UUID_TEXT = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
SID_TEXT = r"S-1-\d{1,3}(?:-\d{1,10}){1,15}"
UUID_ID = re.compile(r"^%s$" % UUID_TEXT)
SID_ID = re.compile(r"^%s$" % SID_TEXT)
# A token: not preceded or followed by a letter, digit, underscore or hyphen,
# so an id inside a longer word or a longer id is never taken.
ID_TOKEN = re.compile(r"(?<![\w-])(%s|%s)(?![\w-])" % (UUID_TEXT, SID_TEXT))
ACCOUNT_LABELS = ("Account", "User", "By", "Member", "Source account")
NAMES = {}
NAMES_REPORT = {"read": [], "refused": [], "entries": 0, "ignored": 0, "off": False}


def name_key(value):
    """The form an id is stored and looked up in: UUIDs in lower case."""
    value = str(value).strip()
    return value.lower() if UUID_ID.match(value) else value


def clean_name(value):
    """A name as shown: no control or formatting characters (a newline would
    start a line of its own in a chat message, a right-to-left override would
    reverse what follows), single spaces, at most NAME_MAX characters."""
    out = []
    for char in str(value):
        kind = unicodedata.category(char)
        if kind in ("Cc", "Zl", "Zp"):
            out.append(" ")
        elif kind not in ("Cf", "Cs", "Co"):
            out.append(char)
    return trim("".join(out), NAME_MAX)


def parse_names(text, names):
    """Lines "id: name" into names; returns (entries, lines ignored)."""
    entries = ignored = 0
    for line in text.lstrip("﻿").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, name = line.partition(":")
        key, name = key.strip(), clean_name(name)
        if not sep or not key or not name or len(key) > 256 \
                or any(unicodedata.category(c)[0] == "C" for c in key):
            ignored += 1
            continue
        if name.casefold() == key.casefold():
            continue        # nothing to tell the reader
        if len(names) >= NAMES_MAX and name_key(key) not in names:
            ignored += 1
            continue
        names[name_key(key)] = name
        entries += 1
    return entries, ignored


def read_names_file(path, names, report):
    fh, problem = open_checked(path, "names file", private=False)
    if problem:
        report["refused"].append((path, problem))
        return
    with fh:
        try:
            raw = fh.read(NAMES_MAX_BYTES + 1)
        except OSError as exc:
            report["refused"].append((path, "names file %s cannot be read: %s"
                                      % (path, exc.strerror or exc)))
            return
    if len(raw) > NAMES_MAX_BYTES:
        report["refused"].append((path, "names file %s is larger than %d MB"
                                  % (path, NAMES_MAX_BYTES >> 20)))
        return
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        report["refused"].append((path, "names file %s is not UTF-8 text" % path))
        return
    entries, ignored = parse_names(text, names)
    report["read"].append((path, entries))
    report["ignored"] += ignored


def read_names_dir(path, names, report):
    """Every file directly in the directory, in name order (a later file wins
    for an id both define); hidden files and editor or package leftovers are
    skipped, so a writer can rename a hidden temporary file into place."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        report["refused"].append((path, "names directory %s cannot be read: %s"
                                  % (path, exc.strerror or exc)))
        return
    if stat.S_ISLNK(info.st_mode):
        report["refused"].append((path, "names directory %s is a symbolic link; name the "
                                  "directory itself" % path))
        return
    if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        # whoever may add a file to it chooses what readers are told
        report["refused"].append((path, "names directory %s must belong to root and be "
                                  "writable by root only (chmod 755 or 700)" % path))
        return
    try:
        entries = sorted(os.listdir(path))
    except OSError as exc:
        report["refused"].append((path, "names directory %s cannot be read: %s"
                                  % (path, exc.strerror or exc)))
        return
    entries = [e for e in entries if not e.startswith(".") and not e.endswith(NAMES_SKIP)]
    if len(entries) > NAMES_MAX_FILES:
        report["refused"].append((path, "names directory %s holds more than %d files; only the "
                                  "first %d were read" % (path, NAMES_MAX_FILES, NAMES_MAX_FILES)))
    for entry in entries[:NAMES_MAX_FILES]:
        read_names_file(os.path.join(path, entry), names, report)


def load_names(site, wazuh):
    """Read the account names map into NAMES; returns the problems, for warnings.

    names_file in the settings file: one or more paths (comma or space
    separated), each a file or a directory, read in the order given; a later
    entry wins for an id two of them define. Not set: etc/jt-packs/
    jt-alert-digest-names and the directory jt-alert-digest-names.d next to
    it, whichever exist. names_file = off turns the map off.
    """
    NAMES.clear()
    report = {"read": [], "refused": [], "entries": 0, "ignored": 0, "off": False}
    NAMES_REPORT.clear()
    NAMES_REPORT.update(report)
    setting = (site.get("names_file") or "").strip()
    if setting.lower() in ("off", "no", "none"):
        NAMES_REPORT["off"] = True
        return []
    explicit = bool(setting)
    paths = split_list(setting) if explicit else [os.path.join(wazuh, NAMES_FILE),
                                                  os.path.join(wazuh, NAMES_DIR)]
    names = {}
    for path in paths:
        try:
            info = os.lstat(path)
        except OSError as exc:
            if explicit:
                report["refused"].append((path, "names_file %s cannot be read: %s"
                                          % (path, exc.strerror or exc)))
            continue
        if stat.S_ISDIR(info.st_mode):
            read_names_dir(path, names, report)
        else:
            read_names_file(path, names, report)
    NAMES.update(names)
    report["entries"] = len(names)
    NAMES_REPORT.update(report)
    return [problem for _, problem in report["refused"]]


def lookup_name(value):
    """(id, name) when the whole value is a key of the map, else None."""
    if not NAMES:
        return None
    key = name_key(value)
    name = NAMES.get(key)
    return (key, name) if name else None


def shown_name(key, name):
    """The name with enough of the id to tell two people of one name apart and
    to find the id in the log: "Alice (3094106c...)", for a SID its last part,
    the account's relative id: "Alice (...-1104)"."""
    if SID_ID.match(key):
        return "%s (…-%s)" % (name, key.rsplit("-", 1)[1])
    if len(key) <= 8:
        return "%s (%s)" % (name, key)
    return "%s (%s…)" % (name, key[:8])


def name_tokens(text, found=None):
    """Each UUID or SID token of text that the map knows, shown by name."""
    if not NAMES or not text:
        return text

    def swap(match):
        hit = lookup_name(match.group(1))
        if not hit:
            return match.group(0)
        if found is not None:
            found[hit[0]] = hit[1]
        return shown_name(*hit)
    return ID_TOKEN.sub(swap, str(text))


def name_value(value, found=None):
    """An account value shown by name: the whole value, the account part of
    DOMAIN\\account, the value before a trailing "(...)" such as Sysmon's
    integrity level, else its UUID or SID tokens."""
    if not NAMES:
        return value
    text = str(value)
    hit = lookup_name(text)
    if hit:
        if found is not None:
            found[hit[0]] = hit[1]
        return shown_name(*hit)
    if "\\" in text:
        domain, _, account = text.rpartition("\\")
        hit = lookup_name(account)
        if hit:
            if found is not None:
                found[hit[0]] = hit[1]
            return "%s\\%s" % (domain, shown_name(*hit))
    suffix = re.match(r"^(.+?)( \([^()]*\))$", text)
    if suffix:
        inner = {}
        shown = name_value(suffix.group(1), inner)
        if inner:
            if found is not None:
                found.update(inner)
            return shown + suffix.group(2)
    return name_tokens(text, found)


def account_sources(alert):
    """(label, value) of the decoded fields that name an account, for a row of
    its own when the map knows the value and nothing shown carries it yet."""
    data = alert.get("data") or {}
    out = [("Account", data.get("dstuser")), ("Source account", data.get("srcuser")),
           ("Account", data.get("user"))]
    win = data.get("win")
    if isinstance(win, dict):
        event = win.get("eventdata") or {}
        out += [("Account", event.get(k)) for k in ("targetUserName", "targetSid", "targetUserSid")]
        out += [("By", event.get(k)) for k in ("subjectUserName", "subjectUserSid")]
        out += [("Member", event.get(k)) for k in ("memberName", "memberSid")]
    return [(label, unwin(value).strip()) for label, value in out
            if isinstance(value, str) and value.strip() not in ("", "-")]


def account_rows(fields, alert):
    """(label, value, shown, names) per field: shown is the value with the map
    applied (account rows only), names the ids it resolved. Without a map,
    shown is the value and nothing is added."""
    if not NAMES:
        return [(label, value, value, {}) for label, value in fields]
    rows = []
    for label, value in fields:
        found = OrderedDict()
        shown = value
        if label in ACCOUNT_LABELS:
            by = re.match(r"^(.*  as )(.+)$", str(value)) if label == "By" else None
            shown = (by.group(1) + name_value(by.group(2), found)) if by \
                else name_value(value, found)
        rows.append((label, value, shown, found))
    if alert.get("syscheck"):
        return rows
    for label, value in account_sources(alert):
        found = OrderedDict()
        shown = name_value(value, found)
        if not found or any(r[0] == label for r in rows) or \
                any(value in str(r[1]) for r in rows if r[0] != "Log"):
            continue
        at = next((i for i, r in enumerate(rows) if r[0] == "Log"), len(rows))
        rows.insert(at, (label, trim(value), trim(shown, MAX_FIELD + NAME_MAX), found))
    return rows


class Batch(object):
    """What one run read: the groups to mail and the counts behind them."""

    def __init__(self, options):
        self.options = options
        self.groups = OrderedDict()
        self.total = 0
        self.oldest = None
        self.levels = {}
        self.excluded = 0
        self.unparsed = 0
        self.health = []
        self.more = False
        self.lost = []
        self.cutoff = None          # alerts older than this are counted, not collected
        self.dropped = 0
        self.dropped_first = None
        self.dropped_last = None

    def qualifies(self, rule, level):
        """rule.mail is analysisd's own verdict (email_alert_level, alert_by_email,
        no_email_alert), so it is honoured unless a level was set explicitly."""
        if self.options.get("forced"):
            return level >= self.options["level"]
        if "mail" in rule:
            return rule.get("mail") is True
        return level >= self.options["level"]

    def take(self, raw):
        """One line of alerts.json; True if it was collected for mail."""
        raw = raw.strip()
        if not raw:
            return False
        learn_agent(raw)
        hint = LEVEL_HINT.search(raw, 0, 600)
        if hint and not HEALTH_HINT.search(raw):
            level = int(hint.group(1))
            below = level < self.options["level"]
            if below and (self.options.get("forced") or not MAIL_HINT.search(raw)):
                self.levels[level] = self.levels.get(level, 0) + 1
                return False
        try:
            alert = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            self.unparsed += 1
            return False
        if not isinstance(alert, dict):
            self.unparsed += 1
            return False
        rule = alert.get("rule") or {}
        try:
            level = int(rule.get("level", 0))
        except (TypeError, ValueError):
            return False
        self.levels[level] = self.levels.get(level, 0) + 1
        rule_id = str(rule.get("id", "?"))
        if agent_event(alert):
            self.health.append(alert)
        if not self.qualifies(rule, level):
            return False
        agent = alert.get("agent") or {}
        if rule_id in self.options.get("exclude_rules", ()) or \
                str(agent.get("name", "")) in self.options.get("exclude_agents", ()) or \
                str(agent.get("id", "")) in self.options.get("exclude_agents", ()):
            self.excluded += 1
            return False
        stamp = parse_ts(alert.get("timestamp"))
        if self.cutoff is not None and stamp is not None and stamp < self.cutoff:
            self.dropped += 1
            when = alert.get("timestamp")
            if self.dropped_first is None or when < self.dropped_first:
                self.dropped_first = when
            if self.dropped_last is None or when > self.dropped_last:
                self.dropped_last = when
            return False
        add_alert(self.groups, alert, rule, level)
        self.total += 1
        if stamp is not None and (self.oldest is None or stamp < self.oldest[0]):
            self.oldest = (stamp, alert.get("timestamp"))
        return True


def read_alerts(segments, batch, limit=None):
    """Feed the new lines to batch; return the position to resume from.

    Bytes, not text: tell() is disabled while a text file is being iterated,
    which turned 1.3's backlog ceiling into a crash that stalled the reader.
    And only complete lines: analysisd flushes alerts.json once a second, so
    the last line of the current file can be half an alert, and 1.3 skipped
    it for good. A rotated file is closed and complete, so its last line is
    taken whole.
    """
    limit = MAX_ALERTS if limit is None else limit
    position = where(segments[0], segments[0]["offset"])
    for segment in segments:
        offset = segment["offset"]
        position = where(segment, offset)
        try:
            with open_segment(segment["path"], segment["gz"]) as fh:
                if offset:
                    fh.seek(offset)
                pending = b""
                while True:
                    chunk = fh.read(CHUNK)
                    if not chunk:
                        break
                    lines = (pending + chunk).split(b"\n")
                    pending = lines.pop()
                    for raw in lines:
                        offset += len(raw) + 1
                        if batch.take(raw) and batch.total >= limit:
                            batch.more = True
                            return where(segment, offset)
                if pending and not segment["current"]:
                    offset += len(pending)
                    batch.take(pending)
        except (OSError, EOFError) as exc:
            if segment["current"]:
                raise
            batch.lost.append("the rotated alert file %s could not be read past byte %d (%s)"
                              % (segment["rel"], offset, exc))
        position = where(segment, offset)
    return position


def parse_ts(value):
    """2026-10-11T08:00:39.123+0800 -> epoch seconds, else None."""
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt).timestamp()
        except (TypeError, ValueError):
            pass
    try:
        return time.mktime(time.strptime(value[:19], "%Y-%m-%dT%H:%M:%S"))
    except (TypeError, ValueError):
        return None


def alert_kind(alert):
    if alert.get("syscheck"):
        return "fim"
    data = alert.get("data") or {}
    if isinstance(data.get("vulnerability"), dict):
        return "vulnerability"
    if isinstance(data.get("container_vuln"), dict) and data["container_vuln"].get("type") == "image":
        return "container"
    if isinstance(data.get("win"), dict):
        return "windows"
    return "other"


def _score(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# Manager scripts that report on agents, by the field their events live under.
REPORT_FIELDS = ("jt_php", "jt_runtime", "jt_zimbra_baseline")


def reported_agent(alert):
    """The agent an alert is about. Usually the agent that sent it; a manager
    script that reports on agents (jt-php's and jt-runtime-vuln's version
    checks, jt-zimbra's baseline check) writes events as the manager, because
    analysisd drops queue events that claim an agent's identity, and names the
    agent in its own fields instead."""
    agent = alert.get("agent") or {}
    if str(agent.get("id", "")) != "000":
        return agent
    data = alert.get("data") or {}
    for field in REPORT_FIELDS:
        report = data.get(field)
        if isinstance(report, dict) and report.get("agent_name"):
            return {"id": str(report.get("agent_id") or ""), "name": str(report["agent_name"]),
                    "ip": str(report.get("agent_ip") or "")}
    return agent


def add_alert(groups, alert, rule, level):
    agent = reported_agent(alert)
    key = (str(rule.get("id", "?")), str(agent.get("name", "?")))
    group = groups.get(key)
    if group is None:
        mitre = rule.get("mitre") or {}
        ids, tactics = mitre.get("id") or [], mitre.get("tactic") or []
        group = groups[key] = {
            "level": level,
            "agent_id": str(agent.get("id", "")),
            "agent_ip": str(agent.get("ip", "")),
            "labels": agent.get("labels") if isinstance(agent.get("labels"), dict) else {},
            "descriptions": [],
            "mitre": [ids] if isinstance(ids, str) else list(ids),
            "tactics": [tactics] if isinstance(tactics, str) else list(tactics),
            "count": 0,
            "first": alert.get("timestamp", ""),
            "last": alert.get("timestamp", ""),
            "samples": [],
            "kind": alert_kind(alert),
            "vulns": OrderedDict(),
            "images": OrderedDict(),
        }
    group["level"] = max(group["level"], level)
    group["count"] += 1
    group["last"] = alert.get("timestamp", group["last"])
    description = rule.get("description", "")
    if description and description not in group["descriptions"] \
            and len(group["descriptions"]) < 50:
        group["descriptions"].append(description)
    if group["kind"] == "vulnerability":
        vuln = (alert.get("data") or {}).get("vulnerability") or {}
        package = vuln.get("package") or {}
        name = " ".join(str(v) for v in (package.get("name"), package.get("version")) if v) or "?"
        if name in group["vulns"] or len(group["vulns"]) < 100:
            entry = group["vulns"].setdefault(name, {"cves": [], "max": None,
                                                     "arch": package.get("architecture", "")})
            cve = vuln.get("cve")
            if cve and cve not in entry["cves"] and len(entry["cves"]) < 500:
                entry["cves"].append(cve)
            score = _score((vuln.get("score") or {}).get("base")) or \
                _score(((vuln.get("cvss") or {}).get("cvss3") or {}).get("base_score"))
            if score is not None and (entry["max"] is None or score > entry["max"]):
                entry["max"] = score
    if group["kind"] == "container":
        record = (alert.get("data") or {}).get("container_vuln") or {}
        image = str(record.get("image") or record.get("image_id") or "?")
        if image in group["images"] or len(group["images"]) < 100:
            group["images"][image] = {"msg": str(record.get("msg") or image),
                                      "containers": str(record.get("containers") or "")}
    if len(group["samples"]) < MAX_SAMPLES:
        group["samples"].append(alert)


def collect(alerts_path, state_path, min_level):
    """Return (groups, total, position) for the alerts after the saved position.

    Kept for callers of 1.3; the state may be 1.3's bare number or 1.4's JSON.
    """
    state, problem = load_state(state_path)
    if problem or state is None:
        return OrderedDict(), 0, end_position(alerts_path)
    segments, _ = plan(alerts_path, state["pos"])
    batch = Batch({"level": min_level, "forced": True})
    position = read_alerts(segments, batch)
    return batch.groups, batch.total, position


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

def fresh_state(position):
    return {"v": 2, "pos": position, "mailed": {}, "held": {},
            "seen": {"start": now(), "pairs": {}, "rules": {}}, "sent": [],
            "daily": None}


def load_state(path):
    """(state, problem). state None with no problem: no state yet (first run).

    1.3 wrote a bare byte offset; it is read as a position with no inode.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, "the state file %s cannot be read: %s" % (path, exc.strerror or exc)
    body = body.strip()
    if re.match(r"^\d+$", body):
        try:
            written = os.stat(path).st_mtime
        except OSError:
            written = None
        state = fresh_state({"legacy": True, "offset": int(body), "mtime": written})
        state["seen"]["start"] = now()
        return state, None
    try:
        state = json.loads(body)
    except ValueError:
        state = None
    if not isinstance(state, dict) or state.get("v") != 2 or not isinstance(state.get("pos"), dict):
        return None, "the state file %s is unreadable" % path
    for key, default in (("mailed", {}), ("held", {}), ("sent", []),
                         ("seen", {"start": now(), "pairs": {}, "rules": {}})):
        if not isinstance(state.get(key), type(default)):
            state[key] = default
    return state, None


def save_state(path, state):
    """Written in full, synced, then renamed over the old one."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, separators=(",", ":"))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def gkey(rule_id, agent):
    return "%s|%s" % (rule_id, agent)


def prune(state, repeat=3600):
    t = now()
    seen = state["seen"]
    for table in ("pairs", "rules"):
        seen[table] = {k: v for k, v in (seen.get(table) or {}).items() if t - v < TRACK_FOR}
    keep = max(86400, 2 * repeat)
    state["mailed"] = {k: v for k, v in state["mailed"].items()
                       if isinstance(v, list) and len(v) == 2 and t - v[0] < keep}
    state["sent"] = [s for s in state["sent"] if t - s < 3600]
    reported = state.get("lost") if isinstance(state.get("lost"), dict) else {}
    state["lost"] = {k: v for k, v in reported.items() if t - v < ESCALATE_EVERY}


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------

def clock(timestamp):
    """2026-09-16T08:00:39.123+0800 -> 08:00:39"""
    if not timestamp:
        return "?"
    parts = timestamp.split("T")
    if len(parts) < 2:
        return timestamp
    return parts[1].split(".")[0].split("+")[0]


def day(timestamp):
    return timestamp.split("T")[0] if "T" in timestamp else timestamp


def zone(timestamp):
    """The UTC offset an alert timestamp carries, as UTC+08:00."""
    match = re.search(r"([+-])(\d{2}):?(\d{2})$", timestamp or "")
    return "UTC%s%s:%s" % match.groups() if match else ""


SEVERITY_MARKER = re.compile(r"^\[(?:CRITICAL|HIGH|WARN|WARNING|INFO|LOW)\]\s*")
TOKEN_CHAR = re.compile(r"[\w.]")


def shared_prefix(values):
    """The part of a description that belongs to the rule, not to one alert.

    Wazuh interpolates $(field) into <description>, so every alert from one
    rule carries a different string. Taking the first one puts a single
    alert's address or path into a heading that covers a dozen of them,
    which is worse than saying less. The cut never falls inside a token:
    a common prefix of CVE ids is "CVE-202", which is half of every value.
    """
    values = [SEVERITY_MARKER.sub("", v) for v in values if v]
    if not values:
        return ""
    if len(set(values)) == 1:
        return values[0]
    low, high = min(values), max(values)
    index = 0
    while index < len(low) and index < len(high) and low[index] == high[index]:
        index += 1
    prefix = low[:index]
    following = low[index:index + 1] + high[index:index + 1]
    if prefix and TOKEN_CHAR.match(prefix[-1]) and any(TOKEN_CHAR.match(c) for c in following):
        prefix = re.sub(r"[\w.]+$", "", prefix)
    prefix = prefix.rstrip()
    while prefix and prefix[-1] in ":-,(/=":
        prefix = prefix[:-1].rstrip()
    return prefix + " ..." if index < len(low) and prefix else prefix


def reduce_names(text, names):
    for name in names:
        text = text.replace(name, "")
    return text


KIND_LABEL = {"vulnerability": "Vulnerabilities detected", "fim": "File integrity changes",
              "windows": "Windows events", "container": "Container image vulnerabilities"}


def heading(group, rule_id="?"):
    """The group's title; a generic label when the descriptions share too little."""
    descriptions = group.get("descriptions") or []
    if group.get("kind") == "container" and group.get("images"):
        # each image is listed on its own line; the title says what they share
        names = sorted(group["images"], key=len, reverse=True)
        descriptions = [" ".join(reduce_names(d, names).split()) for d in descriptions]
    text = shared_prefix(descriptions)
    if len(text.replace(" ...", "").strip()) >= 8:
        return redact(text)
    return KIND_LABEL.get(group.get("kind"), "Rule %s (descriptions vary)" % rule_id)


def trim(value, limit=MAX_FIELD):
    """At most limit characters, the ellipsis included: platform limits are
    hard (Slack refuses a whole message for one 151-character header)."""
    value = " ".join(str(value).split())
    return value if len(value) <= limit else value[:limit - 3] + "..."


def trim_words(value, limit):
    value = " ".join(str(value).split())
    if len(value) <= limit:
        return value
    cut = value[:limit - 3]
    if " " in cut[limit // 2:]:
        cut = cut[:cut.rfind(" ")]
    return cut.rstrip(" ,.:;-") + "..."


def ascii_only(value):
    return str(value).encode("ascii", "ignore").decode("ascii")


def clean_header(value):
    """No CR or LF reaches a header (CVE-2024-6923 is the library-side fix)."""
    return " ".join(str(value).replace("\r", " ").replace("\n", " ").split())


def unwin(value):
    """Eventchannel values carry every backslash twice (CLAUDE.md pitfall 4)."""
    return str(value).replace("\\\\", "\\")


def windows_fields(win):
    system = win.get("system") or {}
    data = win.get("eventdata") or {}
    provider = str(system.get("providerName") or "")
    event_id = str(system.get("eventID") or "")
    out = []

    def get(*keys):
        for key in keys:
            value = data.get(key)
            if value not in (None, "", "-"):
                return unwin(value).strip()
        return ""

    def add(label, value):
        if value:
            out.append((label, trim(redact(value))))

    short = provider or str(system.get("channel") or "Windows")
    for needle, name in (("Sysmon", "Sysmon"), ("Windows Defender", "Defender"),
                         ("Security-Auditing", "Security"), ("PowerShell", "PowerShell")):
        if needle in provider:
            short = name
            break
    label = "%s %s" % (short, event_id)
    message = str(system.get("message") or "").strip().strip('"')
    first_line = message.split("\r")[0].split("\n")[0].strip().rstrip(":")
    if short == "Sysmon" and 0 < len(first_line) <= 60:
        label += ", " + first_line
    out.append(("Event", label))
    sha256 = re.search(r"SHA256=([0-9A-Fa-f]{64})", get("hashes") or "")
    sha256 = sha256.group(1) if sha256 else ""

    if short == "Sysmon":
        if event_id == "1":
            add("Process", get("image"))
            add("Command", get("commandLine"))
            add("Parent", get("parentImage"))
            user = get("user")
            if user and get("integrityLevel"):
                user += " (%s)" % get("integrityLevel")
            add("User", user)
            add("SHA256", sha256)
        elif event_id == "3":
            add("Process", get("image"))
            flow = "%s:%s -> %s:%s" % (get("sourceIp"), get("sourcePort"),
                                       get("destinationIp"), get("destinationPort"))
            if get("destinationIp"):
                add("Connection", flow + (" " + get("protocol") if get("protocol") else ""))
            add("User", get("user"))
        elif event_id in ("11", "15", "23", "26", "29"):
            add("File", get("targetFilename"))
            add("Process", get("image"))
            add("User", get("user"))
            add("SHA256", sha256)
        elif event_id == "22":
            add("Query", get("queryName"))
            add("Process", get("image"))
        elif event_id in ("12", "13", "14"):
            add("Registry", get("targetObject"))
            add("Value", get("details"))
            add("Process", get("image"))
        elif event_id == "7":
            add("Loaded", get("imageLoaded"))
            add("Process", get("image"))
        elif event_id in ("8", "10"):
            add("Source", get("sourceImage"))
            add("Target", get("targetImage"))
            add("Access", get("grantedAccess"))
        else:
            add("Process", get("image"))
            add("User", get("user"))
    elif short == "Defender":
        add("Threat", get("threat Name"))
        add("Path", get("path"))
        add("Action", get("action Name"))
        add("User", get("detection User"))
        add("Process", get("process Name"))
    elif event_id == "4688":
        add("Process", get("newProcessName"))
        add("Command", get("commandLine"))
        add("Parent", get("parentProcessName"))
        add("Account", get("subjectUserName"))
    elif event_id in ("4624", "4625", "4648", "4672", "4768", "4771", "4776"):
        account = get("targetUserName", "subjectUserName")
        if account and get("targetDomainName"):
            account = "%s\\%s" % (get("targetDomainName"), account)
        add("Account", account)
        source = host_label(get("ipAddress")) if get("ipAddress") else None
        if get("workstationName"):
            source = ("%s (%s)" % (source, get("workstationName"))) if source else get("workstationName")
        add("Source", source)
        add("Logon type", get("logonType"))
        add("Process", get("processName"))
        add("Status", get("failureReason", "subStatus", "status"))
    elif short == "PowerShell" and event_id == "4104":
        add("Script", get("scriptBlockText"))
    if len(out) == 1 and first_line:
        add("Message", first_line)
    return out


def interesting_fields(alert):
    """The handful of fields that say what this alert was about.

    Chosen per alert shape rather than printed wholesale: a file integrity
    event and a web access log have nothing in common, and printing every
    decoded field is exactly what makes the stock mail unreadable. Every
    value is passed through redact() before it is shown.
    """
    out = []

    syscheck = alert.get("syscheck")
    if syscheck:
        out.append(("File", redact("%s  (%s)" % (syscheck.get("path", "?"),
                                                 syscheck.get("event", "?")))))
        attributes = []
        if syscheck.get("perm_after"):
            attributes.append(syscheck["perm_after"])
        owner = syscheck.get("uname_after") or syscheck.get("uid_after")
        group = syscheck.get("gname_after") or syscheck.get("gid_after")
        if owner:
            attributes.append("%s:%s" % (owner, group) if group else str(owner))
        if syscheck.get("size_after"):
            try:
                attributes.append("{:,} bytes".format(int(syscheck["size_after"])))
            except (TypeError, ValueError):
                attributes.append(str(syscheck["size_after"]))
        if attributes:
            out.append(("Attributes", "  ".join(str(a) for a in attributes)))
        digest = syscheck.get("sha256_after")
        if digest:
            out.append(("SHA256", "%s...%s" % (digest[:16], digest[-8:])))
        if syscheck.get("changed_attributes"):
            out.append(("Changed", ", ".join(syscheck["changed_attributes"])))
        audit = syscheck.get("audit") or {}
        who = (audit.get("effective_user") or {}).get("name") \
            or (audit.get("user") or {}).get("name")
        process = (audit.get("process") or {}).get("name")
        if who or process:
            out.append(("By", "%s  as %s" % (process or "?", who or "?")))
        return out

    data = alert.get("data") or {}

    vuln = data.get("vulnerability")
    if isinstance(vuln, dict):
        package = vuln.get("package") or {}
        out.append(("Package", " ".join(str(v) for v in (package.get("name"), package.get("version"),
                                                          package.get("architecture")) if v)))
        score = (vuln.get("score") or {}).get("base") or \
            ((vuln.get("cvss") or {}).get("cvss3") or {}).get("base_score")
        rating = ", ".join(str(v) for v in (vuln.get("severity"),
                                             ("CVSS %.1f" % _score(score)) if _score(score) is not None else None)
                           if v)
        out.append(("CVE", "%s%s" % (vuln.get("cve", "?"), ("  " + rating) if rating else "")))
        if vuln.get("status") and vuln.get("status") != "Active":
            out.append(("Status", vuln["status"]))
        return out

    win = data.get("win")
    if isinstance(win, dict):
        return windows_fields(win)

    if data.get("vhost") or data.get("request") or data.get("http_status"):
        source = data.get("remote_addr") or data.get("srcip") \
            or alert.get("srcip") or "?"
        out.append(("Source", "%s  ->  %s" % (host_label(source), data.get("vhost", "?"))))
        request = data.get("request") or \
            ("%s %s" % (data.get("method", ""), data.get("path", ""))).strip()
        if request:
            out.append(("Request", trim(redact("%s   -> %s"
                                               % (request, data.get("http_status", "?"))))))
        if data.get("user_agent"):
            out.append(("Client", trim(redact(data["user_agent"]), 70)))
        return out

    # IDS events (Suricata via its EVE JSON). The raw log is one long JSON line
    # that says less than these five fields and, unbroken, overflowed the card.
    ids = data.get("alert") if isinstance(data.get("alert"), dict) else None
    if ids and (data.get("src_ip") or data.get("dest_ip")):
        if ids.get("signature"):
            out.append(("Signature", ids["signature"]))

        def endpoint(ip, port):
            return "%s:%s" % (ip, port) if port else str(ip or "?")
        flow = "%s  ->  %s" % (endpoint(data.get("src_ip"), data.get("src_port")),
                               endpoint(data.get("dest_ip"), data.get("dest_port")))
        if data.get("proto"):
            flow += "  " + str(data["proto"])
        out.append(("Flow", flow))
        verdict = ", ".join(str(v) for v in (ids.get("action"), ids.get("category")) if v)
        if verdict:
            out.append(("Action", verdict))
        if data.get("in_iface"):
            out.append(("Interface", str(data["in_iface"])))
        return out

    audit = data.get("audit") or {}
    if audit:
        name = (audit.get("file") or {}).get("name")
        if name:
            out.append(("File", redact(name)))
        if audit.get("exe"):
            out.append(("Exec", redact(audit["exe"])))
        command = (audit.get("execve") or {})
        if isinstance(command, dict) and command:
            args = [command[k] for k in sorted(command, key=lambda k: (len(k), k))
                    if re.match(r"^a\d+$", k)]
            if args:
                out.append(("Command", trim(redact(" ".join(str(a) for a in args)))))
        who = (audit.get("effective_user") or {}).get("name") or audit.get("auid")
        if who:
            out.append(("User", str(who)))
        if out:
            return out

    source = data.get("srcip") or alert.get("srcip")
    if source:
        out.append(("Source", host_label(source)))
    if data.get("dstuser"):
        out.append(("Account", data["dstuser"]))
    full_log = (alert.get("full_log") or "").strip()
    if full_log:
        out.append(("Log", trim(redact(full_log))))
    return out


def vuln_fields(group, packages=5, cves=10):
    """One line per package instead of one card per CVE.

    978 vulnerability alerts on one manager in eleven days rendered as
    "CVE-202 ..." with three full samples each and no package at all.
    """
    out = []
    items = sorted(group.get("vulns", {}).items(),
                   key=lambda kv: (-(kv[1]["max"] or 0), -len(kv[1]["cves"])))
    for name, entry in items[:packages]:
        count = len(entry["cves"])
        shown = ", ".join(entry["cves"][:cves])
        if count > cves:
            shown += " +%d" % (count - cves)
        score = (", max CVSS %.1f" % entry["max"]) if entry["max"] is not None else ""
        out.append(("Package", "%s%s: %d CVE%s%s: %s"
                    % (name, (" (%s)" % entry["arch"]) if entry.get("arch") else "",
                       count, "" if count == 1 else "s", score, shown)))
    if len(items) > packages:
        out.append(("More", "%d more packages" % (len(items) - packages)))
    return out


def image_fields(group, images=20):
    """One line per container image (jt-container-vuln), latest report of each.

    The scanner's first run on a host reports every image at once, all under
    one (rule, host) group; with samples only the first three would show.
    """
    items = list(group.get("images", {}).items())
    out = []
    for image, entry in items[:images]:
        line = trim(redact(entry["msg"]))
        if entry.get("containers"):
            line += "  [containers: %s]" % trim(redact(entry["containers"]), 120)
        out.append(("Image", line))
    if len(items) > images:
        out.append(("More", "%d more images" % (len(items) - images)))
    return out


def listed_in_full(group):
    """Groups whose card lists every alert, so no "N more" note applies."""
    return (group.get("kind") == "vulnerability" and bool(group.get("vulns"))) or \
        (group.get("kind") == "container" and bool(group.get("images")))


def ordered_groups(groups):
    return sorted(groups.items(),
                  key=lambda kv: (-kv[1]["level"], not kv[1].get("new"), -kv[1]["count"]))


def headline(group):
    span = clock(group["first"])
    if group["count"] > 1 and clock(group["last"]) != span:
        span = "%s-%s" % (span, clock(group["last"]))
    return "%s %s" % (day(group["first"]), span)


def host_detail(group):
    """Address and agent ID, the part a reader needs to find the machine.

    The first version showed only the agent name, in small grey capitals inside
    the level line, and a reader could not tell which host a message was about.
    """
    parts = []
    if group.get("agent_ip") and group["agent_ip"] not in ("any", "127.0.0.1"):
        parts.append(group["agent_ip"])
    if group.get("agent_id"):
        parts.append("agent " + group["agent_id"])
    return ", ".join(parts)


def host_names(groups, limit=5):
    names = sorted({k[1] for k in groups})
    shown = ", ".join(names[:limit])
    return shown + (" +%d" % (len(names) - limit) if len(names) > limit else "")


def mitre_line(group):
    if not group.get("mitre"):
        return ""
    line = "MITRE " + ", ".join(group["mitre"])
    if group.get("tactics"):
        line += " (%s)" % ", ".join(dedupe(group["tactics"]))
    return line


def badge(group):
    return {"pair": "NEW", "rule": "NEW RULE"}.get(group.get("new"), "")


def group_link(template, base, rule_id, group, agent):
    """A link to this group's alerts in the dashboard, or None."""
    if not template:
        return None
    first, last = parse_ts(group.get("first")), parse_ts(group.get("last"))
    if first is None:
        first = last = now()

    def iso(epoch):
        return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    values = {
        "base": base,
        "rule_id": quote(rule_id if re.match(r"^\d{1,8}$", rule_id) else "", safe=""),
        "agent_id": quote(group.get("agent_id", "") if re.match(r"^\d{1,8}$", group.get("agent_id", "")) else "",
                          safe=""),
        "agent": quote(agent, safe=""),
        "from": quote(iso(first - 300), safe=":-."),
        "to": quote(iso((last or first) + 300), safe=":-."),
    }
    try:
        url = template.format(**values)
    except (KeyError, IndexError, ValueError):
        return None
    return url if re.match(r"^https?://", url) else None


def samples_shown(count):
    """Fewer samples when there are many groups, so the message stays readable."""
    return 3 if count <= 5 else (2 if count <= 10 else 1)


def esc(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def sample_rows(group, samples):
    """Per sample shown, (label, value, shown, names) for each field: see account_rows."""
    if group.get("kind") == "vulnerability" and group.get("vulns"):
        return [[(label, value, value, {}) for label, value in vuln_fields(group)]]
    if group.get("kind") == "container" and group.get("images"):
        return [[(label, value, value, {}) for label, value in image_fields(group)]]
    return [account_rows(interesting_fields(sample), sample)
            for sample in group.get("samples", [])[:samples]]


def card_fields(group, samples):
    """The (label, value) rows of each sample shown, account names applied."""
    return [[(label, shown) for label, _, shown, _ in rows] for rows in sample_rows(group, samples)]


def title(group, rule_id="?"):
    """heading() as shown to a reader: ids the account names map knows, by name.
    heading() itself stays raw, for the state file and the webhook."""
    return name_tokens(heading(group, rule_id))


def html_card(index, rule_id, agent, group, samples, link=None):
    band = BAND.get(group["level"], BAND[12])
    divider = ('border-top:1px solid %s;' % LINE) if index else ''
    out = ['<div style="%spadding:16px 18px;border-left:4px solid %s;">' % (divider, band)]
    count = ('<span style="color:%s;">&nbsp;&times;%d</span>'
             % (MUTED, group["count"])) if group["count"] > 1 else ''
    mark = badge(group)
    if mark:
        count += ('&nbsp;&nbsp;<span style="color:#ffffff;background:%s;border-radius:3px;'
                  'padding:0 5px;letter-spacing:.06em;">%s</span>' % (NEWBADGE, mark))
    out.append(
        '<div style="font-size:12px;letter-spacing:.04em;'
        'text-transform:uppercase;color:%s;font-weight:700;">'
        'Level %d<span style="color:%s;font-weight:600;">'
        '&nbsp;&middot;&nbsp;rule %s</span>%s</div>'
        % (band, group["level"], MUTED, esc(rule_id), count))
    detail = host_detail(group)
    out.append(
        '<div style="margin:8px 0 2px;font-size:14px;">'
        '<span style="color:%s;font-size:12px;">Host</span>&nbsp;&nbsp;'
        '<span style="display:inline-block;font-family:%s;font-weight:700;font-size:15px;'
        'color:%s;background:#f1f5f9;border:1px solid #cbd5e1;border-radius:4px;'
        'padding:1px 8px;">%s</span>'
        '%s</div>'
        % (MUTED, MONO, INK, esc(agent),
           ('&nbsp;&nbsp;<span style="font-family:%s;font-size:13px;color:%s;">%s</span>'
            % (MONO, MUTED, esc(detail))) if detail else ''))
    out.append('<div style="margin:6px 0 2px;font-size:15px;line-height:1.45;'
               'font-weight:600;">%s</div>' % esc(title(group, rule_id)))
    meta = esc(headline(group))
    if group.get("mitre"):
        meta += '&nbsp;&middot;&nbsp;' + esc(mitre_line(group))
    if group.get("labels"):
        meta += '&nbsp;&middot;&nbsp;' + esc(", ".join(
            "%s=%s" % (k, v) for k, v in sorted(group["labels"].items())))
    out.append('<div style="font-size:12px;color:%s;margin-bottom:10px;">%s</div>' % (FAINT, meta))

    for position, fields in enumerate(card_fields(group, samples)):
        if position:
            out.append('<div style="height:1px;background:%s;margin:10px 0;"></div>' % LINE)
        # table-layout:fixed is what makes the value column wrap. With the
        # default automatic layout an unbroken token -- a JSON log line, a
        # long path -- widens the column past the card, and word-break in a
        # table cell is ignored.
        out.append('<table cellpadding="0" cellspacing="0" border="0" '
                   'style="width:100%;border-collapse:collapse;font-size:13px;'
                   'table-layout:fixed;">')
        for label, value in fields:
            long_value = label in ("Log", "Request", "File", "Exec", "Client", "Signature",
                                   "Command", "Process", "Parent", "Path", "Registry", "Value",
                                   "Script", "Message", "Package", "Query", "Loaded")
            style = ('display:block;font-family:%s;font-size:12px;background:%s;'
                     'padding:4px 6px;border-radius:4px;' % (MONO, PANEL)
                     if long_value else 'font-family:%s;font-size:12.5px;' % MONO)
            out.append(
                '<tr>'
                '<td style="padding:3px 10px 3px 0;color:%s;font-size:12px;'
                'white-space:nowrap;vertical-align:top;width:76px;">%s</td>'
                '<td style="padding:3px 0;vertical-align:top;'
                'word-break:break-word;overflow-wrap:anywhere;">'
                '<span style="%sword-break:break-word;overflow-wrap:anywhere;'
                'white-space:pre-wrap;">%s</span></td></tr>'
                % (MUTED, esc(label), style, esc(value)))
        out.append('</table>')

    shown = 0 if listed_in_full(group) \
        else min(samples, len(group.get("samples", [])))
    remaining = group["count"] - shown
    notes = []
    if remaining > 0 and shown:
        notes.append("%d more of the same not listed" % remaining)
    if group.get("earlier"):
        notes.append("plus %d earlier since the last full mail" % group["earlier"])
    if notes:
        out.append('<div style="margin-top:10px;font-size:12px;color:%s;">%s</div>'
                   % (FAINT, esc("; ".join(notes))))
    if link:
        out.append('<div style="margin-top:8px;font-size:12px;"><a href="%s" '
                   'style="color:#1d4ed8;text-decoration:none;">Open these alerts in the '
                   'dashboard</a></div>' % esc(link))
    out.append('</div>')
    return "\n".join(out)


def layout(groups, context):
    """Which groups get a detailed card, with how many samples each.

    Returns (items, detailed, samples). The worst case of 1.3 (40 groups,
    three samples each) came to about 300 KB of HTML; Gmail cuts a message at
    102 KB, which hid the end of the list and the dashboard link.
    """
    items = ordered_groups(groups)
    samples = samples_shown(len(items))
    size, detailed = 0, 0
    for index, ((rule_id, agent), group) in enumerate(items):
        if index >= MAX_GROUPS:
            break
        card = html_card(index, rule_id, agent, group, samples,
                         link_for(context, rule_id, agent, group))
        if detailed and size + len(card) > HTML_BUDGET:
            break
        size += len(card)
        detailed += 1
    return items, detailed, samples


def link_for(context, rule_id, agent, group):
    if not context or not context.get("link"):
        return None
    return group_link(context["link"], context.get("base", ""), rule_id, group, agent)


def opening(groups, total, min_level, held=None):
    if not groups and held:
        return ("No new rules or hosts: %d more alerts of %d groups already mailed"
                % (sum(e.get("n", 0) for e in held), len(held)))
    return ("%s at level %d or above, %s, %s: %s"
            % (plural(total, "alert"), min_level, plural(len(groups), "rule"),
               "host" if len({k[1] for k in groups}) == 1 else "hosts", host_names(groups)))


def plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def held_line(entry):
    since = time.strftime("%H:%M", time.localtime(entry.get("mailed") or now()))
    return ("L%d rule %s on %s: +%d since the full mail at %s (last %s) - %s"
            % (entry.get("level", 0), entry.get("rule", "?"), entry.get("agent", "?"),
               entry.get("n", 0), since, clock(entry.get("last", "")),
               name_tokens(entry.get("heading", ""))))


def render_text(groups, total, min_level, dashboard, context=None):
    """The plain text alternative.

    Deliberately not column aligned. The first version of this padded every
    label to a fixed width, which looks right in a terminal and is destroyed
    by the first mail client that rewraps a long line. Here the label ends in
    a colon and the value follows, so a rewrap costs nothing.
    """
    context = context or {}
    lines = [opening(groups, total, min_level, context.get("held"))]
    items, detailed, samples = layout(groups, context)
    first = items[0][1]["first"] if items else ""
    about = []
    if context.get("node"):
        about.append("From %s%s." % (context["node"], (" (%s)" % context["node_type"])
                                     if context.get("node_type") else ""))
    if zone(first):
        about.append("Times are the manager's local time (%s)." % zone(first))
    if about:
        lines.append(" ".join(about))
    lines.append("")
    if len(items) > 1:
        lines.append("Summary")
        for (rule_id, agent), group in items[:MAX_GROUPS]:
            lines.append("  L%d rule %s x%d %s - %s%s"
                         % (group["level"], rule_id, group["count"], agent,
                            trim(title(group, rule_id), 80),
                            ("  " + badge(group)) if badge(group) else ""))
        lines.append("")
    for index, ((rule_id, agent), group) in enumerate(items):
        if index >= detailed:
            left = len(items) - detailed
            if index >= MAX_GROUPS:
                lines.append("(%d more groups not listed)" % left)
            else:
                lines.append("(details of %d more groups left out to keep this message "
                             "below the size mail clients cut off)" % left)
            break
        count = "  x%d" % group["count"] if group["count"] > 1 else ""
        mark = ("  " + badge(group)) if badge(group) else ""
        lines.append("%s L%d  rule %s%s%s"
                     % (SEVERITY.get(group["level"], "[HIGH]"),
                        group["level"], rule_id, count, mark))
        detail = host_detail(group)
        lines.append("  Host: %s%s" % (agent, " (%s)" % detail if detail else ""))
        lines.append("  " + title(group, rule_id))
        stamp = "  " + headline(group)
        if group.get("mitre"):
            stamp += "   " + mitre_line(group)
        lines.append(stamp)
        if group.get("labels"):
            lines.append("  Labels: " + ", ".join("%s=%s" % (k, v)
                                                 for k, v in sorted(group["labels"].items())))
        for fields in card_fields(group, samples):
            for label, value in fields:
                lines.append("  %s: %s" % (label, value))
            lines.append("")
        shown = 0 if listed_in_full(group) \
            else min(samples, len(group.get("samples", [])))
        remaining = group["count"] - shown
        if remaining > 0 and shown:
            lines.append("  (%d more of the same not listed)" % remaining)
        if group.get("earlier"):
            lines.append("  (plus %d earlier since the last full mail)" % group["earlier"])
        link = link_for(context, rule_id, agent, group)
        if link:
            lines.append("  Dashboard: " + link)
        if remaining > 0 or group.get("earlier") or link:
            lines.append("")
    held = context.get("held") or []
    if held:
        lines.append("Still ongoing: repeats of groups already mailed in full, counted rather than "
                     "repeated (hold %d minutes)" % (context.get("repeat", 3600) // 60))
        for entry in held[:MAX_GROUPS]:
            lines.append("  " + held_line(entry))
        if len(held) > MAX_GROUPS:
            lines.append("  (%d more)" % (len(held) - MAX_GROUPS))
        lines.append("")
    if context.get("more"):
        lines.append("More alerts are waiting; the next run continues from here.")
        lines.append("")
    footer = []
    if context.get("node"):
        footer.append("sent by %s, jt-alert-digest %s" % (context["node"], VERSION))
    if dashboard:
        footer.append(dashboard)
    if footer:
        lines.append("--")
        lines.extend(footer)
    return "\n".join(lines)


def render_html(groups, total, min_level, dashboard, context=None):
    """A table holds its shape when the client rewraps; spaces do not."""
    context = context or {}
    items, detailed, samples = layout(groups, context)
    first = items[0][1]["first"] if items else ""
    about = []
    if context.get("node"):
        about.append("from %s%s" % (context["node"], (" (%s)" % context["node_type"])
                                    if context.get("node_type") else ""))
    if zone(first):
        about.append("times %s" % zone(first))
    out = [
        '<div style="margin:0;padding:20px 12px;background:#eef0f3;'
        'font-family:%s;color:%s;">' % (SANS, INK),
        '<div style="max-width:720px;margin:0 auto;background:#ffffff;'
        'border:1px solid %s;border-radius:10px;overflow:hidden;">' % LINE,
        '<div style="padding:14px 18px;border-bottom:1px solid %s;'
        'font-size:13px;color:%s;">' % (LINE, MUTED),
        '<span style="color:%s;font-weight:600;">Wazuh</span>&nbsp;&nbsp;%s%s'
        % (INK, esc(opening(groups, total, min_level, context.get("held"))),
           ('<br><span style="font-size:12px;color:%s;">%s</span>'
            % (FAINT, esc(", ".join(about)))) if about else ''),
        '</div>',
    ]
    if len(items) > 1:
        out.append('<div style="padding:10px 18px;border-bottom:1px solid %s;">'
                   '<table cellpadding="0" cellspacing="0" border="0" style="width:100%%;'
                   'border-collapse:collapse;font-size:12.5px;table-layout:fixed;">' % LINE)
        for (rule_id, agent), group in items[:MAX_GROUPS]:
            band = BAND.get(group["level"], BAND[12])
            mark = badge(group)
            out.append(
                '<tr><td style="width:34px;padding:2px 0;color:%s;font-weight:700;">L%d</td>'
                '<td style="width:120px;padding:2px 6px 2px 0;font-family:%s;'
                'overflow-wrap:anywhere;">%s</td>'
                '<td style="width:46px;padding:2px 0;color:%s;">&times;%d</td>'
                '<td style="padding:2px 0;overflow-wrap:anywhere;">%s%s</td></tr>'
                % (band, group["level"], MONO, esc(agent), MUTED, group["count"],
                   esc(trim(title(group, rule_id), 90)),
                   ('&nbsp;<span style="color:%s;font-weight:700;">%s</span>'
                    % (NEWBADGE, mark)) if mark else ''))
        out.append('</table></div>')

    for index, ((rule_id, agent), group) in enumerate(items):
        if index >= detailed:
            left = len(items) - detailed
            text = ("%d more groups not listed" % left) if index >= MAX_GROUPS else \
                ("Details of %d more groups left out to keep this message below the size "
                 "mail clients cut off" % left)
            out.append('<div style="padding:12px 18px;font-size:12px;color:%s;">%s</div>'
                       % (MUTED, esc(text)))
            break
        out.append(html_card(index, rule_id, agent, group, samples,
                             link_for(context, rule_id, agent, group)))

    held = context.get("held") or []
    if held:
        out.append('<div style="padding:12px 18px;border-top:1px solid %s;font-size:12.5px;">'
                   '<div style="color:%s;font-size:12px;margin-bottom:6px;">Still ongoing: '
                   'repeats of groups already mailed in full, counted rather than repeated '
                   '(hold %d minutes)</div>'
                   % (LINE, MUTED, context.get("repeat", 3600) // 60))
        for entry in held[:MAX_GROUPS]:
            out.append('<div style="font-family:%s;font-size:12px;padding:1px 0;'
                       'overflow-wrap:anywhere;">%s</div>' % (MONO, esc(held_line(entry))))
        if len(held) > MAX_GROUPS:
            out.append('<div style="color:%s;font-size:12px;">%d more</div>'
                       % (MUTED, len(held) - MAX_GROUPS))
        out.append('</div>')
    if context.get("more"):
        out.append('<div style="padding:12px 18px;border-top:1px solid %s;font-size:12px;'
                   'color:%s;">More alerts are waiting; the next run continues from here.</div>'
                   % (LINE, MUTED))
    footer = []
    if context.get("node"):
        footer.append(esc("sent by %s, jt-alert-digest %s" % (context["node"], VERSION)))
    if dashboard:
        footer.append('<a href="%s" style="color:#1d4ed8;text-decoration:none;">%s</a>'
                      % (esc(dashboard), esc(dashboard)))
    if footer:
        out.append('<div style="padding:12px 18px;border-top:1px solid %s;'
                   'font-size:12px;color:%s;">%s</div>' % (LINE, MUTED, "<br>".join(footer)))
    out.append('</div></div>')
    return "\n".join(out)


def subject(groups, total, held=None):
    """Kept to plain ASCII on purpose.

    A subject carrying an em dash or any other non-ASCII character is sent as
    a MIME encoded word, and a client that does not decode it in the list view
    shows the reader =?utf-8?b?... instead of the alert.
    """
    if not groups:
        entries = held or []
        top = max(entries, key=lambda e: (e.get("level", 0), e.get("n", 0))) if entries else {}
        text = trim_words(ascii_only(name_tokens(top.get("heading", ""))), 50)
        return clean_header("[Wazuh] Still ongoing: L%d %s - %s (+%d)"
                            % (top.get("level", 0), ascii_only(top.get("agent", "?")), text,
                               sum(e.get("n", 0) for e in entries)))
    (rule_id, agent), group = ordered_groups(groups)[0]
    text = title(group, rule_id)
    if ": " in text:
        text = text.split(": ")[0]
    text = trim_words(ascii_only(text).replace(" ...", ""), 62)
    extra = " +%d" % (len(groups) - 1) if len(groups) > 1 else ""
    new = "NEW " if any(g.get("new") for g in groups.values()) else ""
    return clean_header("[Wazuh] %sL%d %s - %s%s (%d)"
                        % (new, group["level"], ascii_only(agent), text, extra, total))


# --------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------

class DeliveryError(Exception):
    """kind: a short stable name; permanent: retrying cannot help (a refused key);
    malformed: the server refused the message's content, so resending the same
    message can never succeed (see channel_flush)."""

    def __init__(self, kind, text, permanent=False, malformed=False):
        Exception.__init__(self, text)
        self.kind = kind
        self.text = text
        self.permanent = permanent
        self.malformed = malformed     # the server refused this message itself, not the sender


def classify(exc):
    """A short, stable name for a failure, so a repeat is recognised as one."""
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        codes = sorted({str(code) for code, _ in exc.recipients.values()})
        return "rcpt-" + "-".join(codes)
    for cls, name in ((smtplib.SMTPSenderRefused, "sender"), (smtplib.SMTPDataError, "data"),
                      (smtplib.SMTPAuthenticationError, "auth"), (smtplib.SMTPHeloError, "helo"),
                      (smtplib.SMTPConnectError, "connect"), (smtplib.SMTPResponseException, "smtp")):
        if isinstance(exc, cls):
            return "%s-%s" % (name, exc.smtp_code)
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return "disconnected"
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return "not-supported"
    if isinstance(exc, getattr(ssl, "SSLCertVerificationError", ())):
        return "tls-verify"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, OSError):
        return "network"
    return "error"


def describe(exc):
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        parts = []
        for address, (code, reply) in exc.recipients.items():
            if isinstance(reply, bytes):
                reply = reply.decode("utf-8", "replace")
            parts.append("%s: %s %s" % (address, code, reply))
        text = "recipients refused: " + "; ".join(parts)
    elif isinstance(exc, smtplib.SMTPResponseException):
        reply = exc.smtp_error
        if isinstance(reply, bytes):
            reply = reply.decode("utf-8", "replace")
        text = "%s: %s %s" % (type(exc).__name__, exc.smtp_code, reply)
    else:
        text = "%s: %s" % (type(exc).__name__, exc)
    return trim(redact(text), 300)


SYSTEM_CA_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt",   # Debian, Ubuntu
                     "/etc/pki/tls/certs/ca-bundle.crt",      # RHEL, Rocky, Alma, Amazon
                     "/etc/ssl/ca-bundle.pem",                # SUSE
                     "/etc/ssl/cert.pem")                     # Alpine, BSD


def verifying_context(cafile=None):
    """A certificate-checking context that also works on Wazuh's own python.

    The framework python under /var/ossec has an empty CA store, so on it every
    verified connection fails ("self-signed certificate in certificate chain")
    unless the system bundle is loaded explicitly.
    """
    context = ssl.create_default_context(cafile=cafile)
    if not cafile and not context.cert_store_stats().get("x509_ca"):
        for bundle in SYSTEM_CA_BUNDLES:
            if os.path.isfile(bundle):
                try:
                    context.load_verify_locations(cafile=bundle)
                    break
                except (ssl.SSLError, OSError):
                    continue
    return context


def tls_context(options):
    if options.get("verify"):
        context = verifying_context(options.get("ca_file"))
    else:
        # Opportunistic, as Postfix's "may" and "encrypt": the traffic is
        # encrypted but the certificate is not checked. tls = verify checks it.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def smtp_open(options, timeout=20, notes=None):
    """A connected, greeted, encrypted (if asked) and authenticated session."""
    notes = notes if notes is not None else []
    tls = options.get("tls", "none")
    server = None
    try:
        if tls == "implicit":
            server = smtplib.SMTP_SSL(options["server"], options["port"], timeout=timeout,
                                      context=tls_context(options))
            notes.append("connected with TLS to %s:%d" % (options["server"], options["port"]))
        else:
            server = smtplib.SMTP(options["server"], options["port"], timeout=timeout)
            notes.append("connected to %s:%d" % (options["server"], options["port"]))
        code, reply = server.ehlo()
        notes.append("EHLO: %s %s" % (code, reply.decode("utf-8", "replace").splitlines()[0]
                                      if reply else ""))
        if tls in ("may", "required", "verify"):
            if server.has_extn("starttls"):
                server.starttls(context=tls_context(options))
                server.ehlo()
                notes.append("STARTTLS: encrypted%s" % (", certificate verified"
                                                        if options.get("verify") else ""))
            elif tls != "may":
                raise DeliveryError("tls-not-offered", "%s:%d does not offer STARTTLS, which "
                                    "tls = %s requires" % (options["server"], options["port"], tls))
            else:
                notes.append("STARTTLS: not offered, continuing without TLS (tls = may)")
        if options.get("user"):
            server.login(options["user"], options["password"])
            notes.append("AUTH: accepted for %s" % options["user"])
        return server
    except DeliveryError:
        _close(server)
        raise
    except (smtplib.SMTPException, OSError) as exc:
        _close(server)
        raise DeliveryError(classify(exc), describe(exc))


def _close(server):
    if server is None:
        return
    try:
        server.quit()
    except (smtplib.SMTPException, OSError):
        try:
            server.close()
        except OSError:
            pass


def deliver(message, options):
    """Send one message; raise DeliveryError when nobody received it.

    smtp_server may be a program, as for wazuh-maild ("full path to a
    sendmail-like executable"), which is run the way maild runs it: the
    message on stdin, no arguments unless sendmail_args says so.
    """
    server = options["server"]
    if server.startswith("/"):
        try:
            done = subprocess.run([server] + list(options.get("sendmail_args") or []),
                                  input=message.as_bytes(), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            raise DeliveryError("program", trim("%s: %s" % (server, exc), 300))
        if done.returncode != 0:
            raise DeliveryError("program-exit-%d" % done.returncode, trim(
                "%s exited with %d: %s" % (server, done.returncode,
                                           done.stderr.decode("utf-8", "replace")), 300))
        return {}
    session = smtp_open(options)
    try:
        refused = session.send_message(message, from_addr=options["email_from"],
                                       to_addrs=options["to"])
    except (smtplib.SMTPException, OSError) as exc:
        _close(session)
        raise DeliveryError(classify(exc), describe(exc))
    _close(session)
    return refused or {}


def build_message(line, text, html, options, context, total=None):
    message = EmailMessage()
    message["Subject"] = clean_header(ascii_only(line))
    message["From"] = clean_header("Wazuh <%s>" % options["email_from"])
    message["To"] = clean_header(", ".join(options["to"]))
    if options.get("reply_to"):
        message["Reply-To"] = clean_header(options["reply_to"])
    message["Date"] = formatdate(now(), localtime=True)
    domain = options["email_from"].rpartition("@")[2].strip(" >") or None
    if domain and not re.match(r"^[A-Za-z0-9.-]+$", domain):
        domain = None
    # RFC 5322 3.6.4; Gmail refuses mail without one. Not the host's name:
    # getfqdn() on a node is often only its short host name.
    message["Message-ID"] = make_msgid("jt-alert-digest", domain=domain)
    # RFC 3834: no vacation replies to a notifier, which would answer every digest.
    message["Auto-Submitted"] = "auto-generated"
    message["X-Auto-Response-Suppress"] = "All"
    if total is not None:
        message["X-Wazuh-Alerts"] = str(total)
    if context.get("node"):
        message["X-Wazuh-Node"] = clean_header(ascii_only(context["node"]))
    if options.get("idsname"):
        message["X-IDS-OSSEC"] = clean_header(ascii_only(options["idsname"]))
    # quoted-printable rather than 8bit: a relay that downgrades 8bit breaks a
    # DKIM signature (RFC 6376 5.3), and Defender's messages are localised.
    message.set_content(text, cte="quoted-printable")
    message.add_alternative(html, subtype="html", cte="quoted-printable")
    return message


# --------------------------------------------------------------------------
# Zulip: an optional second channel, independent of the mail
# --------------------------------------------------------------------------

ZULIP_KEYS = ("zulip_url", "zulip_email", "zulip_api_key_file", "zulip_stream", "zulip_topic",
              "zulip_summary_topic", "zulip_tls_verify", "zulip_ca_file", "zulip_max_backlog",
              "zulip_level", "zulip_daily")
ZULIP_LIMIT = 9000     # Zulip's default max_message_length is 10,000 characters
ZULIP_PARTS = 4        # one run never posts more than this many messages
ZULIP_TOPIC_MAX = 60   # Zulip's default max_topic_length


def build_zulip_options(site, warnings):
    """(options, fatal) for the Zulip channel; (None, []) when it is not configured.

    Any zulip_* key switches the channel on, so a half-written configuration
    is reported (rule 131126) instead of being silently ignored.
    """
    if not any(key in site for key in ZULIP_KEYS):
        return None, []
    fatal = []
    z = {}
    url = (site.get("zulip_url") or "").strip().rstrip("/")
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        parts, host = None, ""
    if not parts or not parts.netloc or parts.query or parts.fragment or not (
            parts.scheme == "https" or (parts.scheme == "http" and host in ("127.0.0.1", "localhost", "::1"))):
        # The API key travels with every request, so plain http is refused
        # except to this host itself.
        fatal.append("zulip_url must be an https:// address of the Zulip server")
    z["url"] = url
    z["email"] = (site.get("zulip_email") or "").strip()
    if "@" not in z["email"]:
        fatal.append("zulip_email must be the bot's e-mail address")
    z["key"] = None
    key_file = site.get("zulip_api_key_file")
    if not key_file:
        fatal.append("zulip_api_key_file is not set")
    else:
        key, problem = read_secret(key_file, "zulip_api_key_file")
        if problem:
            fatal.append(problem)
        elif not re.match(r"^[A-Za-z0-9_-]{8,256}$", key.strip()):
            fatal.append("zulip_api_key_file %s does not hold an API key on its first line" % key_file)
        else:
            z["key"] = key.strip()
    z["key_file"] = key_file
    z["stream"] = (site.get("zulip_stream") or "").strip()
    if not z["stream"]:
        fatal.append("zulip_stream is not set")
    z["topic"] = (site.get("zulip_topic") or "Wazuh alerts").strip()
    z["summary_topic"] = (site.get("zulip_summary_topic") or z["topic"]).strip()
    for key in ("topic", "summary_topic"):
        if len(z[key]) > ZULIP_TOPIC_MAX:
            warnings.append("zulip_%s is longer than %d characters and was shortened"
                            % (key, ZULIP_TOPIC_MAX))
            z[key] = z[key][:ZULIP_TOPIC_MAX]
    z["verify"] = True
    if site.get("zulip_tls_verify"):
        try:
            z["verify"] = _yes(site["zulip_tls_verify"])
        except ValueError:
            fatal.append("zulip_tls_verify must be yes or no")
    z["ca_file"] = site.get("zulip_ca_file") or None
    if z["ca_file"] and not os.access(z["ca_file"], os.R_OK):
        fatal.append("zulip_ca_file %s cannot be read" % z["ca_file"])
    z["max_backlog"] = 24 * 3600
    if site.get("zulip_max_backlog"):
        try:
            z["max_backlog"] = max(3600, _duration(site["zulip_max_backlog"]))
        except ValueError:
            warnings.append("zulip_max_backlog = %s ignored, using 24 hours" % site["zulip_max_backlog"])
    z["level"], z["daily"] = None, True
    if site.get("zulip_level"):
        try:
            z["level"] = int(site["zulip_level"])
            if not 0 <= z["level"] <= 16:
                raise ValueError(z["level"])
        except ValueError:
            z["level"] = None
            warnings.append("zulip_level = %s ignored" % site["zulip_level"])
    if site.get("zulip_daily"):
        try:
            z["daily"] = _yes(site["zulip_daily"])
        except ValueError:
            warnings.append("zulip_daily = %s ignored, the daily summary is posted" % site["zulip_daily"])
    return z, fatal


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the Authorization header to wherever it points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def zulip_context(z):
    if z.get("verify", True):
        context = verifying_context(z.get("ca_file"))
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def zulip_call(z, method, path, fields=None, timeout=20):
    """One Zulip API request with HTTP basic auth (bot e-mail, API key).

    Returns the decoded JSON on success; raises DeliveryError otherwise, with
    permanent=True for answers that retrying cannot change (a refused key, a
    bot that may not post, a channel that does not exist). The key is never
    part of a URL, a log line or an error text.
    """
    url = z["url"] + path
    body = None
    if fields and method == "GET":
        url += "?" + urlencode(fields)
    elif fields:
        body = urlencode(fields).encode("utf-8")
    request = urllib.request.Request(url, data=body, method=method)
    token = base64.b64encode(("%s:%s" % (z["email"], z["key"])).encode("utf-8")).decode("ascii")
    request.add_header("Authorization", "Basic " + token)
    request.add_header("User-Agent", "jt-alert-digest/" + VERSION)
    request.add_header("Accept", "application/json")
    if body is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
    handlers = [_NoRedirect()]
    if url.startswith("https:"):
        handlers.append(urllib.request.HTTPSHandler(context=zulip_context(z)))
    opener = urllib.request.build_opener(*handlers)

    def clean(text):
        text = str(text)
        if z.get("key"):
            text = text.replace(z["key"], REDACTED)
        return trim(redact(text.replace(token, REDACTED)), 300)

    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(1 << 20)
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(1 << 16) if exc.fp else b""
            data = json.loads(raw.decode("utf-8", "replace"))
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        code = re.sub(r"[^A-Z_]", "", str(data.get("code") or ""))[:40]
        message = data.get("msg") or exc.reason
        status = exc.code
        permanent = 300 <= status < 500 and status not in (408, 429)
        raise DeliveryError("http-%d%s" % (status, ("-" + code) if code else ""),
                            clean("HTTP %d%s: %s" % (status, (" " + code) if code else "", message)),
                            permanent=permanent)
    except urllib.error.URLError as exc:
        reason = exc.reason
        kind = classify(reason) if isinstance(reason, BaseException) else "network"
        raise DeliveryError(kind, clean("%s: %s" % (urlsplit(url).netloc, reason)))
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise DeliveryError(classify(exc), clean("%s: %s: %s" % (urlsplit(url).netloc,
                                                                   type(exc).__name__, exc)))
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        data = None
    if not isinstance(data, dict) or data.get("result") != "success":
        raise DeliveryError("bad-response", clean("unexpected answer from %s" % urlsplit(url).netloc))
    return data


def zulip_post(z, topic, content):
    """POST /api/v1/messages. type "stream" is accepted by every version; "channel"
    is only an alias from feature level 248 (Zulip 9.0)."""
    return zulip_call(z, "POST", "/api/v1/messages",
                      {"type": "stream", "to": z["stream"], "topic": topic, "content": content})


def md(text):
    """Alert text made inert in Zulip markdown, without backslashes.

    Descriptions, agent names and logs carry attacker-influenced text: a
    mention (@**all**) would notify everyone in the channel and a link could
    be disguised. Zulip does not honour backslash escapes (1.7 showed
    "sshd\\[4242\\]"), so each construct is broken instead: asterisks and
    backticks become look-alikes, and a zero-width space splits a link's "](",
    "__", "$$", "~~", a mention's "@" and a leading list or quote marker.
    """
    text = " ".join(str(text).split())
    text = text.replace("*", "\u2217").replace("`", "\u02cb")
    text = re.sub(r"@(?=[_\u2217])", "@\u200b", text)
    for pair in ("$$", "~~", "__"):
        text = text.replace(pair, pair[0] + "\u200b" + pair[1])
    text = text.replace("](", "]\u200b(")
    # A heading, quote or list marker only counts at the start of a line.
    return re.sub(r"^(>|[#+-](?=\s)|\d+[.)](?=\s))", "\u200b\\1", text)


def md_link(url):
    return url.replace(" ", "%20").replace("(", "%28").replace(")", "%29")


def fenced(lines):
    """Decoded fields in a code block: nothing inside is interpreted, so no
    escaping can be got wrong, and the block reads as it does in the mail."""
    body = "\n".join(lines)
    longest = max([len(run) for run in re.findall(r"~+", body)] or [0])
    fence = "~" * max(3, longest + 1)
    return "%stext\n%s\n%s" % (fence, body, fence)


# Zulip markdown, not the mail's layout: *x* is italic (an underscore is shown
# as is), a single newline is a line break, "> " quotes a block, and a
# ```spoiler block is collapsed until clicked.
LEVEL_MARK = ((14, "\U0001F534"), (12, "\U0001F7E0"), (10, "\U0001F7E1"), (0, "\U0001F535"))
# A row of squares in the level's colour above each title: Zulip has no
# headings and no larger text, so the bar is what makes a card's start stand out.
LEVEL_BAR = ((14, "\U0001F7E5"), (12, "\U0001F7E7"), (10, "\U0001F7E8"), (0, "\U0001F7E6"))
BAR_WIDTH = 10
CODE_LABELS = ("File", "Path", "Exec", "Command", "SHA256", "Process", "Parent", "Target",
               "Registry", "Loaded", "Script", "Request", "Query")


def level_mark(level):
    return next(mark for floor, mark in LEVEL_MARK if level >= floor)


def level_bar(level):
    return next(square for floor, square in LEVEL_BAR if level >= floor) * BAR_WIDTH


def md_code(text):
    """Inline code, which Zulip leaves uninterpreted; plain escaped text if it
    cannot be fenced safely."""
    text = " ".join(str(text).split())
    if not text or "`" in text:
        return md(text)
    return "`%s`" % text


def md_value(label, value):
    if label == "Image" and ": " in str(value):
        # jt-container-vuln: "<image>: <counts>"
        name, rest = str(value).split(": ", 1)
        return "%s %s" % (md_code(name), md(rest))
    if label in CODE_LABELS:
        # "path (modified)": only the path is code
        found = re.match(r"^(\S+)(\s+\(.*\))?$", " ".join(str(value).split()))
        if found:
            return md_code(found.group(1)) + ((" " + md(found.group(2))) if found.group(2) else "")
        return md_code(value)
    return md(value)


def md_quote(lines):
    return "\n".join("> " + line for line in lines)


TABLE_TEXT = 28   # widest value kept in the table on a phone; Zulip table cells never wrap
TABLE_CODE = 20   # the same for code, set in a wider monospace font


def text_width(text):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def fits_table(label, value):
    plain = " ".join(str(value).split())
    if "|" in plain or "\n" in str(value):
        return False
    code = label in CODE_LABELS or label == "Image"
    return text_width(plain) <= (TABLE_CODE if code else TABLE_TEXT)


def spoiler_text(title, values):
    """Collapsed block of wrapped text. A code block inside a spoiler does not
    wrap and has to be scrolled sideways on a phone."""
    return "```spoiler %s\n%s\n```" % (title, "\n\n".join(md(v) for v in values))


def zulip_group(rule_id, agent, group, samples, link=None, compact=False):
    """One group as a card: a title line, a two-column table of the short
    values, the long values as a quoted block below it, the raw log collapsed."""
    count = (" \u00d7%d" % group["count"]) if group["count"] > 1 else ""
    mark = (" \u00b7 **%s**" % badge(group)) if badge(group) else ""
    rule = ("[%s](%s)" % (md(rule_id), md_link(link))) if link else md(rule_id)
    if compact:
        return "- %s **L%d** \u00b7 **%s** \u00b7 rule %s%s \u00b7 %s" % (
            level_mark(group["level"]), group["level"], md(agent), rule, count,
            md(trim(title(group, rule_id), 90)))
    heading_ = SEVERITY_MARKER.sub("", title(group, rule_id))
    blocks = ["%s\n%s **L%d \u00b7 %s**%s%s" % (level_bar(group["level"]), level_mark(group["level"]),
                                               group["level"], md(heading_), count, mark)]
    rows, below = [], []

    def place(label, value, shown):
        if fits_table(label, value):
            rows.append("| %s | %s |" % (md(label), shown))
        else:
            below.append("**%s** %s" % (md(label), shown))

    detail = host_detail(group)
    if detail:
        place("Address", detail.replace(", ", " \u00b7 "), md(detail.replace(", ", " \u00b7 ")))
    when = re.sub(r"^\d{4}-", "", headline(group))
    place("Time", when, md(when))
    rows.append("| Rule | %s |" % rule)
    if group.get("mitre"):
        tactics = ", ".join(dedupe(group.get("tactics") or []))
        text = ", ".join(group["mitre"]) + ((" " + tactics) if tactics else "")
        place("MITRE", text, md(text))
    samples_fields = card_fields(group, samples)
    logs, extra = [], []
    for index, fields in enumerate(samples_fields):
        shown = [(label, value) for label, value in fields if label != "Log"]
        log = [value for label, value in fields if label == "Log"]
        if not shown:
            # nothing decoded: the log line is the content, so it stays visible
            extra.append(md_quote(md(value) for value in log))
            continue
        logs.extend(log)
        if index == 0:
            for label, value in shown:
                place(label, value, md_value(label, value))
        else:
            extra.append(md_quote("**%s** %s" % (md(label), md_value(label, value))
                                  for label, value in shown))
    blocks.append("\n".join(["| Host | %s |" % md(agent), "|:--|:--|"] + rows))
    if below:
        blocks.append(md_quote(below))
    blocks.extend(extra)
    if logs:
        blocks.append(spoiler_text("Log" if len(logs) == 1 else "Logs (%d)" % len(logs), logs))
    shown_count = 0 if listed_in_full(group) \
        else min(samples, len(group.get("samples", [])))
    notes = []
    if group["count"] - shown_count > 0 and shown_count:
        notes.append("%d more of the same" % (group["count"] - shown_count))
    if group.get("earlier"):
        notes.append("plus %d earlier since the last full post" % group["earlier"])
    if notes:
        blocks.append("*(%s)*" % "; ".join(notes))
    return "\n\n".join(blocks)


FENCE_LINE = re.compile(r"^(`{3,}|~{3,})(.*)$")


def cut_block(block, limit):
    """Shorten one block to fit a message, closing every block left open."""
    out, size, open_fences = [], 0, []
    for line in block.split("\n"):
        if size + len(line) + 1 > limit - 60 - 4 * len(open_fences):
            break
        out.append(line)
        size += len(line) + 1
        found = FENCE_LINE.match(line)
        if found:
            fence, rest = found.group(1), found.group(2).strip()
            top = open_fences[-1] if open_fences else None
            if top and not rest and fence[0] == top[0] and len(fence) >= len(top):
                open_fences.pop()
            elif not top or top[0] != fence[0]:
                open_fences.append(fence)
    out.extend(reversed(open_fences))
    out.append("*(cut to fit one message)*")
    return "\n".join(out)


def pack(blocks, limit=ZULIP_LIMIT):
    """Blocks into messages under the limit; a block is never split between two."""
    room = limit - 40
    parts, current = [], ""
    for block in blocks:
        if len(block) > room:
            block = cut_block(block, room)
        if current and len(current) + 2 + len(block) > room:
            parts.append(current)
            current = block
        else:
            current = (current + "\n\n" + block) if current else block
    if current:
        parts.append(current)
    if len(parts) > 1:
        parts = ["*(%d/%d)*\n%s" % (i + 1, len(parts), p) for i, p in enumerate(parts)]
    return parts


def render_zulip(groups, total, min_level, dashboard, context=None, notice=None, limit=ZULIP_LIMIT):
    """The digest as Zulip messages: the same groups, holds and fields as the mail.

    Written for a phone: one short title line per group, the description,
    one line of time, host and MITRE, then the decoded fields of 1-3
    samples in a code block. If everything does not fit in ZULIP_PARTS
    messages, samples drop to one, then the remaining groups become one line each.
    """
    context = context or {}
    held = context.get("held") or []
    items = ordered_groups(groups)
    first = items[0][1]["first"] if items else ""
    about = []
    if context.get("node"):
        about.append("from %s%s" % (context["node"], (" (%s)" % context["node_type"])
                                    if context.get("node_type") else ""))
    if zone(first):
        about.append("times %s" % zone(first))
    if groups:
        head = "\U0001F6A8 **%s** \u00b7 %s \u00b7 %s" % (
            plural(total, "alert"), plural(len(groups), "rule"),
            md(("host " if len({k[1] for k in groups}) == 1 else "hosts ") + host_names(groups)))
    else:
        head = "\U0001F6A8 **%s**" % md(opening(groups, total, min_level, held))
    if about:
        head += "\n*%s*" % md(" \u00b7 ".join(about))
    blocks = [head]
    if notice:
        blocks.append(notice)
    tail = []
    if len(items) > MAX_GROUPS:
        tail.append("*%d more groups not listed*" % (len(items) - MAX_GROUPS))
    if held:
        lines = ["**Still ongoing**: repeats of groups already posted in full, counted rather than "
                 "repeated (hold %d minutes)" % (context.get("repeat", 3600) // 60)]
        lines.extend("- " + md(held_line(entry)) for entry in held[:MAX_GROUPS])
        if len(held) > MAX_GROUPS:
            lines.append("- %d more" % (len(held) - MAX_GROUPS))
        tail.append("\n".join(lines))
    if context.get("more"):
        tail.append("*More alerts are waiting; the next run continues from here.*")
    footer = []
    if context.get("node"):
        footer.append("*sent by %s \u00b7 jt-alert-digest %s*" % (md(context["node"]), VERSION))
    if dashboard and re.match(r"^https?://", dashboard):
        footer.append("[dashboard](%s)" % md_link(dashboard))
    if footer:
        tail.append(" \u00b7 ".join(footer))

    budget = ZULIP_PARTS * (limit - 40) - sum(len(b) + 2 for b in blocks + tail)
    shown = items[:MAX_GROUPS]
    for samples in (samples_shown(len(items)), 1):
        rendered = [zulip_group(r, a, g, samples, link_for(context, r, a, g)) for (r, a), g in shown]
        if sum(len(b) + 2 for b in rendered) <= budget:
            break
    else:
        # Still too long: full blocks while they fit, then one line per group.
        out, used, full = [], 0, True
        for block, ((r, a), g) in zip(rendered, shown):
            left = len(shown) - len(out) - 1
            if full and used + len(block) + 2 + 200 * left <= budget:
                out.append(block)
                used += len(block) + 2
                continue
            full = False
            line = zulip_group(r, a, g, 1, compact=True)
            if out and out[-1].startswith("- "):
                out[-1] += "\n" + line
            else:
                out.append(line)
            used += len(line) + 1
        rendered = out
    return pack(blocks + rendered + tail, limit)


# --------------------------------------------------------------------------
# More channels (1.13): Microsoft Teams, Telegram, Slack, Discord, Mattermost,
# a generic JSON webhook and LINE
# --------------------------------------------------------------------------
#
# Each works as the Zulip channel does: its own position in the alert file,
# repeat hold, outbox, failure record and daily summary, kept under its name
# in the state file, and its own status rules (131131-131196, ten IDs per
# channel). A channel that fails or crashes never moves, loses or repeats the
# work of mail or of another channel.
#
# Alert text is attacker-influenced (descriptions, agent names, logs), so each
# channel has escaping written for what its platform interprets: a mention
# that notifies a whole channel, a link whose text hides its target, markup
# that makes one alert look like another. Credentials (webhook URLs, which are
# credentials in themselves, and tokens) come only from root-only files and
# never appear in logs, state, events or error texts.

CHAT_COMMON = ("level", "max_backlog", "daily", "ca_file", "tls_verify")
CHAT_SPECIFIC = OrderedDict((
    ("teams", ("url_file",)),
    ("telegram", ("token_file", "chat_id", "thread_id", "api")),
    ("slack", ("url_file",)),
    ("discord", ("url_file",)),
    ("mattermost", ("url_file", "channel")),
    ("webhook", ("url", "url_file", "hmac_key_file", "bearer_file")),
    ("line", ("token_file", "to", "api")),
))
CHAT_KEYS = tuple("%s_%s" % (name, key) for name, keys in CHAT_SPECIFIC.items()
                  for key in keys + CHAT_COMMON)
LOOPBACK = ("127.0.0.1", "localhost", "::1")
COLOUR = ((14, 0x991B1B), (12, 0xC2410C), (10, 0xCA8A04), (0, 0x2563EB))
TEST_NOTE = ("If you can read this, alert digests from this node reach this channel. Nothing "
             "was read from the alert file, nothing was changed and no mail was sent. Below, "
             "an invented alert shows the layout.")
WEBHOOK_SCHEMA = "jt-alert-digest/1"
MALFORMED_TRIES = 3   # a message the server calls malformed is dropped after this many tries


def utf16_len(text):
    """Telegram and LINE count message length in UTF-16 code units."""
    return len(text.encode("utf-16-le")) // 2


def colour(level):
    return next(value for floor, value in COLOUR if level >= floor)


def checked_url(url, setting, fatal, query=True):
    """url if it is https (plain http only to this host); otherwise None and a problem.

    The URL itself is never quoted in the problem: for a webhook it is the
    credential.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        parts, host = None, ""
    if not parts or not host or parts.fragment or "@" in parts.netloc or re.search(r"\s", url) \
            or (parts.query and not query) or not (
                parts.scheme == "https" or (parts.scheme == "http" and host in LOOPBACK)):
        fatal.append("%s must be an https:// address" % setting)
        return None
    return url


def secret_setting(site, setting, fatal, pattern, what, required=True):
    """The first line of the root-only file named by setting, if it matches pattern."""
    path = site.get(setting)
    if not path:
        if required:
            fatal.append("%s is not set" % setting)
        return None
    value, problem = read_secret(path, setting)
    if problem:
        fatal.append(problem)
        return None
    value = value.strip()
    if not re.match(pattern, value):
        fatal.append("%s %s does not hold %s on its first line" % (setting, path, what))
        return None
    return value


def secret_url(site, setting, fatal):
    url = secret_setting(site, setting, fatal, r"^\S{10,4096}$", "an address")
    if url is None:
        return None
    return checked_url(url, "the address in %s" % setting, fatal)


def chat_common(site, name, fatal, warnings):
    c = {"name": name, "level": None, "max_backlog": 24 * 3600, "daily": True,
         "verify": True, "ca_file": None, "secrets": []}
    raw = site.get(name + "_level")
    if raw:
        try:
            value = int(raw)
            if not 0 <= value <= 16:
                raise ValueError(raw)
            c["level"] = value
        except ValueError:
            warnings.append("%s_level = %s ignored" % (name, raw))
    raw = site.get(name + "_max_backlog")
    if raw:
        try:
            c["max_backlog"] = max(3600, _duration(raw))
        except ValueError:
            warnings.append("%s_max_backlog = %s ignored, using 24 hours" % (name, raw))
    raw = site.get(name + "_daily")
    if raw:
        try:
            c["daily"] = _yes(raw)
        except ValueError:
            warnings.append("%s_daily = %s ignored, the daily summary is posted" % (name, raw))
    raw = site.get(name + "_tls_verify")
    if raw:
        try:
            c["verify"] = _yes(raw)
        except ValueError:
            fatal.append("%s_tls_verify must be yes or no" % name)
    c["ca_file"] = site.get(name + "_ca_file") or None
    if c["ca_file"] and not os.access(c["ca_file"], os.R_OK):
        fatal.append("%s_ca_file %s cannot be read" % (name, c["ca_file"]))
    return c


def build_chat_options(site, name, warnings):
    """(options, fatal) for one channel; (None, []) when none of its settings exist.

    Any of a channel's settings switches it on, so a half-written configuration
    is reported (its config_error rule) instead of being silently ignored.
    """
    keys = ["%s_%s" % (name, key) for key in CHAT_SPECIFIC[name] + CHAT_COMMON]
    if not any(key in site for key in keys):
        return None, []
    fatal = []
    c = chat_common(site, name, fatal, warnings)
    if name in ("teams", "slack", "discord", "mattermost"):
        c["url"] = secret_url(site, name + "_url_file", fatal)
        c["secrets"].append(c["url"])
    if name == "mattermost":
        c["channel"] = (site.get("mattermost_channel") or "").strip() or None
        if c["channel"] and not re.match(r"^@?[a-z0-9][a-z0-9._-]{0,63}$", c["channel"]):
            fatal.append("mattermost_channel must be a channel name (the last part of its URL)")
    if name == "telegram":
        c["token"] = secret_setting(site, "telegram_token_file", fatal,
                                    r"^\d{3,20}:[A-Za-z0-9_-]{30,80}$", "a bot token")
        c["secrets"].append(c["token"])
        c["api"] = checked_url((site.get("telegram_api") or "https://api.telegram.org").strip()
                               .rstrip("/"), "telegram_api", fatal, query=False)
        chat = (site.get("telegram_chat_id") or "").strip()
        c["chat_id"] = None
        if re.match(r"^-?\d{1,20}$", chat):
            c["chat_id"] = int(chat)
        elif re.match(r"^@[A-Za-z][A-Za-z0-9_]{3,31}$", chat):
            c["chat_id"] = chat
        else:
            fatal.append("telegram_chat_id must be a numeric chat id (a group's starts with -100) "
                         "or a public @channelname")
        c["thread_id"] = None
        thread = (site.get("telegram_thread_id") or "").strip()
        if thread:
            if thread.isdigit():
                c["thread_id"] = int(thread)
            else:
                fatal.append("telegram_thread_id must be the numeric id of a forum topic")
    if name == "line":
        c["token"] = secret_setting(site, "line_token_file", fatal,
                                    r"^[A-Za-z0-9+/=._-]{20,1024}$", "a channel access token")
        c["secrets"].append(c["token"])
        c["api"] = checked_url((site.get("line_api") or "https://api.line.me").strip().rstrip("/"),
                               "line_api", fatal, query=False)
        c["to"] = (site.get("line_to") or "").strip()
        if not re.match(r"^[UCR][0-9a-f]{32}$", c["to"]):
            fatal.append("line_to must be a user, group or room id (U, C or R and 32 hex digits)")
    if name == "webhook":
        if site.get("webhook_url") and site.get("webhook_url_file"):
            fatal.append("set webhook_url or webhook_url_file, not both")
        if site.get("webhook_url_file"):
            c["url"] = secret_url(site, "webhook_url_file", fatal)
            c["secrets"].append(c["url"])
        elif site.get("webhook_url"):
            c["url"] = checked_url(site["webhook_url"].strip(), "webhook_url", fatal)
        else:
            c["url"] = None
            fatal.append("webhook_url (or webhook_url_file) is not set")
        c["hmac_key"] = secret_setting(site, "webhook_hmac_key_file", fatal, r"^.{16,4096}$",
                                       "a key of at least 16 characters", required=False)
        c["bearer"] = secret_setting(site, "webhook_bearer_file", fatal, r"^[\x21-\x7e]{8,4096}$",
                                     "a token", required=False)
        c["secrets"].extend([c["hmac_key"], c["bearer"]])
    c["secrets"] = [s for s in c["secrets"] if s]
    for secret in list(c["secrets"]):
        if secret.startswith("http"):
            # the token part of a webhook address, wherever an error might quote it
            parts = urlsplit(secret)
            c["secrets"].append(parts.path + (("?" + parts.query) if parts.query else ""))
            c["secrets"].extend(piece for piece in re.split(r"[/?&=]", parts.path + "?" + parts.query)
                                if len(piece) >= 12)
    return c, fatal


def channel_tls(verify, ca_file):
    if verify:
        context = verifying_context(ca_file)
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def http_send(c, url, body=None, headers=None, method="POST", timeout=20, explain=None):
    """One request for a channel; returns (status, body). Raises DeliveryError.

    A redirect is refused: it would carry the address's token or the
    Authorization header to wherever it points. Only the host name of the
    address is ever quoted, and every credential of the channel is removed
    from any text this returns or raises. explain(status, raw) gives a
    platform's own (code, message, malformed) for an error answer.
    """
    request = urllib.request.Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    request.add_header("User-Agent", "jt-alert-digest/" + VERSION)
    handlers = [_NoRedirect()]
    if url.startswith("https:"):
        handlers.append(urllib.request.HTTPSHandler(context=channel_tls(c.get("verify", True),
                                                                         c.get("ca_file"))))
    opener = urllib.request.build_opener(*handlers)
    try:
        host = urlsplit(url).hostname or "?"
    except ValueError:
        host = "?"

    def clean(text):
        text = str(text)
        for secret in sorted(c.get("secrets") or [], key=len, reverse=True):
            if secret and len(secret) >= 6:
                text = text.replace(secret, REDACTED)
        return trim(redact(text), 300)

    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(1 << 20)
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(1 << 16) if exc.fp else b""
        except (OSError, http.client.HTTPException):
            raw = b""
        status = exc.code
        code, message, malformed = "", "", False
        if explain:
            try:
                code, message, malformed = explain(status, raw)
            except Exception:       # an odd error body must not hide the status
                code, message, malformed = "", "", False
        code = re.sub(r"[^A-Za-z0-9_]", "", str(code or ""))[:40]
        permanent = 300 <= status < 500 and status not in (408, 429)
        raise DeliveryError("http-%d%s" % (status, ("-" + code) if code else ""),
                            clean("%s: HTTP %d%s: %s" % (host, status, (" " + code) if code else "",
                                                         message or exc.reason)),
                            permanent=permanent, malformed=malformed and permanent)
    except urllib.error.URLError as exc:
        reason = exc.reason
        kind = classify(reason) if isinstance(reason, BaseException) else "network"
        raise DeliveryError(kind, clean("%s: %s" % (host, reason)))
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise DeliveryError(classify(exc), clean("%s: %s: %s" % (host, type(exc).__name__, exc)))


def json_body(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def json_error(raw):
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def code_split(label, value):
    """(code, rest) for a value shown as code: in "path (modified)" only the path is code.
    (None, value) for a value shown as text."""
    if label not in CODE_LABELS and label != "Image":
        return None, value
    text = " ".join(str(value).split())
    if label == "Image" and ": " in text:
        name, rest = text.split(": ", 1)
        return name, rest
    found = re.match(r"^(\S+)(\s+\(.*\))?$", text)
    if found:
        return found.group(1), (found.group(2) or "").strip()
    return text, ""


def group_view(rule_id, agent, group, samples, link=None):
    """One group as plain values, for every chat layout except Zulip's.

    The same choices as the Zulip card: address and time first, the first
    sample's fields as rows, further samples' fields after them, the raw logs
    last; values are already redacted (interesting_fields) and trimmed.
    """
    rows, more, logs = [], [], []
    detail = host_detail(group)
    if detail:
        rows.append(("Address", detail.replace(", ", " \u00b7 ")))
    rows.append(("Time", re.sub(r"^\d{4}-", "", headline(group))))
    if group.get("mitre"):
        tactics = ", ".join(dedupe(group.get("tactics") or []))
        rows.append(("MITRE", ", ".join(group["mitre"]) + ((" " + tactics) if tactics else "")))
    for index, fields in enumerate(card_fields(group, samples)):
        shown = [(label, value) for label, value in fields if label != "Log"]
        logs.extend(value for label, value in fields if label == "Log")
        if index == 0:
            rows.extend(shown)
        elif shown:
            more.append(shown)
    shown_count = 0 if listed_in_full(group) else min(samples, len(group.get("samples", [])))
    notes = []
    if group["count"] - shown_count > 0 and shown_count:
        notes.append("%d more of the same" % (group["count"] - shown_count))
    if group.get("earlier"):
        notes.append("plus %d earlier since the last full post" % group["earlier"])
    return {"rule": rule_id, "agent": agent, "level": group["level"], "count": group["count"],
            "title": SEVERITY_MARKER.sub("", title(group, rule_id)), "badge": badge(group),
            "link": link if link and re.match(r"^https?://[^\s<>|\"]+$", link) else None,
            "rows": rows, "more": more, "logs": logs, "notes": notes}


def daily_info(state, options, context, warnings, others=()):
    """What a daily summary says, before any layout."""
    daily = state["daily"]
    t = now()
    return {"context": context, "options": options, "daily": daily, "t": t,
            "stopped": sorted((n, s) for n, s in daily.get("stops", {}).items()
                              if t - s >= STOP_GRACE),
            "levels": sorted(((int(k), v) for k, v in daily.get("levels", {}).items()),
                             reverse=True),
            "top": sorted(daily.get("rules", {}).items(), key=lambda kv: -kv[1][0])[:5],
            "failure": state.get("failure"), "others": list(others), "warnings": warnings}


def daily_view(info):
    """The daily summary as plain rows and sections, for every channel but Zulip."""
    context, options, daily = info["context"], info["options"], info["daily"]
    failure = info["failure"]
    rows = [("L%d+ alerts" % options["level"], "{:,}".format(daily.get("qualifying", 0))),
            ("Digests sent", "{:,}".format(daily.get("digests", 0))),
            ("Alerts in them", "{:,}".format(daily.get("mailed", 0))),
            ("Repeats held", "{:,}".format(daily.get("held", 0)))]
    if daily.get("excluded"):
        rows.append(("Excluded", "{:,}".format(daily["excluded"])))
    if isinstance(failure, dict):
        rows.append(("Delivery", "\u274c failing since %s (%s, %d attempts), %s alerts waiting"
                     % (local_iso(failure.get("since"))[:16], failure.get("kind", "?"),
                        failure.get("attempts", 0), failure.get("pending", "?"))))
    else:
        rows.append(("Delivery", "\u2705 working" + ((" (%d failed tries)" % daily["failures"])
                                                     if daily.get("failures") else "")))
    for name, other in info["others"]:
        rows.append((name, ("\u274c failing since %s (%s)" % (local_iso(other.get("since"))[:16],
                                                              other.get("kind", "?")))
                     if isinstance(other, dict) else "\u2705 working"))
    if daily.get("unparsed"):
        rows.append(("Unreadable lines", "{:,}".format(daily["unparsed"])))
    sections = []
    if info["levels"]:
        sections.append(("Alerts written by level", [" \u00b7 ".join(
            "L%d %s" % (k, "{:,}".format(v)) for k, v in info["levels"])]))
    if info["top"]:
        sections.append(("Most frequent at L%d+" % options["level"], [
            "%s L%d \u00b7 rule %s \u00d7%s \u00b7 %s" % (level_mark(level), level, rule_id,
                                                          "{:,}".format(count),
                                                          trim(name_tokens(text), 90))
            for rule_id, (count, level, text) in info["top"]]))
    if info["stopped"]:
        sections.append(("Agents stopped and not back within %d minutes" % (STOP_GRACE // 60),
                         ["%s \u00b7 %s" % (n, local_iso(st)[5:16]) for n, st in info["stopped"]]))
    if daily.get("disconnects"):
        sections.append(("Agents reported disconnected",
                         ["%s \u00d7%d" % (n, c) for n, c in sorted(daily["disconnects"].items())]))
    if info["warnings"]:
        sections.append(("Settings ignored", ["; ".join(info["warnings"])]))
    trouble = isinstance(failure, dict) or any(isinstance(o, dict) for _, o in info["others"])
    return {"title": "Daily summary \u00b7 %s%s" % (context["node"], (" (%s)" % context["node_type"])
                                                    if context.get("node_type") else ""),
            "period": "%s \u2192 %s" % (local_iso(daily.get("since"))[:16], local_iso(info["t"])[:16]),
            "rows": rows, "sections": sections, "trouble": trouble,
            "foot": "jt-alert-digest %s on %s \u00b7 sent once a day; a day without one means the "
                    "digest is not running" % (VERSION, context["node"]),
            "dashboard": options.get("dashboard") if re.match(r"^https?://[^\s<>|\"]+$",
                                                               options.get("dashboard") or "")
            else None}


def chat_layout(ch, groups, total, options, context, notice=None):
    """Groups into at most ch.parts messages, as render_zulip does.

    Full cards with the usual number of samples; if that needs more messages
    than ch.parts, one sample each; then full cards while they fit and one
    line per group after that. A group is never split between two messages.
    """
    context = context or {}
    held = context.get("held") or []
    items = ordered_groups(groups)
    shown = items[:MAX_GROUPS]
    pre = [ch.head(groups, total, options["level"], context)]
    if notice:
        pre.append(ch.notice(notice))
    post = ch.tail(len(items), held, context, options.get("dashboard"))
    views, parts = [], []
    for samples in (samples_shown(len(items)), 1):
        views = [group_view(r, a, g, samples, link_for(context, r, a, g)) for (r, a), g in shown]
        parts = ch.pack(pre + [ch.group(v) for v in views] + post)
        if len(parts) <= ch.parts:
            return parts
    full = [ch.group(v) for v in views]
    for keep in range(len(views) - 1, -1, -1):
        parts = ch.pack(pre + full[:keep] + ch.compact(views[keep:]) + post)
        if len(parts) <= ch.parts:
            break
    return parts


class Channel(object):
    """A chat or webhook destination: settings, layout and the one request that posts.

    A unit is a pair (full, compact) of element lists; pack() puts whole units
    into messages, using the compact form of one that cannot fit a message on
    its own. What an element is depends on the platform: a line of text, a
    Slack block, a Discord embed, an Adaptive Card element.
    """

    name = label = ""
    parts = 4          # messages a run posts before groups become one line each
    gap = ()           # elements between two units in one message
    compact_chunk = 10

    def __init__(self, c, fatal):
        self.c, self.fatal = c, fatal

    def options(self, options):
        o = dict(options)
        if self.c.get("level") is not None:
            o["level"], o["forced"] = self.c["level"], True
        if not self.c.get("daily", True):
            o["daily"] = None
        return o

    def server(self):
        """Where failures say they were going: a host name, never a full address."""
        url = self.c.get("url") or self.c.get("api") or ""
        try:
            return urlsplit(url).hostname or self.label
        except ValueError:
            return self.label

    def where(self):
        return "%s via %s" % (self.label, self.server())

    def describe(self):
        """--check's settings line, without credentials."""
        bits = [self.where()]
        if self.c.get("level") is not None:
            bits.append("level %d" % self.c["level"])
        if not self.c.get("daily", True):
            bits.append("no daily summary")
        if not self.c.get("verify", True):
            bits.append("certificate NOT verified")
        return ", ".join(bits)

    # --- layout -----------------------------------------------------------

    def render(self, groups, total, options, context, notice=None):
        return [self.item(p) for p in chat_layout(self, groups, total, options, context, notice)]

    def item(self, payload):
        return {"payload": payload}

    def preview(self, item):
        return json.dumps(item.get("payload"), ensure_ascii=False, indent=1)

    def fits(self, elements):
        raise NotImplementedError

    def assemble(self, elements, index, count):
        raise NotImplementedError

    def ellipsis(self):
        raise NotImplementedError

    def pack(self, units):
        messages, current = [], []
        for full, compact in units:
            chosen = full if self.fits(list(full)) else compact
            if not self.fits(list(chosen)):
                kept = []
                for element in chosen:
                    if not self.fits(kept + [element, self.ellipsis()]):
                        break
                    kept.append(element)
                chosen = kept + [self.ellipsis()]
            joined = current + list(self.gap) + list(chosen) if current else list(chosen)
            if current and not self.fits(joined):
                messages.append(current)
                current = list(chosen)
            else:
                current = joined
        if current:
            messages.append(current)
        return [self.assemble(m, i, len(messages)) for i, m in enumerate(messages)]

    def compact(self, views):
        units = []
        for start in range(0, len(views), self.compact_chunk):
            lines = self.compact_lines(views[start:start + self.compact_chunk])
            units.append((lines, lines))
        return units

    # --- plain texts every layout shows ------------------------------------

    def summary(self, groups, total, level, context):
        if context.get("test"):
            return "jt-alert-digest %s test message from %s" % (VERSION, context.get("node", "?"))
        if groups:
            return "%s \u00b7 %s \u00b7 %s" % (
                plural(total, "alert"), plural(len(groups), "rule"),
                ("host " if len({k[1] for k in groups}) == 1 else "hosts ") + host_names(groups))
        return opening(groups, total, level, context.get("held") or [])

    def about(self, groups, context):
        about = []
        if context.get("node"):
            about.append("from %s%s" % (context["node"], (" (%s)" % context["node_type"])
                                        if context.get("node_type") else ""))
        items = ordered_groups(groups)
        if items and zone(items[0][1]["first"]):
            about.append("times %s" % zone(items[0][1]["first"]))
        return " \u00b7 ".join(about)

    @staticmethod
    def notice_text(notice):
        return ("%d alerts from %s to %s were not posted here: they were more than %d hours old "
                "when they could be read. The mail digest and the dashboard have them."
                % (notice["n"], notice["first"] or "?", notice["last"] or "?", notice["hours"]))

    @staticmethod
    def held_lines(held):
        lines = [held_line(entry) for entry in held[:MAX_GROUPS]]
        if len(held) > MAX_GROUPS:
            lines.append("%d more" % (len(held) - MAX_GROUPS))
        return lines

    def held_title(self, context):
        return ("Still ongoing: repeats of groups already posted in full, counted rather than "
                "repeated (hold %d minutes)" % (context.get("repeat", 3600) // 60))

    def compact_text(self, v):
        return "L%d \u00b7 %s \u00b7 rule %s%s \u00b7 %s" % (
            v["level"], v["agent"], v["rule"], (" \u00d7%d" % v["count"]) if v["count"] > 1 else "",
            trim(v["title"], 90))

    # --- delivery ---------------------------------------------------------

    def post(self, item):
        raise NotImplementedError

    def check(self):
        print("  %s: %s" % (self.name, self.describe()))
        if self.fatal:
            for problem in self.fatal:
                print("  PROBLEM: %s: %s" % (self.name, problem))
            return 1
        return self.probe()

    def probe(self):
        print("  %s: there is no read-only way to test this address; --test %s posts one "
              "test message" % (self.name, self.name))
        return 0

    def test_items(self, context):
        group = sample_group()
        groups = OrderedDict([(("100001", "example-host"), group)])
        return self.render(groups, 1, dict(level=12, dashboard=None),
                           dict(context, test=True, link=None))


class TextChannel(Channel):
    """One formatted text per message: Telegram, Mattermost, LINE.

    Elements are lines (a line may hold a newline inside a block); a message
    is the lines joined by newlines, and groups are separated by a blank line.
    """

    limit = 4000
    gap = ("",)

    def size(self, text):
        return utf16_len(text)

    def fits(self, elements):
        return self.size("\n".join(elements)) <= self.limit - 30

    def ellipsis(self):
        return self.i("(cut to fit one message)")

    def assemble(self, elements, index, count):
        text = "\n".join(elements)
        return ("%s\n%s" % (self.i("(%d/%d)" % (index + 1, count)), text)) if count > 1 else text

    def preview(self, item):
        return item["payload"] if isinstance(item.get("payload"), str) else Channel.preview(self, item)

    # markup, overridden per platform; t() makes text inert
    def t(self, text):
        return " ".join(str(text).split())

    def b(self, text):
        return self.t(text)

    def i(self, text):
        return self.t(text)

    def code(self, text):
        return self.t(text)

    def link(self, text, url):
        return self.t(text)

    def logs(self, logs):
        return ["Log: " + self.t(log) for log in logs]

    def value(self, label, value):
        code, rest = code_split(label, value)
        if code is None:
            return self.t(value)
        return self.code(code) + ((" " + self.t(rest)) if rest else "")

    def lab(self, label):
        return self.b(label)

    def row(self, label, value):
        return "%s %s" % (self.lab(label), self.value(label, value))

    def head(self, groups, total, level, context):
        lines = ["\U0001F6A8 " + self.b(self.summary(groups, total, level, context))]
        about = self.about(groups, context)
        if about:
            lines.append(self.i(about))
        if context.get("test"):
            lines.append(self.t(TEST_NOTE))
        return (lines, lines)

    def notice(self, notice):
        lines = [self.b(self.notice_text(notice))]
        return (lines, lines)

    def group(self, v):
        title = "%s %s%s%s" % (level_mark(v["level"]), self.b("L%d \u00b7 %s" % (v["level"], v["title"])),
                               (" \u00d7%d" % v["count"]) if v["count"] > 1 else "",
                               (" \u00b7 " + self.b(v["badge"])) if v["badge"] else "")
        lines = [title, "%s %s" % (self.lab("Host"), self.t(v["agent"]))]
        for label, value in v["rows"]:
            lines.append(self.row(label, value))
            if label == "Time":
                rule = self.link(v["rule"], v["link"]) if v["link"] else self.t(v["rule"])
                lines.append("%s %s" % (self.lab("Rule"), rule))
        for fields in v["more"]:
            lines.append(" \u00b7 ".join(self.row(label, value) for label, value in fields))
        lines.extend(self.logs(v["logs"]))
        if v["notes"]:
            lines.append(self.i("(%s)" % "; ".join(v["notes"])))
        return (lines, self.compact_lines([v]))

    def compact_lines(self, views):
        return ["%s %s" % (level_mark(v["level"]), self.t(self.compact_text(v))) for v in views]

    def tail(self, count, held, context, dashboard):
        units = []
        if count > MAX_GROUPS:
            line = [self.i("%d more groups not listed" % (count - MAX_GROUPS))]
            units.append((line, line))
        if held:
            lines = [self.b(self.held_title(context))] + \
                ["\u2022 " + self.t(line) for line in self.held_lines(held)]
            short = lines[:11] + ([self.t("\u2022 %d more" % (len(lines) - 11))] if len(lines) > 11 else [])
            units.append((lines, short))
        if context.get("more"):
            line = [self.i("More alerts are waiting; the next run continues from here.")]
            units.append((line, line))
        foot = []
        if context.get("node"):
            foot.append(self.i("sent by %s \u00b7 jt-alert-digest %s" % (context["node"], VERSION)))
        if dashboard and re.match(r"^https?://[^\s<>|\"]+$", dashboard):
            foot.append(self.link("dashboard", dashboard))
        if foot:
            units.append(([" \u00b7 ".join(foot)], [" \u00b7 ".join(foot)]))
        return units

    def daily(self, info):
        v = daily_view(info)
        head = [("\U0001F7E5" if v["trouble"] else "\U0001F7E9") * BAR_WIDTH,
                "\U0001F4CA " + self.b(v["title"]), self.i(v["period"])]
        units = [(head + [self.row(label, value) for label, value in v["rows"]],) * 2]
        for title, lines in v["sections"]:
            body = [self.b(title)] + ["\u2022 " + self.t(line) for line in lines[:20]]
            if len(lines) > 20:
                body.append(self.t("\u2022 %d more" % (len(lines) - 20)))
            units.append((body, body))
        foot = self.i(v["foot"])
        if v["dashboard"]:
            foot += " \u00b7 " + self.link("dashboard", v["dashboard"])
        units.append(([foot], [foot]))
        return [self.item(p) for p in self.pack(units)]


# --- Telegram ---------------------------------------------------------------

def tg(text):
    """Text made inert in Telegram's HTML parse mode.

    Only <, > and & are special in the markup itself. Telegram also turns
    plain text into entities: an @username notifies that user and a /command
    is tappable and sends itself to the group's bots, so both are broken with
    a zero-width space. Code and quotes are not parsed further, but the
    blockquote is, so the logs in it go through this as well.
    """
    text = " ".join(str(text).split())
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"@(?=\w)", "@\u200b", text)
    return re.sub(r"(^|[\s(\[])/(?=[A-Za-z])", "\\1/\u200b", text)


def tg_plain(html_text):
    """The same message without markup, for a server that refuses to parse it."""
    text = re.sub(r"<[^>]+>", "", html_text)
    return text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&amp;", "&")


class TelegramChannel(TextChannel):
    name, label = "telegram", "Telegram"
    limit = 4096

    def t(self, text):
        return tg(text)

    def b(self, text):
        return "<b>%s</b>" % tg(text)

    def i(self, text):
        return "<i>%s</i>" % tg(text)

    def code(self, text):
        text = " ".join(str(text).split())
        return "<code>%s</code>" % text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def link(self, text, url):
        return '<a href="%s">%s</a>' % (esc(url), tg(text))

    def logs(self, logs):
        if not logs:
            return []
        # collapsed until tapped (Bot API 7.4); wraps, unlike a code block
        return ["<blockquote expandable>%s</blockquote>" % "\n".join(tg(log) for log in logs)]

    def where(self):
        return "Telegram chat %s%s" % (self.c.get("chat_id"), (", topic %s" % self.c["thread_id"])
                                       if self.c.get("thread_id") else "")

    def explain(self, status, raw):
        data = json_error(raw)
        text = str(data.get("description") or "")
        moved = (data.get("parameters") or {}).get("migrate_to_chat_id")
        if moved:
            text += "; the group is now chat %s: set telegram_chat_id to that" % moved
        malformed = bool(re.search(r"parse entities|message is too long|text must be non-empty",
                                   text, re.I))
        return "", text, malformed

    def api(self, method, payload=None):
        url = "%s/bot%s/%s" % (self.c["api"], self.c["token"], method)
        body = json_body(payload) if payload is not None else None
        status, raw = http_send(self.c, url, body, {"Content-Type": "application/json",
                                                    "Accept": "application/json"},
                                method="POST" if body is not None else "GET",
                                explain=self.explain)
        data = json_error(raw)
        if not data.get("ok"):
            raise DeliveryError("bad-response", "unexpected answer from %s" % self.server())
        return data.get("result") or {}

    def post(self, item):
        payload = {"chat_id": self.c["chat_id"], "text": item["payload"], "parse_mode": "HTML",
                   "link_preview_options": {"is_disabled": True}}
        if self.c.get("thread_id"):
            payload["message_thread_id"] = self.c["thread_id"]
        try:
            self.api("sendMessage", payload)
        except DeliveryError as exc:
            if not exc.malformed or "parse entities" not in exc.text:
                raise
            # A link or tag this server will not take: the text still gets through.
            payload.pop("parse_mode")
            payload["text"] = tg_plain(item["payload"])
            self.api("sendMessage", payload)

    def probe(self):
        try:
            me = self.api("getMe")
        except DeliveryError as exc:
            print("  PROBLEM: telegram: the bot token was refused: %s (%s)" % (exc.text, exc.kind))
            return 1
        print("  telegram auth: accepted as @%s" % me.get("username", "?"))
        try:
            chat = self.api("getChat", {"chat_id": self.c["chat_id"]})
        except DeliveryError as exc:
            print("  PROBLEM: telegram: chat %s cannot be reached: add the bot to the group or "
                  "channel (a channel needs it as an administrator): %s" % (self.c["chat_id"], exc.text))
            return 1
        print("  telegram chat: %s (%s)" % (chat.get("title") or chat.get("username") or "?",
                                            chat.get("type", "?")))
        print("  telegram result: the bot can reach the chat; --test telegram posts one message")
        return 0


# --- Mattermost -------------------------------------------------------------

def mm(text):
    """Mattermost markdown made inert: md() plus every @word, since an incoming
    webhook's @channel, @all, @here or @user notifies like a person's post.
    (MattermostChannel.post also removes every <, see there.)"""
    return re.sub(r"@(?=[\w.-])", "@\u200b", md(text))


class MattermostChannel(TextChannel):
    name, label = "mattermost", "Mattermost"
    limit = 12000      # 16,383 characters by default since Mattermost 5.0

    def t(self, text):
        return mm(text)

    def b(self, text):
        return "**%s**" % mm(text)

    def i(self, text):
        return "*%s*" % mm(text)

    def code(self, text):
        text = " ".join(str(text).split())
        return mm(text) if (not text or "`" in text) else "`%s`" % text

    def link(self, text, url):
        return "[%s](%s)" % (mm(text), md_link(url))

    def logs(self, logs):
        # a quote wraps on a phone; a code block would scroll sideways
        return ["> " + mm(log) for log in logs]

    def where(self):
        return "Mattermost via %s%s" % (self.server(), (", channel %s" % self.c["channel"])
                                        if self.c.get("channel") else "")

    def explain(self, status, raw):
        data = json_error(raw)
        text = str(data.get("message") or raw[:200].decode("utf-8", "replace"))
        return str(data.get("id") or "").replace(".", "_")[-40:], text, status == 400 and \
            "webhook" not in text.lower()

    def post(self, item):
        # Incoming webhooks are Slack-compatible: the server itself turns
        # <!channel>, <!here> and <!all> into live @channel, @here and @all,
        # and <url|text> into a link, after the text has left us, inside code
        # spans and blocks too (measured on a real Mattermost server). Our own
        # markup never uses <, so none reaches the server.
        payload = {"text": item["payload"].replace("<", "\u2039")}
        if self.c.get("channel"):
            payload["channel"] = self.c["channel"]
        http_send(self.c, self.c["url"], json_body(payload), {"Content-Type": "application/json"},
                  explain=self.explain)


# --- LINE -------------------------------------------------------------------

class LineChannel(TextChannel):
    """LINE Messaging API push messages: plain text, which LINE never interprets
    (no markup, and a plain text message cannot mention anyone).

    Every push counts against the channel's monthly message quota, once per
    recipient, so a group of ten is ten messages. One run therefore sends one
    request holding up to five text messages, which LINE counts as one.
    """

    name, label = "line", "LINE"
    limit = 5000
    parts = 5

    def link(self, text, url):
        return "%s %s" % (self.t(text), url)

    def lab(self, label):
        return self.t(label) + ":"

    def group(self, v):
        v = dict(v, link=None)       # a dashboard address per group is too long for a phone
        return TextChannel.group(self, v)

    def render(self, groups, total, options, context, notice=None):
        texts = chat_layout(self, groups, total, options, context, notice)
        return [self.item(texts[i:i + 5]) for i in range(0, len(texts), 5)]

    def daily(self, info):
        texts = [item["payload"] for item in TextChannel.daily(self, info)]
        return [self.item(texts[i:i + 5]) for i in range(0, len(texts), 5)]

    def item(self, payload):
        # the same retry key on every attempt: LINE answers 409 to a repeat it already sent
        return {"payload": payload, "retry_key": str(uuid.uuid4())}

    def preview(self, item):
        return "\n-----\n".join(item["payload"])

    def where(self):
        return "LINE %s %s" % ({"U": "user", "C": "group", "R": "room"}.get(self.c.get("to", "?")[:1], "?"),
                               self.c.get("to"))

    def explain(self, status, raw):
        data = json_error(raw)
        text = str(data.get("message") or "")
        details = data.get("details") or []
        if details and isinstance(details[0], dict):
            text += " (%s: %s)" % (details[0].get("property", "?"), details[0].get("message", "?"))
        return "", text, status == 400 and "request body" in text.lower()

    def call(self, method, path, payload=None, headers=None):
        all_headers = {"Authorization": "Bearer " + self.c["token"], "Accept": "application/json"}
        all_headers.update(headers or {})
        body = None
        if payload is not None:
            body = json_body(payload)
            all_headers["Content-Type"] = "application/json"
        return http_send(self.c, self.c["api"] + path, body, all_headers, method=method,
                         explain=self.explain)

    def post(self, item):
        try:
            self.call("POST", "/v2/bot/message/push",
                      {"to": self.c["to"], "messages": [{"type": "text", "text": text}
                                                        for text in item["payload"][:5]]},
                      {"X-Line-Retry-Key": item.get("retry_key") or str(uuid.uuid4())})
        except DeliveryError as exc:
            if exc.kind.startswith("http-409"):
                return      # accepted on an earlier try whose answer was lost
            raise

    def probe(self):
        try:
            _, raw = self.call("GET", "/v2/bot/info")
        except DeliveryError as exc:
            print("  PROBLEM: line: the channel access token was refused: %s (%s)" % (exc.text, exc.kind))
            return 1
        print("  line auth: accepted as %s" % (json_error(raw).get("displayName") or "?"))
        path = {"C": "/v2/bot/group/%s/summary", "U": "/v2/bot/profile/%s"}.get(self.c["to"][:1])
        if path:
            try:
                _, raw = self.call("GET", path % self.c["to"])
            except DeliveryError as exc:
                print("  PROBLEM: line: %s cannot be reached: invite the bot to the group, or have "
                      "the user add it as a friend: %s" % (self.c["to"], exc.text))
                return 1
            data = json_error(raw)
            print("  line target: %s" % (data.get("groupName") or data.get("displayName") or "?"))
        print("  line result: the bot can reach the target; --test line sends one push message, "
              "which counts against the monthly quota")
        return 0


# --- Slack ------------------------------------------------------------------

def sl(text):
    """Slack mrkdwn made inert.

    &, < and > are the escapes Slack documents, and with them gone no <!channel>,
    <@user> or <url|disguised text> can be formed. * ` ~ have no escape in
    mrkdwn, so they become look-alikes. The webhook never sets link_names, so a
    bare @channel stays text; it also gets a zero-width space, in case a
    workspace or a forwarding bot resolves names after all.
    """
    text = " ".join(str(text).split())
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("*", "\u2217").replace("`", "\u02cb").replace("~", "\u223c")
    return text.replace("@", "@\u200b")


def sl_code(text):
    text = " ".join(str(text).split())
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("`", "\u02cb")
    return "`%s`" % text if text else ""


def sl_section(text):
    return {"type": "section", "text": {"type": "mrkdwn", "text": trim_keep(text, 2900)}}


def trim_keep(text, limit):
    """Shorten without collapsing the line breaks a block needs."""
    return text if len(text) <= limit else text[:limit - 3] + "..."


# Slack: a header holds at most 150 characters; the margin covers an emoji
# counted as two.
SLACK_HEADER = 140


class SlackChannel(Channel):
    """An incoming webhook with Block Kit: a header per group, the short values
    as two-column fields, long values and logs as sections, rule and notes in a
    small context line."""

    name, label = "slack", "Slack"

    def fits(self, elements):
        return len(elements) <= 48 and len(json.dumps(elements, ensure_ascii=False)) <= 24000

    def ellipsis(self):
        return {"type": "context", "elements": [{"type": "mrkdwn", "text": "_(cut to fit one message)_"}]}

    def assemble(self, elements, index, count):
        blocks = list(elements)
        if count > 1:
            blocks.insert(0, {"type": "context", "elements": [
                {"type": "mrkdwn", "text": "(%d/%d)" % (index + 1, count)}]})
        return {"text": self._fallback, "blocks": blocks, "unfurl_links": False, "unfurl_media": False}

    def render(self, groups, total, options, context, notice=None):
        self._fallback = sl(self.summary(groups, total, options["level"], context or {}))
        return Channel.render(self, groups, total, options, context, notice)

    def value(self, label, value):
        code, rest = code_split(label, value)
        if code is None:
            return sl(value)
        return sl_code(code) + ((" " + sl(rest)) if rest else "")

    def head(self, groups, total, level, context):
        blocks = [sl_section("\U0001F6A8 *%s*" % sl(self.summary(groups, total, level, context)))]
        about = self.about(groups, context)
        texts = ([sl(about)] if about else []) + ([sl(TEST_NOTE)] if context.get("test") else [])
        if texts:
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": "\n".join(texts)}]})
        return (blocks, blocks)

    def notice(self, notice):
        blocks = [sl_section("*%s*" % sl(self.notice_text(notice)))]
        return (blocks, blocks)

    def link(self, text, url):
        # Slack decodes &amp; in a link's address; < > | cannot occur (group_view checked)
        return "<%s|%s>" % (url.replace("&", "&amp;"), sl(text))

    def group(self, v):
        # plain_text: nothing in it is interpreted, but @ is split as everywhere else
        title = trim("%s L%d \u00b7 %s" % (level_mark(v["level"]), v["level"],
                                           v["title"].replace("@", "@\u200b")), SLACK_HEADER)
        blocks = [{"type": "divider"},
                  {"type": "header", "text": {"type": "plain_text", "text": title, "emoji": False}}]
        fields, long_rows = [{"type": "mrkdwn", "text": "*Host*\n%s" % sl(v["agent"])}], []
        for label, value in v["rows"]:
            if fits_table(label, value) and len(fields) < 10:
                fields.append({"type": "mrkdwn", "text": "*%s*\n%s" % (label, self.value(label, value))})
            else:
                long_rows.append("*%s* %s" % (label, self.value(label, value)))
        blocks.append({"type": "section", "fields": fields})
        for fields_more in v["more"]:
            long_rows.append(" \u00b7 ".join("*%s* %s" % (label, self.value(label, value))
                                             for label, value in fields_more))
        if long_rows:
            blocks.append(sl_section("\n".join(long_rows)))
        if v["logs"]:
            body = "\n".join(" ".join(log.split()).replace("&", "&amp;").replace("<", "&lt;")
                             .replace(">", "&gt;").replace("`", "\u02cb") for log in v["logs"])
            blocks.append(sl_section("```%s```" % trim_keep(body, 2890)))
        context = ["rule " + (self.link(v["rule"], v["link"]) if v["link"] else sl(v["rule"]))]
        if v["count"] > 1:
            context.append("\u00d7%d" % v["count"])
        if v["badge"]:
            context.append("*%s*" % v["badge"])
        context.extend(sl(note) for note in v["notes"])
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
                                                         "text": trim(" \u00b7 ".join(context), 2900)}]})
        return (blocks, [{"type": "divider"}] + self.compact_lines([v]))

    def compact_lines(self, views):
        return [sl_section("\n".join("%s %s" % (level_mark(v["level"]), sl(self.compact_text(v)))
                                     for v in views))]

    def tail(self, count, held, context, dashboard):
        units = []
        if count > MAX_GROUPS:
            units.append(([sl_section("_%d more groups not listed_" % (count - MAX_GROUPS))],) * 2)
        if held:
            lines = ["*%s*" % sl(self.held_title(context))] + \
                ["\u2022 " + sl(line) for line in self.held_lines(held)]
            units.append(([{"type": "divider"}, sl_section("\n".join(lines))],) * 2)
        if context.get("more"):
            units.append(([sl_section("_More alerts are waiting; the next run continues from here._")],) * 2)
        foot = []
        if context.get("node"):
            foot.append("sent by %s \u00b7 jt-alert-digest %s" % (sl(context["node"]), VERSION))
        if dashboard and re.match(r"^https?://[^\s<>|\"]+$", dashboard):
            foot.append(self.link("dashboard", dashboard))
        if foot:
            units.append(([{"type": "context", "elements": [{"type": "mrkdwn",
                                                             "text": " \u00b7 ".join(foot)}]}],) * 2)
        return units

    def daily(self, info):
        v = daily_view(info)
        self._fallback = sl(v["title"])
        head = [{"type": "header", "text": {"type": "plain_text", "emoji": False, "text": trim(
                    "%s %s" % ("\U0001F7E5" if v["trouble"] else "\U0001F7E9", v["title"]), SLACK_HEADER)}},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": sl(v["period"])}]}]
        rows = [{"type": "mrkdwn", "text": "*%s*\n%s" % (sl(label), sl(value))} for label, value in v["rows"]]
        for start in range(0, len(rows), 10):
            head.append({"type": "section", "fields": rows[start:start + 10]})
        units = [(head, head)]
        for title, lines in v["sections"]:
            body = ["*%s*" % sl(title)] + ["\u2022 " + sl(line) for line in lines[:20]]
            if len(lines) > 20:
                body.append("\u2022 %d more" % (len(lines) - 20))
            units.append(([sl_section("\n".join(body))],) * 2)
        foot = sl(v["foot"]) + ((" \u00b7 " + self.link("dashboard", v["dashboard"])) if v["dashboard"] else "")
        units.append(([{"type": "context", "elements": [{"type": "mrkdwn", "text": foot}]}],) * 2)
        return [self.item(p) for p in self.pack(units)]

    def explain(self, status, raw):
        code = raw[:80].decode("utf-8", "replace").strip()
        if not re.match(r"^[a-z_]+$", code):
            code = ""
        return code, code, code in ("invalid_blocks", "invalid_blocks_format", "invalid_payload",
                                    "invalid_attachments", "too_many_attachments", "no_text")

    def post(self, item):
        http_send(self.c, self.c["url"], json_body(item["payload"]),
                  {"Content-Type": "application/json"}, explain=self.explain)

    def probe(self):
        # An empty message is refused as no_text by a valid webhook and posts nothing;
        # a wrong or revoked one answers no_service, invalid_token or channel_not_found.
        try:
            http_send(self.c, self.c["url"], b"{}", {"Content-Type": "application/json"},
                      explain=self.explain)
        except DeliveryError as exc:
            if exc.kind in ("http-400-no_text", "http-400-invalid_payload"):
                print("  slack result: the webhook exists (an empty message was refused as "
                      "expected); --test slack posts one message")
                return 0
            print("  PROBLEM: slack: %s (%s)" % (exc.text, exc.kind))
            return 1
        print("  warning: slack: the webhook took an empty message; is the address a Slack webhook?")
        return 0


# --- Discord ----------------------------------------------------------------

def dc(text):
    """Discord markdown made inert with backslash escapes, which Discord honours
    for any punctuation; @ also gets a zero-width space. allowed_mentions with
    an empty parse list is what guarantees nobody is notified."""
    text = " ".join(str(text).split())
    text = re.sub(r"([\\*_~`|<>#\[\]()\-:])", r"\\\1", text)
    return text.replace("@", "@\u200b")


def dc_plain(text):
    """For embed titles and footers, where markdown may or may not be parsed:
    look-alikes instead of backslashes, which would show if it is not."""
    text = " ".join(str(text).split())
    text = text.replace("*", "\u2217").replace("`", "\u02cb").replace("@", "@\u200b")
    for pair in ("__", "~~", "||"):
        text = text.replace(pair, pair[0] + "\u200b" + pair[1])
    return text.replace("](", "]\u200b(").replace("<", "\u2039").replace(">", "\u203a")


def dc_code(text, block=False):
    text = str(text).replace("`", "\u02cb")
    if block:
        return "```\n%s\n```" % text
    text = " ".join(text.split())
    return "`%s`" % text if text else ""


def embed_size(embed):
    size = len(embed.get("title", "")) + len(embed.get("description", ""))
    size += len((embed.get("footer") or {}).get("text", ""))
    for field in embed.get("fields", []):
        size += len(field.get("name", "")) + len(field.get("value", ""))
    return size


class DiscordChannel(Channel):
    """A channel webhook with embeds: one embed per group in the level's colour,
    short values as inline fields, the log as a code block field. Messages hold
    at most ten embeds and 6,000 characters of them."""

    name, label = "discord", "Discord"

    def fits(self, elements):
        embeds = [e for e in elements if "content" not in e]
        content = "\n".join(e["content"] for e in elements if "content" in e)
        return len(embeds) <= 10 and sum(embed_size(e) for e in embeds) <= 5800 and len(content) <= 1900

    def ellipsis(self):
        return {"description": "*(cut to fit one message)*"}

    def assemble(self, elements, index, count):
        content = "\n".join(e["content"] for e in elements if "content" in e)
        if count > 1:
            content = ("*(%d/%d)*\n" % (index + 1, count)) + content
        payload = {"embeds": [e for e in elements if "content" not in e],
                   "allowed_mentions": {"parse": []}}
        if content.strip():
            payload["content"] = content.strip()
        return payload

    def value(self, label, value):
        code, rest = code_split(label, value)
        if code is None:
            return dc(value)
        return dc_code(code) + ((" " + dc(rest)) if rest else "")

    def head(self, groups, total, level, context):
        lines = ["\U0001F6A8 **%s**" % dc(self.summary(groups, total, level, context))]
        about = self.about(groups, context)
        if about:
            lines.append("*%s*" % dc(about))
        if context.get("test"):
            lines.append(dc(TEST_NOTE))
        element = {"content": "\n".join(lines)}
        return ([element], [element])

    def notice(self, notice):
        embed = {"description": "**%s**" % dc(self.notice_text(notice))}
        return ([embed], [embed])

    def group(self, v):
        title = "%s L%d \u00b7 %s%s" % (level_mark(v["level"]), v["level"], v["title"],
                                         (" \u00d7%d" % v["count"]) if v["count"] > 1 else "")
        embed = {"title": trim(dc_plain(title), 250), "color": colour(v["level"])}
        if v["link"]:
            embed["url"] = v["link"]
        fields = [{"name": "Host", "value": trim(dc(v["agent"]), 1000), "inline": True}]
        for label, value in v["rows"]:
            fields.append({"name": label, "value": trim_keep(self.value(label, value), 1000) or "-",
                           "inline": fits_table(label, value)})
        for extra in v["more"]:
            fields.append({"name": "Also", "value": trim_keep(" \u00b7 ".join(
                "**%s** %s" % (label, self.value(label, value)) for label, value in extra), 1000),
                "inline": False})
        if v["logs"]:
            fields.append({"name": "Log" if len(v["logs"]) == 1 else "Logs (%d)" % len(v["logs"]),
                           "value": dc_code(trim_keep("\n".join(" ".join(log.split()) for log in v["logs"]),
                                                      980), block=True), "inline": False})
        embed["fields"] = fields[:25]
        footer = ["rule %s" % v["rule"]] + ([v["badge"]] if v["badge"] else []) + v["notes"]
        embed["footer"] = {"text": trim(dc_plain(" \u00b7 ".join(footer)), 2000)}
        return ([embed], self.compact_lines([v]))

    def compact_lines(self, views):
        return [{"description": trim_keep("\n".join("%s %s" % (level_mark(v["level"]), dc(self.compact_text(v)))
                                                     for v in views), 4000)}]

    def tail(self, count, held, context, dashboard):
        lines = []
        if count > MAX_GROUPS:
            lines.append("*%d more groups not listed*" % (count - MAX_GROUPS))
        if held:
            lines.append("**%s**" % dc(self.held_title(context)))
            lines.extend("\u2022 " + dc(line) for line in self.held_lines(held))
        if context.get("more"):
            lines.append("*More alerts are waiting; the next run continues from here.*")
        foot = []
        if context.get("node"):
            foot.append("*sent by %s \u00b7 jt-alert-digest %s*" % (dc(context["node"]), VERSION))
        if dashboard and re.match(r"^https?://[^\s<>|\"()]+$", dashboard):
            foot.append("[dashboard](%s)" % dashboard)
        if foot:
            lines.append(" \u00b7 ".join(foot))
        if not lines:
            return []
        embed = {"description": trim_keep("\n".join(lines), 4000)}
        return [([embed], [embed])]

    def daily(self, info):
        v = daily_view(info)
        embed = {"title": trim(dc_plain("\U0001F4CA " + v["title"]), 250),
                 "color": 0xB91C1C if v["trouble"] else 0x15803D,
                 "description": "*%s*" % dc(v["period"]),
                 "fields": [{"name": dc_plain(label), "value": dc(value), "inline": True}
                            for label, value in v["rows"]][:25]}
        units = [([embed], [embed])]
        for title, lines in v["sections"]:
            body = ["\u2022 " + dc(line) for line in lines[:20]]
            if len(lines) > 20:
                body.append("\u2022 %d more" % (len(lines) - 20))
            section = {"title": trim(dc_plain(title), 250), "description": trim_keep("\n".join(body), 4000)}
            units.append(([section], [section]))
        foot = "*%s*" % dc(v["foot"])
        if v["dashboard"] and re.match(r"^https?://[^\s<>|\"()]+$", v["dashboard"]):
            foot += " \u00b7 [dashboard](%s)" % v["dashboard"]
        units.append(([{"description": foot}],) * 2)
        return [self.item(p) for p in self.pack(units)]

    def explain(self, status, raw):
        data = json_error(raw)
        code = data.get("code")
        return (str(code) if code else ""), str(data.get("message") or ""), code == 50035

    def post_url(self):
        url = self.c["url"]
        return url + ("&" if "?" in url else "?") + "wait=true"

    def post(self, item):
        http_send(self.c, self.post_url(), json_body(item["payload"]),
                  {"Content-Type": "application/json"}, explain=self.explain)

    def probe(self):
        try:
            _, raw = http_send(self.c, self.c["url"], None, {"Accept": "application/json"},
                               method="GET", explain=self.explain)
        except DeliveryError as exc:
            print("  PROBLEM: discord: the webhook was refused: %s (%s)" % (exc.text, exc.kind))
            return 1
        data = json_error(raw)
        print("  discord webhook: %s, channel id %s" % (data.get("name", "?"), data.get("channel_id", "?")))
        print("  discord result: the webhook exists; --test discord posts one message")
        return 0


# --- Microsoft Teams --------------------------------------------------------

def ms(text):
    """Adaptive Card text made inert.

    TextBlock and FactSet render a markdown subset (bold, italic, lists, links)
    and {{DATE()}} functions; there is no escape, so the markers become
    look-alikes or are split by a zero-width space. A mention needs an <at>
    entity the card itself declares, which alert text cannot add.
    """
    text = " ".join(str(text).split())
    text = text.replace("*", "\u2217").replace("`", "\u02cb").replace("@", "@\u200b")
    for pair in ("__", "~~", "{{"):
        text = text.replace(pair, pair[0] + "\u200b" + pair[1])
    text = text.replace("](", "]\u200b(")
    return re.sub(r"^([#>+-]|\d+\.)(?=\s)", "\u200b\\1", text)


STYLE = ((14, "attention"), (12, "warning"), (10, "accent"), (0, "emphasis"))


class TeamsChannel(Channel):
    """A Teams channel through a Workflows webhook ("Post to a channel when a
    webhook request is received"), as Adaptive Cards: each group in a container
    tinted by level, the values as a fact set, the log behind a "Show log"
    toggle, and a button to the group's alerts in the dashboard.

    Office 365 connectors (outlook.office.com/webhook) were retired by
    Microsoft; Workflows is the replacement and takes the same card.
    """

    name, label = "teams", "Microsoft Teams"
    limit = 24000      # bytes of card; Teams refuses a message above about 28 KB

    def fits(self, elements):
        return len(json.dumps(elements, ensure_ascii=False).encode("utf-8")) <= self.limit

    def ellipsis(self):
        return {"type": "TextBlock", "text": "*(cut to fit one message)*", "isSubtle": True, "wrap": True}

    def assemble(self, elements, index, count):
        body = list(elements)
        if count > 1:
            body.insert(0, {"type": "TextBlock", "text": "(%d/%d)" % (index + 1, count),
                            "isSubtle": True, "size": "Small"})
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard", "version": "1.4", "msteams": {"width": "Full"},
                        "body": body}}]}

    def render(self, groups, total, options, context, notice=None):
        self._ids = 0
        return Channel.render(self, groups, total, options, context, notice)

    def head(self, groups, total, level, context):
        items = [{"type": "TextBlock", "text": "\U0001F6A8 **%s**" % ms(self.summary(groups, total, level, context)),
                  "wrap": True, "size": "Medium"}]
        about = self.about(groups, context)
        if about:
            items.append({"type": "TextBlock", "text": ms(about), "isSubtle": True, "wrap": True,
                          "spacing": "None"})
        if context.get("test"):
            items.append({"type": "TextBlock", "text": ms(TEST_NOTE), "wrap": True})
        return (items, items)

    def notice(self, notice):
        items = [{"type": "TextBlock", "text": "**%s**" % ms(self.notice_text(notice)), "wrap": True,
                  "color": "Warning"}]
        return (items, items)

    def group(self, v):
        style = next(name for floor, name in STYLE if v["level"] >= floor)
        title = "%s **L%d \u00b7 %s**%s%s" % (level_mark(v["level"]), v["level"], ms(v["title"]),
                                              (" \u00d7%d" % v["count"]) if v["count"] > 1 else "",
                                              (" \u00b7 **%s**" % v["badge"]) if v["badge"] else "")
        facts = [{"title": "Host", "value": ms(v["agent"])}]
        for label, value in v["rows"]:
            facts.append({"title": label, "value": ms(value)})
            if label == "Time":
                facts.append({"title": "Rule", "value": ms(v["rule"])})
        items = [{"type": "TextBlock", "text": title, "wrap": True, "size": "Medium"},
                 {"type": "FactSet", "facts": facts}]
        for extra in v["more"]:
            items.append({"type": "TextBlock", "wrap": True, "text": " \u00b7 ".join(
                "**%s** %s" % (label, ms(value)) for label, value in extra)})
        actions = []
        if v["logs"]:
            self._ids = getattr(self, "_ids", 0) + 1
            target = "log-%d" % self._ids
            items.append({"type": "TextBlock", "id": target, "isVisible": False, "wrap": True,
                          "fontType": "Monospace", "size": "Small",
                          "text": "\n\n".join(ms(log) for log in v["logs"])})
            actions.append({"type": "Action.ToggleVisibility", "title": "Show log",
                            "targetElements": [target]})
        if v["link"]:
            actions.append({"type": "Action.OpenUrl", "title": "Alerts in the dashboard", "url": v["link"]})
        if actions:
            items.append({"type": "ActionSet", "actions": actions})
        if v["notes"]:
            items.append({"type": "TextBlock", "text": ms("(%s)" % "; ".join(v["notes"])),
                          "isSubtle": True, "size": "Small", "wrap": True})
        container = {"type": "Container", "style": style, "separator": True, "spacing": "Medium",
                     "items": items}
        return ([container], self.compact_lines([v]))

    def compact_lines(self, views):
        return [{"type": "TextBlock", "wrap": True, "text": "\n\n".join(
            "%s %s" % (level_mark(v["level"]), ms(self.compact_text(v))) for v in views)}]

    def tail(self, count, held, context, dashboard):
        units = []
        if count > MAX_GROUPS:
            units.append(([{"type": "TextBlock", "isSubtle": True, "wrap": True,
                            "text": "%d more groups not listed" % (count - MAX_GROUPS)}],) * 2)
        if held:
            lines = ["**%s**" % ms(self.held_title(context))] + ["\u2022 " + ms(l) for l in self.held_lines(held)]
            units.append(([{"type": "TextBlock", "wrap": True, "separator": True,
                            "text": "\n\n".join(lines)}],) * 2)
        if context.get("more"):
            units.append(([{"type": "TextBlock", "wrap": True, "isSubtle": True,
                            "text": "More alerts are waiting; the next run continues from here."}],) * 2)
        foot = []
        if context.get("node"):
            foot.append({"type": "TextBlock", "isSubtle": True, "size": "Small", "wrap": True,
                         "separator": True,
                         "text": ms("sent by %s \u00b7 jt-alert-digest %s" % (context["node"], VERSION))})
        if dashboard and re.match(r"^https?://[^\s<>|\"]+$", dashboard):
            foot.append({"type": "ActionSet", "actions": [{"type": "Action.OpenUrl",
                                                           "title": "Dashboard", "url": dashboard}]})
        if foot:
            units.append((foot, foot))
        return units

    def daily(self, info):
        v = daily_view(info)
        head = [{"type": "Container", "style": "attention" if v["trouble"] else "good", "items": [
                    {"type": "TextBlock", "text": "\U0001F4CA **%s**" % ms(v["title"]), "wrap": True,
                     "size": "Medium"},
                    {"type": "TextBlock", "text": ms(v["period"]), "isSubtle": True, "spacing": "None"}]},
                {"type": "FactSet", "facts": [{"title": ms(l), "value": ms(x)} for l, x in v["rows"]]}]
        units = [(head, head)]
        for title, lines in v["sections"]:
            body = ["**%s**" % ms(title)] + ["\u2022 " + ms(line) for line in lines[:20]]
            if len(lines) > 20:
                body.append("\u2022 %d more" % (len(lines) - 20))
            units.append(([{"type": "TextBlock", "wrap": True, "text": "\n\n".join(body)}],) * 2)
        foot = [{"type": "TextBlock", "wrap": True, "isSubtle": True, "size": "Small", "text": ms(v["foot"])}]
        if v["dashboard"]:
            foot.append({"type": "ActionSet", "actions": [{"type": "Action.OpenUrl", "title": "Dashboard",
                                                           "url": v["dashboard"]}]})
        units.append((foot, foot))
        return [self.item(p) for p in self.pack(units)]

    def explain(self, status, raw):
        data = json_error(raw)
        error = data.get("error") if isinstance(data.get("error"), dict) else {}
        return str(error.get("code") or ""), str(error.get("message") or ""), \
            status == 400 and "TriggerInputSchemaMismatch" not in str(error.get("code"))

    def post(self, item):
        http_send(self.c, self.c["url"], json_body(item["payload"]),
                  {"Content-Type": "application/json"}, explain=self.explain)


# --- Generic webhook --------------------------------------------------------

def webhook_group(rule_id, agent, group, link):
    """Values as they are in the alert. With the account names map (1.14), a
    sample row whose account it knows carries account_name beside the value,
    and the group lists account_names {id: name} for every id it resolved, in
    the title, the descriptions or the samples."""
    descriptions = [redact(d) for d in (group.get("descriptions") or [])[:10]]
    rows = sample_rows(group, MAX_SAMPLES)
    doc = {"rule_id": rule_id, "level": group["level"], "title": heading(group, rule_id),
           "descriptions": descriptions,
           "agent": {"name": agent, "id": group.get("agent_id") or None,
                     "ip": group.get("agent_ip") or None},
           "count": group["count"], "first": group.get("first"), "last": group.get("last"),
           "new": group.get("new") or None, "earlier": group.get("earlier", 0),
           "mitre": {"ids": list(group.get("mitre") or []),
                     "tactics": dedupe(group.get("tactics") or [])},
           "link": link,
           "samples": [[dict({"label": label, "value": value},
                             **({"account_name": ", ".join(dedupe(list(names.values())))}
                                if names else {}))
                        for label, value, _, names in fields] for fields in rows]}
    if NAMES:
        found = OrderedDict()
        for text in [doc["title"]] + descriptions:
            name_tokens(text, found)
        for fields in rows:
            for _, _, _, names in fields:
                found.update(names)
        if found:
            doc["account_names"] = dict(found)
    return doc


class WebhookChannel(Channel):
    """POST of a documented JSON document, for any system: a SOAR, a ticket
    queue, a pager, a script. Nothing in it is markup and nothing is escaped:
    the receiver must treat every string as untrusted text. Values are redacted
    as they are in the mail.

    Headers: X-JT-Event (digest, daily or test), X-JT-Delivery (the same on
    every retry of one document, for de-duplication), and with
    webhook_hmac_key_file X-JT-Timestamp and X-JT-Signature =
    "sha256=" + hex HMAC-SHA256(key, timestamp + "." + body); with
    webhook_bearer_file, Authorization: Bearer <token>.
    """

    name, label = "webhook", "Webhook"
    per_part = 50

    def base(self, kind, context):
        return {"schema": WEBHOOK_SCHEMA, "kind": kind, "version": VERSION,
                "node": context.get("node"), "node_type": context.get("node_type") or None,
                "sent_at": datetime.fromtimestamp(now(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}

    def render(self, groups, total, options, context, notice=None):
        context = context or {}
        kind = "test" if context.get("test") else "digest"
        items = ordered_groups(groups)
        chunks = [items[i:i + self.per_part] for i in range(0, len(items), self.per_part)] or [[]]
        out = []
        for index, chunk in enumerate(chunks):
            doc = self.base(kind, context)
            doc.update({"level": options["level"], "total": total, "part": index + 1,
                        "parts": len(chunks), "more_waiting": bool(context.get("more")),
                        "dashboard": options.get("dashboard"),
                        "groups": [webhook_group(r, a, g, link_for(context, r, a, g))
                                   for (r, a), g in chunk]})
            if index == len(chunks) - 1:
                doc["held"] = [{"rule_id": e.get("rule"), "agent": e.get("agent"),
                                "level": e.get("level"), "count": e.get("n", 0),
                                "first": e.get("first"), "last": e.get("last"),
                                "title": e.get("heading")} for e in context.get("held") or []]
                if notice:
                    doc["skipped"] = {"count": notice["n"], "first": notice["first"],
                                      "last": notice["last"], "older_than_hours": notice["hours"]}
            out.append(self.item(doc, kind))
        return out

    def daily(self, info):
        daily, context = info["daily"], info["context"]
        failure = info["failure"]

        def state_of(f):
            return {"ok": False, "since": local_iso(f.get("since")), "error_class": f.get("kind")} \
                if isinstance(f, dict) else {"ok": True}
        doc = self.base("daily", context)
        doc["summary"] = {
            "since": local_iso(daily.get("since")), "until": local_iso(info["t"]),
            "level": info["options"]["level"],
            "levels": {str(k): v for k, v in info["levels"]},
            "qualifying": daily.get("qualifying", 0), "digests": daily.get("digests", 0),
            "alerts_sent": daily.get("mailed", 0), "held": daily.get("held", 0),
            "excluded": daily.get("excluded", 0), "unparsed": daily.get("unparsed", 0),
            "delivery": dict(state_of(failure), failed_tries=daily.get("failures", 0)),
            "other_channels": {name: state_of(other) for name, other in info["others"]},
            "top_rules": [{"rule_id": r, "count": c, "level": l, "title": t}
                          for r, (c, l, t) in info["top"]],
            "stopped_agents": [{"agent": n, "stopped": local_iso(s)} for n, s in info["stopped"]],
            "disconnects": dict(daily.get("disconnects") or {}),
            "warnings": list(info["warnings"])}
        return [self.item(doc, "daily")]

    def item(self, payload, kind="digest"):
        return {"payload": payload, "kind": kind, "delivery": str(uuid.uuid4())}

    def where(self):
        return "webhook to %s%s%s" % (self.server(), ", signed" if self.c.get("hmac_key") else "",
                                      ", bearer token" if self.c.get("bearer") else "")

    def explain(self, status, raw):
        return "", raw[:200].decode("utf-8", "replace"), False

    def post(self, item):
        body = json_body(item["payload"])
        headers = {"Content-Type": "application/json; charset=utf-8",
                   "X-JT-Event": item.get("kind") or "digest",
                   "X-JT-Delivery": item.get("delivery") or str(uuid.uuid4())}
        if self.c.get("hmac_key"):
            stamp = str(int(time.time()))
            digest_ = hmac.new(self.c["hmac_key"].encode("utf-8"), stamp.encode("ascii") + b"." + body,
                               hashlib.sha256).hexdigest()
            headers.update({"X-JT-Timestamp": stamp, "X-JT-Signature": "sha256=" + digest_})
        if self.c.get("bearer"):
            headers["Authorization"] = "Bearer " + self.c["bearer"]
        http_send(self.c, self.c["url"], body, headers, explain=self.explain)


CHANNEL_CLASSES = OrderedDict((
    ("teams", TeamsChannel), ("telegram", TelegramChannel), ("slack", SlackChannel),
    ("discord", DiscordChannel), ("mattermost", MattermostChannel),
    ("webhook", WebhookChannel), ("line", LineChannel),
))


class ZulipChannel(Channel):
    """The 1.5 Zulip channel, in the same frame as the others: its own layout
    (render_zulip, daily_zulip) and API calls are unchanged."""

    name, label = "zulip", "Zulip"

    def where(self):
        return "Zulip channel %s, topic %s" % (self.c["stream"], self.c["topic"])

    def server(self):
        return self.c["url"]

    def render(self, groups, total, options, context, notice=None):
        text = None
        if notice:
            text = ("**%d alerts from %s to %s were not posted here**: they were more than %d hours "
                    "old when they could be read. The mail digest and the dashboard have them."
                    % (notice["n"], md(notice["first"] or "?"), md(notice["last"] or "?"),
                       notice["hours"]))
        return [{"topic": self.c["topic"], "content": part}
                for part in render_zulip(groups, total, options["level"], options["dashboard"],
                                         context, text)]

    def daily(self, info):
        content = daily_zulip(info["context"], info["options"], info["daily"], info["t"],
                              info["levels"], info["top"], info["stopped"], info["failure"],
                              info["others"], info["warnings"])
        return [{"topic": self.c["summary_topic"], "content": part} for part in pack([content])]

    def preview(self, item):
        return item["content"]

    def post(self, item):
        zulip_post(self.c, item["topic"], item["content"])

    def check(self):
        return check_zulip(self.c, self.fatal)


# --------------------------------------------------------------------------
# Reporting into the manager's own event queue
# --------------------------------------------------------------------------

_QUEUE = None
_NODE = ""


def emit(event, **fields):
    """Put a status event where someone will see it.

    A notifier that stops working cannot announce that by mail, and nobody
    reads a log file. Writing to the manager's own queue turns the event into
    an ordinary alert: the built-in json decoder decodes it and rules
    131110-131116 match its jt_alert_digest.event field (131121-131126 when
    jt_alert_digest.channel is "zulip", 131131-131196 for the other channels,
    ten IDs each; mail events carry no channel, as in 1.4).
    """
    body = {"event": event, "node": _NODE}
    for key, value in fields.items():
        if value is None:
            continue
        body[key] = value if isinstance(value, (int, float)) else trim(redact(value), 300)
    payload = "1:jt-alert-digest:" + json.dumps({"jt_alert_digest": body},
                                                ensure_ascii=False, separators=(",", ":"))
    if not _QUEUE:
        sys.stderr.write("jt-alert-digest: no event queue for: %s\n" % payload)
        return
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.connect(_QUEUE)
            sock.send(payload.encode("utf-8", "replace"))
        finally:
            sock.close()
    except OSError as exc:
        sys.stderr.write("jt-alert-digest: event queue refused (%s): %s\n" % (exc, payload))


def local_iso(epoch):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch)) if epoch else ""


def note_failure(state, kind, text, pending, oldest, server, silent=False, channel=None,
                 permanent=False):
    """Report a failed send without reporting it every two minutes.

    1.3 raised the same level 10 alert on every run: 703 identical alerts a
    day on a node whose mail was refused for three weeks, and none of them
    said how old the backlog was. Here: once when the failure starts or
    changes, then hourly; at level 12 once nothing has been delivered for two
    hours, then every six.
    """
    t = now()
    failure = state.get("failure")
    if not isinstance(failure, dict):
        failure = None
    changed = failure is None or failure.get("kind") != kind
    if failure is None:
        failure = {"since": t, "attempts": 0, "reported": 0, "escalated": 0}
    failure.update({"kind": kind, "error": text, "pending": pending,
                    "oldest": oldest[1] if oldest else failure.get("oldest")})
    failure["attempts"] = failure.get("attempts", 0) + 1
    state["failure"] = failure
    daily = state.get("daily")
    if isinstance(daily, dict):
        daily["failures"] = daily.get("failures", 0) + 1
    if silent:
        failure["reported"] = t
        return
    prefix = ("%s: " % channel) if channel else ""
    if permanent:
        # A refused key or a channel the bot may not post to: a configuration
        # problem (level 12), not a delay, so no two-hour escalation either.
        if changed or t - failure.get("reported", 0) >= ESCALATE_EVERY:
            emit("config_error", channel=channel, problem=text, error_class=kind)
            failure["reported"] = t
            log("%scannot deliver with this configuration (%s): %s" % (prefix, kind, text))
        return
    age_from = oldest[0] if oldest else failure["since"]
    age = int(max(0, t - min(age_from, failure["since"])) // 60)
    fields = dict(error_class=kind, error=text, server=server, pending=pending,
                  oldest=failure.get("oldest") or "", age_minutes=age,
                  attempts=failure["attempts"], failing_since=local_iso(failure["since"]))
    if changed or t - failure.get("reported", 0) >= REPORT_EVERY:
        emit("delivery_failed", channel=channel, **fields)
        failure["reported"] = t
        log("%scannot deliver (%s): %s; %s alerts waiting%s"
            % (prefix, kind, text, pending,
               (", oldest " + failure["oldest"]) if failure.get("oldest") else ""))
    if age * 60 >= STALE_AFTER and t - failure.get("escalated", 0) >= ESCALATE_EVERY:
        emit("undelivered", channel=channel, **fields)
        failure["escalated"] = t
        log("%salerts have reached nobody for %d minutes" % (prefix, age))


def note_success(state, sent, channel=None):
    failure = state.pop("failure", None)
    if isinstance(failure, dict):
        minutes = int(max(0, now() - failure.get("since", now())) // 60)
        emit("recovered", channel=channel, sent_late=sent, failed_minutes=minutes,
             failing_since=local_iso(failure.get("since")), attempts=failure.get("attempts", 0),
             error_class=failure.get("kind", ""))
        log("%sdelivering again after %d minutes (%s); %d alerts sent late"
            % (("%s: " % channel) if channel else "", minutes, failure.get("kind", ""), sent))


def note_config(state, fatal, channel=None):
    """131116 (131126 for Zulip) for a configuration that cannot deliver: on
    change, then every six hours."""
    prefix = ("%s: " % channel) if channel else ""
    if not fatal:
        if state.pop("config_error", None):
            log("%sconfiguration problem resolved" % prefix)
        return
    signature = "; ".join(fatal)
    previous = state.get("config_error") or {}
    if previous.get("sig") != signature or now() - previous.get("reported", 0) >= ESCALATE_EVERY:
        emit("config_error", channel=channel, problem=signature)
        log("%sconfiguration makes delivery impossible: %s" % (prefix, signature))
        state["config_error"] = {"sig": signature, "reported": now()}


def note_lost(state, lost, channel=None):
    """131113 (131123 for Zulip), once per reason: a loss is an event, not a
    condition to repeat."""
    reported = state.setdefault("lost", {})
    for reason in lost:
        if reason in reported:
            continue
        emit("skipped", channel=channel, reason=reason)
        log("%salerts skipped: %s" % (("%s: " % channel) if channel else "", reason))
        reported[reason] = now()


# --------------------------------------------------------------------------
# Daily summary: a missing summary is the sign that the notifier is dead
# --------------------------------------------------------------------------

def daily_due(state, options):
    if not options.get("daily"):
        return False
    daily = state.get("daily")
    if not isinstance(daily, dict):
        return False
    lt = time.localtime(now())
    today = time.strftime("%Y-%m-%d", lt)
    hour, minute = options["daily"]
    return daily.get("last") != today and (lt.tm_hour, lt.tm_min) >= (hour, minute)


def new_daily(last=None):
    return {"last": last, "since": now(), "levels": {}, "qualifying": 0, "digests": 0,
            "mailed": 0, "held": 0, "excluded": 0, "failures": 0, "unparsed": 0,
            "rules": {}, "stops": {}, "disconnects": {}}


def init_daily(options):
    """Start counting; the first summary goes out at the next due time."""
    lt = time.localtime(now())
    last = None
    if options.get("daily") and (lt.tm_hour, lt.tm_min) >= options["daily"]:
        last = time.strftime("%Y-%m-%d", lt)
    return new_daily(last)


def agent_event(alert):
    """("started"|"stopped"|"disconnected", agent name) or None."""
    log = alert.get("full_log") or ""
    if "Agent " not in log:
        return None
    match = AGENT_EVENT.search(log)
    if not match:
        return None
    name = re.sub(r"(?:->.*|-any|-[0-9a-fA-F.:]+)$", "", match.group(2))
    if not name:
        name = str((alert.get("agent") or {}).get("name", "?"))
    return match.group(1), name


def count_batch(state, batch, mailed, held):
    daily = state.get("daily")
    if not isinstance(daily, dict):
        return
    for level, n in batch.levels.items():
        daily["levels"][str(level)] = daily["levels"].get(str(level), 0) + n
    daily["qualifying"] += batch.total
    daily["mailed"] += mailed
    daily["held"] += held
    daily["excluded"] += batch.excluded
    daily["unparsed"] += batch.unparsed
    rules = daily["rules"]
    for (rule_id, _), group in batch.groups.items():
        entry = rules.get(rule_id) or [0, group["level"], heading(group, rule_id)]
        entry[0] += group["count"]
        entry[1] = max(entry[1], group["level"])
        rules[rule_id] = entry
    if len(rules) > 300:
        daily["rules"] = dict(sorted(rules.items(), key=lambda kv: -kv[1][0])[:200])
    for alert in batch.health:
        found = agent_event(alert)
        if not found:
            continue
        kind, name = found
        stamp = parse_ts(alert.get("timestamp")) or now()
        if kind == "stopped":
            daily["stops"][name] = stamp
        elif kind == "started":
            daily["stops"].pop(name, None)
        else:
            daily["disconnects"][name] = daily["disconnects"].get(name, 0) + 1


def render_daily(state, options, context, warnings, others=()):
    info = daily_info(state, options, context, warnings, others)
    daily, t, stopped, levels, top, failure = (info[k] for k in ("daily", "t", "stopped", "levels",
                                                                 "top", "failure"))
    lines = ["Daily summary from %s%s, %s to %s"
             % (context["node"], (" (%s)" % context["node_type"]) if context.get("node_type") else "",
                local_iso(daily.get("since")), local_iso(t)), ""]
    lines.append("Alerts written: %s" % (", ".join("L%d: %s" % (k, "{:,}".format(v))
                                                    for k, v in levels) or "none"))
    lines.append("At mail level (L%d+): %s; digests sent: %d; alerts in them: %s; repeats held "
                 "back: %s; excluded by settings: %s"
                 % (options["level"], "{:,}".format(daily.get("qualifying", 0)),
                    daily.get("digests", 0), "{:,}".format(daily.get("mailed", 0)),
                    "{:,}".format(daily.get("held", 0)), "{:,}".format(daily.get("excluded", 0))))
    if isinstance(failure, dict):
        lines.append("Delivery: FAILING since %s (%s, %d attempts), %s alerts waiting%s"
                     % (local_iso(failure.get("since")), failure.get("kind", "?"),
                        failure.get("attempts", 0), failure.get("pending", "?"),
                        (", oldest " + failure["oldest"]) if failure.get("oldest") else ""))
    else:
        lines.append("Delivery: working (%d failed attempts in this period)"
                     % daily.get("failures", 0))
    for name, other in others:
        lines.append("%s: %s" % (name, ("FAILING since %s (%s)" % (local_iso(other.get("since")),
                                                                    other.get("kind", "?")))
                                 if isinstance(other, dict) else "working"))
    if daily.get("unparsed"):
        lines.append("Unreadable lines in the alert file: %d" % daily["unparsed"])
    if top:
        lines.append("")
        lines.append("Most frequent rules at mail level:")
        for rule_id, (count, level, text) in top:
            lines.append("  rule %s L%d x%s - %s" % (rule_id, level, "{:,}".format(count),
                                                     trim(name_tokens(text), 90)))
    if stopped:
        lines.append("")
        lines.append("Agents that stopped and did not start again within %d minutes:"
                     % (STOP_GRACE // 60))
        for name, stamp in stopped:
            lines.append("  %s (stopped %s)" % (name, local_iso(stamp)))
    if daily.get("disconnects"):
        lines.append("")
        lines.append("Agents reported disconnected: " + ", ".join(
            "%s (x%d)" % (n, c) for n, c in sorted(daily["disconnects"].items())))
    if warnings:
        lines.append("")
        lines.append("Settings ignored: " + "; ".join(warnings))
    lines.append("")
    lines.append("--")
    lines.append("jt-alert-digest %s on %s; this summary is sent once a day, so a day "
                 "without one means the digest is not running." % (VERSION, context["node"]))
    if options.get("dashboard"):
        lines.append(options["dashboard"])
    text = "\n".join(lines)
    html = ('<div style="margin:0;padding:20px 12px;background:#eef0f3;font-family:%s;color:%s;">'
            '<div style="max-width:720px;margin:0 auto;background:#ffffff;border:1px solid %s;'
            'border-radius:10px;padding:16px 18px;font-size:13px;line-height:1.5;">'
            '<pre style="margin:0;font-family:%s;font-size:12.5px;white-space:pre-wrap;'
            'overflow-wrap:anywhere;">%s</pre></div></div>' % (SANS, INK, LINE, MONO, esc(text)))
    line = clean_header("[Wazuh] Daily summary %s: %s alerts at L%d+, %d digests%s"
                        % (ascii_only(context["node"]), daily.get("qualifying", 0), options["level"],
                           daily.get("digests", 0),
                           ", DELIVERY FAILING" if isinstance(failure, dict) else ""))
    shown = [name for name, _ in stopped]
    zulip = daily_zulip(context, options, daily, t, levels, top, stopped, failure, others, warnings)
    return line, text, html, shown, zulip


DAILY_LIST = 8   # longer lists of agents are collapsed


def daily_zulip(context, options, daily, t, levels, top, stopped, failure, others, warnings):
    """The daily summary in Zulip markdown, laid out like the alert cards."""
    trouble = isinstance(failure, dict) or any(isinstance(o, dict) for _, o in others)
    bar = ("\U0001F7E5" if trouble else "\U0001F7E9") * BAR_WIDTH
    head = "%s\n\U0001F4CA **Daily summary \u00b7 %s%s**\n*%s \u2192 %s*" % (
        bar, md(context["node"]), (" (%s)" % md(context["node_type"])) if context.get("node_type") else "",
        md(local_iso(daily.get("since"))[:16]), md(local_iso(t)[:16]))
    rows, below = [], []

    def place(label, value):
        if fits_table(label, value):
            rows.append("| %s | %s |" % (md(label), md(value)))
        else:
            below.append("**%s** %s" % (md(label), md(value)))

    place("L%d+ alerts" % options["level"], "{:,}".format(daily.get("qualifying", 0)))
    place("Digests sent", "{:,}".format(daily.get("digests", 0)))
    place("Alerts in them", "{:,}".format(daily.get("mailed", 0)))
    place("Repeats held", "{:,}".format(daily.get("held", 0)))
    if daily.get("excluded"):
        place("Excluded", "{:,}".format(daily["excluded"]))
    if isinstance(failure, dict):
        place("Delivery", "\u274c failing since %s (%s, %d attempts), %s alerts waiting"
              % (local_iso(failure.get("since"))[:16], failure.get("kind", "?"),
                 failure.get("attempts", 0), failure.get("pending", "?")))
    else:
        place("Delivery", "\u2705 working" + ((" (%d failed tries)" % daily["failures"])
                                              if daily.get("failures") else ""))
    for name, other in others:
        place(name, ("\u274c failing since %s (%s)" % (local_iso(other.get("since"))[:16],
                                                       other.get("kind", "?")))
              if isinstance(other, dict) else "\u2705 working")
    if daily.get("unparsed"):
        place("Unreadable lines", "{:,}".format(daily["unparsed"]))
    blocks = [head, "\n".join(["| Item | Value |", "|:--|:--|"] + rows)]
    if below:
        blocks.append(md_quote(below))
    if levels:
        blocks.append("**Alerts written by level**\n" + md_quote(
            [" \u00b7 ".join("L%d %s" % (k, "{:,}".format(v)) for k, v in levels)]))
    if top:
        blocks.append("**Most frequent at L%d+**\n" % options["level"] + "\n".join(
            "- %s **L%d** \u00b7 rule %s \u00d7%s \u00b7 %s"
            % (level_mark(level), level, md(rule_id), "{:,}".format(count),
               md(trim(name_tokens(text), 90)))
            for rule_id, (count, level, text) in top))

    def listed(title, items):
        lines = ["- " + item for item in items]
        if len(lines) > DAILY_LIST:
            return "**%s** (%d)\n%s" % (title, len(lines), spoiler_text("Show all", items))
        return "**%s** (%d)\n%s" % (title, len(lines), "\n".join(lines))

    if stopped:
        blocks.append(listed("Agents stopped and not back within %d minutes" % (STOP_GRACE // 60),
                             ["%s \u00b7 %s" % (md(n), md(local_iso(st)[5:16])) for n, st in stopped]))
    if daily.get("disconnects"):
        blocks.append(listed("Agents reported disconnected",
                             ["%s \u00d7%d" % (md(n), c) for n, c in sorted(daily["disconnects"].items())]))
    if warnings:
        blocks.append(md_quote(["**Settings ignored** " + md("; ".join(warnings))]))
    foot = "*jt-alert-digest %s on %s \u00b7 sent once a day; a day without one means the digest is not running*" % (
        VERSION, md(context["node"]))
    if options.get("dashboard") and re.match(r"^https?://", options["dashboard"]):
        foot += " \u00b7 [dashboard](%s)" % md_link(options["dashboard"])
    blocks.append(foot)
    return "\n\n".join(blocks)


# --------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------

def trim_log(path):
    """Keep the cron log bounded: the worker's had 14,622 identical lines."""
    try:
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= LOG_CAP:
            return
        with open(path, "r+b") as fh:
            fh.seek(-(LOG_CAP // 2), 2)
            tail = fh.read()
            cut = tail.find(b"\n")
            tail = tail[cut + 1:] if cut >= 0 else tail
            fh.seek(0)
            fh.write(b"[earlier lines trimmed by jt-alert-digest]\n" + tail)
            fh.truncate()
    except OSError:
        pass


def take_lock(path):
    """Two overlapping runs would both mail the same alerts."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def is_held(state, options, key, group):
    """A repeat of a group mailed within the hold time, at no higher a level.

    Never held: a group not mailed before for this agent, one whose level
    rose, or one marked NEW. Held alerts are counted and appear as one line
    in the next message, never dropped.
    """
    if options.get("repeat", 0) <= 0 or group.get("new"):
        return False
    mailed = state["mailed"].get(key)
    if not mailed:
        return False
    return now() - mailed[0] < options["repeat"] and group["level"] <= mailed[1]


def mark_new(state, groups):
    seen = state["seen"]
    learning = now() - seen.get("start", now()) < LEARN_FOR
    for (rule_id, agent), group in groups.items():
        if learning:
            group["new"] = None
        elif rule_id not in seen["rules"]:
            group["new"] = "rule"
        elif gkey(rule_id, agent) not in seen["pairs"]:
            group["new"] = "pair"
        else:
            group["new"] = None


def remember(state, groups):
    t = now()
    for (rule_id, agent), group in groups.items():
        state["seen"]["pairs"][gkey(rule_id, agent)] = t
        state["seen"]["rules"][rule_id] = t


def merge_held(state, held_groups):
    merged = {k: dict(v) for k, v in state["held"].items() if isinstance(v, dict)}
    for (rule_id, agent), group in held_groups.items():
        key = gkey(rule_id, agent)
        entry = merged.setdefault(key, {"rule": rule_id, "agent": agent, "n": 0,
                                        "first": group["first"], "level": group["level"],
                                        "heading": heading(group, rule_id),
                                        "mailed": (state["mailed"].get(key) or [now()])[0]})
        entry["n"] += group["count"]
        entry["last"] = group["last"]
        entry["level"] = max(entry.get("level", 0), group["level"])
    return merged


def make_context(config, options):
    return {"node": config["node"], "node_type": config["node_type"], "link": options.get("link"),
            "base": options.get("base", ""), "repeat": options.get("repeat", 3600)}


def run(args):
    wazuh = os.path.abspath(args.wazuh_path)
    global _QUEUE, _NODE
    queue = os.path.join(wazuh, "queue", "sockets", "queue")
    quiet = args.dry_run or args.check or args.test
    _QUEUE = queue if os.path.exists(queue) and not quiet else None

    try:
        config = read_global_config(wazuh)
    except ConfigUnreadable as exc:
        _NODE = socket.gethostname()
        if not quiet:
            emit("config_error", problem=str(exc))
        sys.stderr.write("jt-alert-digest: %s\n" % exc)
        return 2
    _NODE = config["node"]
    site = read_site_settings(wazuh)
    options, fatal, warnings = build_options(site, config, args)
    warnings.extend(load_names(site, wazuh))
    context = make_context(config, options)

    if args.check:
        return check(wazuh, config, options, fatal, warnings)
    if args.test and args.test != "mail":
        return send_test_channel(options, context, args.test)
    if args.test:
        return send_test(options, fatal, context)
    if args.dry_run:
        return digest(wazuh, options, fatal, warnings, context, dry_run=True, html=args.html)

    lock = take_lock(os.path.join(wazuh, "var", "jt-alert-digest.lock"))
    if lock is None:
        return 0
    agents_path = os.path.join(wazuh, "var", "jt-alert-digest.agents")
    try:
        trim_log(os.path.join(wazuh, "logs", "jt-alert-digest.log"))
        load_agents(agents_path)
        return digest(wazuh, options, fatal, warnings, context)
    finally:
        save_agents(agents_path)
        os.close(lock)


def new_channel_state(position, options):
    sub = fresh_state(position)
    del sub["v"]
    sub["daily"] = init_daily(options)
    return sub


def digest(wazuh, options, fatal, warnings, context, dry_run=False, html=False):
    """One run: each channel reads what is new to it, sends, and keeps its own place.

    Mail keeps the top level of the state file, exactly as in 1.4; each chat or
    webhook channel, when configured, keeps its own position, holds and failure
    record under its name ("zulip", "teams", "telegram", ...). No channel's
    failure or crash moves, loses or repeats another's work.
    """
    alerts_path = os.path.join(wazuh, "logs", "alerts", "alerts.json")
    state_path = os.path.join(wazuh, "var", "jt-alert-digest.state")
    channels = options.get("channels") or []
    try:
        stat_alerts(alerts_path)
        unreadable = None if os.access(alerts_path, os.R_OK) else "permission denied"
    except OSError as exc:
        unreadable = exc.strerror or str(exc)
    if unreadable:
        fatal = fatal + ["cannot read %s: %s" % (alerts_path, unreadable)]

    state, problem = load_state(state_path)
    if state is None and problem is None:
        if dry_run:
            print("first run: would start at the end of alerts.json and send nothing")
            return 0
        start = end_position(alerts_path) if not unreadable else \
            {"ino": None, "dev": None, "path": None, "offset": 0}
        state = fresh_state(start)
        state["daily"] = init_daily(options)
        for ch in channels:
            state[ch.name] = new_channel_state(dict(start), options)
        note_config(state, fatal)
        save_state(state_path, state)
        log("first run: starting at the end of alerts.json, nothing mailed")
        return 0

    lost = []
    if problem:
        # Not a first run: starting at the end would silently skip everything
        # since the last good position, so start at the top of today's file.
        lost.append("%s; reading again from the start of the current alert file" % problem)
        state = fresh_state({"ino": None, "dev": None, "path": None, "offset": 0})
        if not unreadable:
            info = stat_alerts(alerts_path)
            state["pos"] = {"ino": info.st_ino, "dev": info.st_dev, "offset": 0,
                            "path": find_by_inode(os.path.dirname(alerts_path),
                                                  info.st_ino, info.st_dev)}
        for ch in channels:
            state[ch.name] = new_channel_state(dict(state["pos"]), options)
        if not dry_run:
            # Saved before the loss is reported: a state that cannot be written
            # either ends here as one (deduplicated) crash, not a 131113 per run.
            save_state(state_path, state)

    def persist():
        if not dry_run:
            save_state(state_path, state)

    # Mail. A crash here is reported as in 1.4 (by main), but only after the
    # other channels have had their turn, and with the mail state as it was.
    before = copy.deepcopy(state)
    mail_crash = None
    try:
        code = mail_round(alerts_path, state, options, fatal, warnings, context, lost,
                          unreadable, dry_run, html)
    except Exception:
        mail_crash = sys.exc_info()
        state.clear()
        state.update(before)
        code = 3
    else:
        persist()

    for ch in ([] if unreadable else channels):
        before = copy.deepcopy(state)
        try:
            ccode = channel_round(alerts_path, state, ch, options, context, warnings, dry_run,
                                  persist, channels)
        except Exception:
            traceback.print_exc()
            state.clear()
            state.update(before)
            if not dry_run:
                report_crash(wazuh, ch.name)
            ccode = 3
        else:
            persist()
            if not dry_run:
                clear_crash(wazuh, ch.name)
        code = max(code, ccode)
    if mail_crash:
        raise mail_crash[1].with_traceback(mail_crash[2])
    return code


class Round(object):
    """One channel's view of the alerts that are new to it."""


def prepare(alerts_path, sub, options, lost, dry_run, channel=None, cutoff=None):
    """Plan, read and split one channel's new alerts into full groups and repeats."""
    r = Round()
    segments, more_lost = plan(alerts_path, sub["pos"])
    lost = list(lost) + more_lost
    if lost or sub["pos"].get("legacy"):
        # The starting point moved: a loss, or a 1.3 state converted. Keep the
        # new start even if this run's send fails, so a loss is reported once.
        sub["pos"] = where(segments[0], segments[0]["offset"])
        if not dry_run:
            note_lost(sub, lost, channel)
    if len(segments) == 1 and segments[0]["current"]:
        # Still in the same file: note how much of it exists, so that if it is
        # rotated away before it is read, the loss is known (see plan()).
        sub["pos"]["size"] = max(segments[0]["size"] or 0, sub["pos"].get("offset") or 0)
    batch = Batch(options)
    batch.cutoff = cutoff
    r.end = read_alerts(segments, batch)
    if batch.lost and not dry_run:
        note_lost(sub, batch.lost, channel)
    mark_new(sub, batch.groups)
    r.full, r.held_now = OrderedDict(), OrderedDict()
    for key, group in batch.groups.items():
        (r.held_now if is_held(sub, options, gkey(*key), group) else r.full)[key] = group
    r.merged = merge_held(sub, r.held_now)
    for key, group in r.full.items():
        entry = r.merged.pop(gkey(*key), None)
        if entry:
            group["earlier"] = entry.get("n", 0)
    # A repeat whose hold has run out with nothing new after it: say how many
    # there were rather than let the count wait for the next unrelated alert.
    r.due = [k for k in r.merged
             if now() - (sub["mailed"].get(k) or [0])[0] >= options.get("repeat", 3600)]
    r.held_list = sorted(r.merged.values(), key=lambda e: (-e.get("level", 0), -e.get("n", 0)))
    r.total = sum(g["count"] for g in r.full.values())
    r.held_count = sum(g["count"] for g in r.held_now.values())
    r.sendable = bool(r.full) or bool(r.due)
    r.batch = batch
    r.lost = lost
    return r


def consume(sub, r, shown):
    """The position moves on and the trackers learn what was sent (or held)."""
    if shown:
        for key, group in r.full.items():
            sub["mailed"][gkey(*key)] = [now(), group["level"]]
        sub["held"] = {}
        count_batch(sub, r.batch, r.total, r.held_count)
        sub["daily"]["digests"] = sub["daily"].get("digests", 0) + 1
    else:
        sub["held"] = r.merged
        count_batch(sub, r.batch, 0, r.held_count)
    remember(sub, r.batch.groups)
    sub["pos"] = r.end


def mail_round(alerts_path, state, options, fatal, warnings, context, lost, unreadable,
               dry_run, html):
    if not isinstance(state.get("daily"), dict):
        state["daily"] = init_daily(options)
    prune(state, options.get("repeat", 3600))
    if not dry_run:
        note_config(state, fatal)
    if unreadable:
        return 2
    r = prepare(alerts_path, state, options, lost, dry_run)
    batch = r.batch
    context = dict(context, held=r.held_list, more=batch.more)
    full, total, held_list = r.full, r.total, r.held_list

    if dry_run:
        if r.sendable:
            print("Subject: %s\n" % subject(full, total, held_list))
            print((render_html if html else render_text)(
                full, total, options["level"], options["dashboard"], context))
        elif batch.total:
            print("nothing would be sent: %d alerts repeat groups mailed in the last %d minutes"
                  % (batch.total, options["repeat"] // 60))
        else:
            print("no new alerts at level %d or above" % options["level"])
        for reason in r.lost + batch.lost:
            print("would report: alerts skipped: %s" % reason)
        if fatal:
            print("would report: configuration makes delivery impossible: %s" % "; ".join(fatal))
        return 0

    server_label = options["server"] if options["server"].startswith("/") \
        else "%s:%s" % (options["server"], options["port"])
    delivered = True
    if not r.sendable:
        # Nothing new worth a message: the repeats are counted and the
        # position moves on, so they are not read again.
        consume(state, r, False)
    elif fatal:
        note_failure(state, "config", "; ".join(fatal), batch.total, batch.oldest,
                     server_label, silent=True)
        delivered = False
    elif options.get("max_per_hour") and len(state["sent"]) >= options["max_per_hour"]:
        if not state.get("limited"):
            log("max_per_hour (%d) reached; %d alerts wait for the next run"
                % (options["max_per_hour"], batch.total))
        state["limited"] = now()
        delivered = False
    else:
        state.pop("limited", None)
        message = build_message(
            subject(full, total, held_list),
            render_text(full, total, options["level"], options["dashboard"], context),
            render_html(full, total, options["level"], options["dashboard"], context),
            options, context, total)
        try:
            refused = deliver(message, options)
        except DeliveryError as exc:
            note_failure(state, exc.kind, exc.text, batch.total, batch.oldest, server_label)
            delivered = False
        else:
            if refused:
                log("delivered, but refused for: %s" % ", ".join(sorted(refused)))
            note_success(state, total)
            state["sent"].append(now())
            consume(state, r, True)
            log("sent %d alerts in %d groups%s, %s"
                % (total, len(full),
                   (", %d repeats in %d groups listed as ongoing" %
                    (sum(e.get("n", 0) for e in held_list), len(held_list))) if held_list else "",
                   message["Message-ID"]))

    if delivered and not fatal and daily_due(state, options):
        others = [(ch.label, (state.get(ch.name) or {}).get("failure"))
                  for ch in options.get("channels") or []]
        line, text, body, shown, _ = render_daily(state, options, context, warnings, others)
        message = build_message(line, text, body, options, context)
        try:
            deliver(message, options)
        except DeliveryError as exc:
            note_failure(state, exc.kind, exc.text, batch.total, batch.oldest, server_label)
            delivered = False
        else:
            note_success(state, 0)
            reset_daily(state, shown)
            log("daily summary sent, %s" % message["Message-ID"])
    return 0 if delivered else 1


def reset_daily(sub, shown):
    stops = {n: s for n, s in sub["daily"].get("stops", {}).items() if n not in shown}
    sub["daily"] = new_daily(time.strftime("%Y-%m-%d", time.localtime(now())))
    sub["daily"]["stops"] = stops


def channel_flush(sub, ch, persist):
    """Post the outbox in order, removing each message once the platform has it.

    A batch is moved into the outbox together with the position, in one save,
    before anything is posted. A failure halfway through a multi-part post
    leaves exactly the unposted parts for the next run: nothing is lost and
    nothing already posted is posted again.

    A message the server refuses as malformed (its content, not the sender)
    would block the channel for good if retried forever; after MALFORMED_TRIES
    attempts it is dropped and reported as skipped (the skipped rule of the
    channel). Only the 1.13 channels mark refusals as malformed.
    """
    outbox = sub.get("outbox") or []
    sent = 0
    while outbox:
        item = outbox[0]
        try:
            ch.post(item)
        except DeliveryError as exc:
            if exc.malformed:
                item["tries"] = item.get("tries", 0) + 1
                if item["tries"] >= MALFORMED_TRIES:
                    outbox.pop(0)
                    note_lost(sub, ["%s refused a message as malformed %d times, so it was dropped "
                                    "(%s); %d alerts were in it, and the mail digest has them"
                                    % (ch.label, item["tries"], exc.text, item.get("alerts", 0))],
                              ch.name)
                    persist()
                    continue
            note_failure(sub, exc.kind, exc.text, sum(i.get("alerts", 0) for i in outbox),
                         item.get("oldest"), ch.server(), channel=ch.name, permanent=exc.permanent)
            persist()
            return False
        sent += item.get("alerts", 0)
        outbox.pop(0)
        persist()
    sub.pop("outbox", None)
    note_success(sub, sent, channel=ch.name)
    return True


def channel_round(alerts_path, state, ch, options, context, warnings, dry_run, persist,
                  channels=()):
    """One chat or webhook channel's run, under state[ch.name]; Zulip's since 1.5."""
    name = ch.name
    sub = state.get(name)
    if not isinstance(sub, dict) or not isinstance(sub.get("pos"), dict):
        # Newly configured: start at the end, as a first run does, so the
        # channel does not open with the whole day's backlog.
        if dry_run:
            print("\n----- %s: first run, would start at the end of alerts.json -----" % ch.label)
            return 0
        state[name] = new_channel_state(end_position(alerts_path), options)
        log("%s: first run, starting at the end of alerts.json, nothing posted" % name)
        return 0
    options = ch.options(options)
    for key, default in (("mailed", {}), ("held", {}), ("sent", []),
                         ("seen", {"start": now(), "pairs": {}, "rules": {}})):
        if not isinstance(sub.get(key), type(default)):
            sub[key] = default
    if not isinstance(sub.get("daily"), dict):
        sub["daily"] = init_daily(options)
    prune(sub, options.get("repeat", 3600))
    if not dry_run:
        note_config(sub, ch.fatal, channel=name)
    if ch.fatal:
        if dry_run:
            print("\n----- %s: not posting: %s -----" % (ch.label, "; ".join(ch.fatal)))
        return 2
    if sub.get("outbox"):
        if dry_run:
            print("\n----- %s: %d messages wait in the outbox from an earlier run -----"
                  % (ch.label, len(sub["outbox"])))
            return 0
        if not channel_flush(sub, ch, persist):
            return 1

    # Alerts older than <channel>_max_backlog are counted, not posted: after a
    # long outage the channel says how many it skipped instead of replaying a day.
    max_backlog = ch.c["max_backlog"]
    r = prepare(alerts_path, sub, options, [], dry_run, channel=name, cutoff=now() - max_backlog)
    batch = r.batch
    if batch.dropped:
        dropped = sub.get("dropped") or {"n": 0, "first": batch.dropped_first, "last": None}
        dropped["n"] += batch.dropped
        dropped["first"] = min(filter(None, (dropped.get("first"), batch.dropped_first)))
        dropped["last"] = max(filter(None, (dropped.get("last"), batch.dropped_last)))
        sub["dropped"] = dropped
    notice = None
    dropped = sub.get("dropped")
    if dropped and (r.sendable or not batch.more):
        notice = {"n": dropped["n"], "first": dropped.get("first"), "last": dropped.get("last"),
                  "hours": max_backlog // 3600}
    context = dict(context, held=r.held_list, more=batch.more)
    if dry_run:
        print("\n----- %s -----" % ch.where())
        if r.sendable or notice:
            for item in ch.render(r.full, r.total, options, context, notice):
                print(ch.preview(item))
                print("-----")
        else:
            print("nothing would be posted")
        return 0

    if r.sendable or notice:
        items = ch.render(r.full, r.total, options, context, notice)
        oldest = list(batch.oldest) if batch.oldest else [now(), local_iso(now())]
        for index, item in enumerate(items):
            item["alerts"] = r.total if index == 0 else 0
            item["oldest"] = oldest
        sub["outbox"] = items
        consume(sub, r, r.sendable)
        if notice:
            note_lost(sub, ["%d alerts from %s to %s were older than %d hours and were not posted "
                            "to %s" % (dropped["n"], dropped["first"], dropped["last"],
                                       max_backlog // 3600, ch.label)], name)
            sub.pop("dropped", None)
        persist()
        if not channel_flush(sub, ch, persist):
            return 1
        log("%s: posted %d alerts in %d groups as %d message%s"
            % (name, r.total, len(r.full), len(items), "" if len(items) == 1 else "s"))
    else:
        consume(sub, r, False)

    if daily_due(sub, options):
        others = [("Mail", state.get("failure"))] + [
            (other.label, (state.get(other.name) or {}).get("failure"))
            for other in channels if other.name != name]
        info = daily_info(sub, options, context, warnings, others)
        items = ch.daily(info)
        for item in items:
            item["alerts"] = 0
        sub["outbox"] = items
        reset_daily(sub, [n for n, _ in info["stopped"]])
        persist()
        if not channel_flush(sub, ch, persist):
            return 1
        log("%s: daily summary posted" % name)
    return 0


# --------------------------------------------------------------------------
# --check and --test: see the mail server's answer before an alert depends on it
# --------------------------------------------------------------------------

def check(wazuh, config, options, fatal, warnings):
    """--check: the mail transport, then every chat or webhook channel configured.

    Nothing is sent on either channel and nothing is written.
    """
    code = check_mail(wazuh, config, options, fatal, warnings)
    for ch in options.get("channels") or []:
        code = max(code, ch.check())
    return code


def check_zulip(z, zfatal):
    """Authenticate, find the channel, and say whether the bot can post to it.

    Read-only API calls (GET); the one way to prove posting is --test zulip.
    """
    print("  zulip: %s, bot %s, key file %s, channel %s, topic %s%s%s" % (
        z.get("url") or "-", z.get("email") or "-", z.get("key_file") or "-",
        z.get("stream") or "-", z.get("topic"),
        ("" if z.get("summary_topic") == z.get("topic") else
         ", daily summary topic %s" % z.get("summary_topic")),
        "" if z.get("verify", True) else ", certificate NOT verified"))
    if zfatal:
        for problem in zfatal:
            print("  PROBLEM: zulip: %s" % problem)
        return 1
    try:
        me = zulip_call(z, "GET", "/api/v1/users/me")
    except DeliveryError as exc:
        print("  PROBLEM: zulip: the server refused the bot: %s (%s)" % (exc.text, exc.kind))
        return 1
    print("  zulip auth: accepted as %s <%s>%s" % (me.get("full_name", "?"), me.get("email", "?"),
                                                  " (bot)" if me.get("is_bot") else ""))
    try:
        stream_id = zulip_call(z, "GET", "/api/v1/get_stream_id", {"stream": z["stream"]})["stream_id"]
    except (DeliveryError, KeyError) as exc:
        print("  PROBLEM: zulip: channel %s not found, or it is private and the bot is not "
              "subscribed (%s)" % (z["stream"], getattr(exc, "text", exc)))
        return 1
    subscribed = None
    try:
        subs = zulip_call(z, "GET", "/api/v1/users/me/subscriptions").get("subscriptions") or []
        subscribed = any(s.get("stream_id") == stream_id for s in subs if isinstance(s, dict))
    except DeliveryError:
        pass
    info = {}
    try:
        info = zulip_call(z, "GET", "/api/v1/streams/%d" % int(stream_id)).get("stream") or {}
    except (DeliveryError, ValueError, TypeError):
        pass
    private = info.get("invite_only")
    print("  zulip channel: %s (id %s), %s, bot %s" % (
        z["stream"], stream_id,
        "private" if private else ("public" if private is False else "visibility unknown"),
        "subscribed" if subscribed else ("not subscribed" if subscribed is False
                                         else "subscription unknown")))
    if private and subscribed is False:
        print("  PROBLEM: zulip: a private channel only takes posts from subscribers: "
              "subscribe the bot to %s" % z["stream"])
        return 1
    policy = info.get("stream_post_policy")
    if policy not in (None, 1):
        print("  warning: zulip: only some members may post in %s (stream_post_policy %s)"
              % (z["stream"], policy))
    print("  zulip result: the bot is accepted; --test zulip posts one test message")
    return 0


def names_summary():
    """One line on the account names map, for --check."""
    report = NAMES_REPORT
    if report.get("off"):
        return "off (names_file = off)"
    if not report.get("read"):
        return "none (no names file%s)" % (" could be read" if report.get("refused") else "")
    text = "{:,} entries from ".format(report.get("entries", 0)) + ", ".join(
        "%s ({:,})".format(n) % path for path, n in report["read"])
    if report.get("ignored"):
        text += "; {:,} lines ignored (not \"id: name\")".format(report["ignored"])
    return text


def check_mail(wazuh, config, options, fatal, warnings):
    """Report the settings and walk the SMTP dialogue up to RCPT TO, then RSET.

    Nothing is delivered and nothing is written. On a node whose mail server
    refuses it (a missing PTR record is the usual reason), this prints the
    refusal on the first try instead of after the first alert.
    """
    ok = not fatal
    print("jt-alert-digest %s on %s%s" % (VERSION, config["node"],
                                          (" (%s)" % config["node_type"]) if config["node_type"] else ""))
    server = options.get("server") or "(none)"
    if server.startswith("/"):
        print("  transport: program %s %s" % (server, " ".join(options.get("sendmail_args") or [])))
    else:
        print("  transport: SMTP %s:%s, tls = %s%s%s" % (
            server, options.get("port"), options.get("tls"),
            ", certificate verified" if options.get("verify") else "",
            (", AUTH as %s" % options["user"]) if options.get("user") else ""))
    print("  from: %s" % options.get("email_from"))
    print("  to: %s" % ", ".join(options.get("to") or []))
    print("  level: %d (%s)" % (options["level"], "set explicitly, rule.mail ignored"
                                if options["forced"] else "email_alert_level, honouring rule.mail"))
    print("  repeat hold: %s; daily summary: %s; max per hour: %s" % (
        ("%d min" % (options["repeat"] // 60)) if options["repeat"] else "off",
        ("%02d:%02d" % options["daily"]) if options["daily"] else "off",
        options["max_per_hour"] or "no limit"))
    print("  dashboard: %s; per-group links: %s" % (options.get("dashboard") or "-",
                                                    "on" if options.get("link") else "off"))
    print("  account names: %s" % names_summary())
    refused = [problem for _, problem in NAMES_REPORT.get("refused") or []]
    for problem in refused:
        print("  account names: REFUSED %s" % problem)
    for problem in fatal:
        print("  PROBLEM: %s" % problem)
    for warning in warnings:
        if warning not in refused:
            print("  warning: %s" % warning)

    alerts_path = os.path.join(wazuh, "logs", "alerts", "alerts.json")
    try:
        info = os.stat(alerts_path)
        print("  alerts.json: %s bytes, inode %d, is %s" % (
            "{:,}".format(info.st_size), info.st_ino,
            find_by_inode(os.path.dirname(alerts_path), info.st_ino, info.st_dev)
            or "(no dated name found)"))
    except OSError as exc:
        print("  PROBLEM: alerts.json: %s" % (exc.strerror or exc))
        ok = False
    state, problem = load_state(os.path.join(wazuh, "var", "jt-alert-digest.state"))
    if problem:
        print("  PROBLEM: %s" % problem)
        ok = False
    elif state is None:
        print("  state: none yet (the first run starts at the end of alerts.json)")
    else:
        failure = state.get("failure")
        print("  state: position %s; %s" % (
            json.dumps(state["pos"]), ("FAILING since %s (%s)" % (local_iso(failure.get("since")),
                                                                  failure.get("kind")))
            if isinstance(failure, dict) else "last send succeeded"))
    queue = os.path.join(wazuh, "queue", "sockets", "queue")
    print("  event queue: %s" % ("present" if os.path.exists(queue)
                                 else "MISSING, failures would reach only this log"))
    if fatal:
        return 1
    if server.startswith("/"):
        print("  the program is not run by --check; use --test to send a message through it")
        return 0 if ok else 1
    notes = []
    try:
        session = smtp_open(options, notes=notes)
    except DeliveryError as exc:
        for note in notes:
            print("  " + note)
        print("  PROBLEM: %s (%s)" % (exc.text, exc.kind))
        return 1
    for note in notes:
        print("  " + note)
    try:
        code, reply = session.mail(options["email_from"])
        print("  MAIL FROM: %s %s" % (code, reply.decode("utf-8", "replace")))
        ok = ok and code < 300
        for address in options["to"]:
            code, reply = session.rcpt(address)
            print("  RCPT TO %s: %s %s" % (address, code, reply.decode("utf-8", "replace")))
            ok = ok and code < 300
        session.rset()
    except (smtplib.SMTPException, OSError) as exc:
        print("  PROBLEM: %s" % describe(exc))
        ok = False
    _close(session)
    print("  result: %s" % ("the server accepts this node and every recipient" if ok
                            else "delivery would fail, see above"))
    return 0 if ok else 1


def send_test_zulip(options, context):
    """--test zulip: one message to the configured topic, and no mail."""
    z = options.get("zulip")
    if not z:
        print("PROBLEM: zulip is not configured (no zulip_* settings in jt-alert-digest.conf)")
        return 1
    if options.get("zulip_fatal"):
        for problem in options["zulip_fatal"]:
            print("PROBLEM: zulip: %s" % problem)
        return 1
    content = ("**jt-alert-digest %s test message** from %s\nIf you can read this, alert digests "
               "from this node reach this topic. Nothing was read from the alert file, nothing "
               "was changed and no mail was sent. Below, an invented alert shows the layout."
               % (VERSION, md(context["node"])))
    content += "\n\n" + zulip_group("100001", "example-host", sample_group(), 3)
    try:
        answer = zulip_post(z, z["topic"], content)
    except DeliveryError as exc:
        print("not posted: %s (%s)" % (exc.text, exc.kind))
        return 1
    print("posted message %s to %s > %s" % (answer.get("id", "?"), z["stream"], z["topic"]))
    return 0


def send_test_channel(options, context, name):
    """--test <channel>: one test message to that channel only, and no mail."""
    if name == "zulip":
        return send_test_zulip(options, context)
    ch = next((c for c in options.get("channels") or [] if c.name == name), None)
    if ch is None:
        print("PROBLEM: %s is not configured (no %s_* settings in jt-alert-digest.conf)" % (name, name))
        return 1
    if ch.fatal:
        for problem in ch.fatal:
            print("PROBLEM: %s: %s" % (name, problem))
        return 1
    items = ch.test_items(context)
    try:
        for item in items:
            ch.post(item)
    except DeliveryError as exc:
        print("not posted: %s (%s)" % (exc.text, exc.kind))
        return 1
    print("posted a test message (%d part%s) to %s" % (len(items), "" if len(items) == 1 else "s",
                                                       ch.where()))
    return 0


def sample_group():
    """An invented alert for --test <channel>, so the layout can be seen before a real one."""
    groups = {}
    alert = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000%z", time.localtime(now())), "agent": {"id": "001", "name": "example-host",
                                                            "ip": "192.0.2.10"},
             "rule": {"id": "100001", "level": 12, "description": "Example: login after repeated "
                      "failures (this is a test, not an alert)",
                      "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}},
             "data": {"srcip": "203.0.113.7", "dstuser": "alice"},
             "full_log": "Oct 19 09:00:00 example-host sshd[4242]: Accepted password for alice "
                         "from 203.0.113.7 port 52344 ssh2"}
    add_alert(groups, alert, alert["rule"], 12)
    return list(groups.values())[0]


def send_test(options, fatal, context):
    if fatal:
        for problem in fatal:
            print("PROBLEM: %s" % problem)
        return 1
    text = ("This is a test message from jt-alert-digest %s on %s.\n\nIf you can read it, "
            "alert digests from this node reach you. Nothing was read from the alert file "
            "and nothing was changed." % (VERSION, context["node"]))
    html = ('<div style="font-family:%s;font-size:14px;color:%s;">%s</div>'
            % (SANS, INK, esc(text).replace("\n", "<br>")))
    message = build_message("[Wazuh] jt-alert-digest test message from %s" % context["node"],
                            text, html, options, context)
    try:
        refused = deliver(message, options)
    except DeliveryError as exc:
        print("not delivered: %s (%s)" % (exc.text, exc.kind))
        return 1
    print("sent %s to %s%s" % (message["Message-ID"], ", ".join(options["to"]),
                               ("; refused for " + ", ".join(sorted(refused))) if refused else ""))
    return 0


# --------------------------------------------------------------------------

def crash_file(wazuh, channel=None):
    return os.path.join(wazuh, "var", "jt-alert-digest%s.crash" % (("-" + channel) if channel else ""))


def clear_crash(wazuh, channel=None):
    path = crash_file(wazuh, channel)
    if os.path.exists(path):
        try:
            os.remove(path)
            log("%srunning normally again after a crash" % (("%s: " % channel) if channel else ""))
        except OSError:
            pass


def report_crash(wazuh, channel=None):
    """131115 (131125 for Zulip), once per kind of crash and then hourly."""
    kind, value, tb = sys.exc_info()
    frames = traceback.extract_tb(tb)
    spot = "%s:%d" % (os.path.basename(frames[-1].filename), frames[-1].lineno) if frames else "?"
    signature = "%s at %s" % (kind.__name__ if kind else "?", spot)
    path = crash_file(wazuh, channel)
    previous = {}
    try:
        with open(path, encoding="utf-8") as fh:
            previous = json.load(fh)
    except (OSError, ValueError):
        pass
    if not isinstance(previous, dict):
        previous = {}
    if previous.get("sig") != signature or now() - previous.get("reported", 0) >= REPORT_EVERY:
        emit("crashed", channel=channel, exception=signature, error="%s" % value)
        previous = {"sig": signature, "reported": now()}
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(previous, fh)
        except OSError:
            pass


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--wazuh-path", default=DEFAULT_WAZUH,
                        help="manager installation root (default %s)" % DEFAULT_WAZUH)
    parser.add_argument("--level", type=int,
                        help="minimum alert level; defaults to email_alert_level")
    parser.add_argument("--to", action="append",
                        help="recipient; defaults to email_to from <global> in ossec.conf")
    parser.add_argument("--dashboard", help="URL printed at the foot of the message")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the message instead of sending it; change nothing")
    parser.add_argument("--html", action="store_true",
                        help="with --dry-run, print the HTML part")
    parser.add_argument("--check", action="store_true",
                        help="show the settings, test the mail server up to RCPT TO and each "
                             "chat channel's credentials where that can be done without posting")
    parser.add_argument("--test", nargs="?", const="mail",
                        choices=("mail", "zulip") + tuple(CHANNEL_CLASSES),
                        help="send one test message by mail (default) or to one channel, nothing else")
    parser.add_argument("--version", action="version", version="jt-alert-digest " + VERSION)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    quiet = args.dry_run or args.check or args.test
    wazuh = os.path.abspath(args.wazuh_path)
    try:
        code = run(args)
    except KeyboardInterrupt:
        return 130
    except Exception:
        traceback.print_exc()
        if not quiet:
            report_crash(wazuh)
        return 3
    if not quiet:
        clear_crash(wazuh)
    return code


if __name__ == "__main__":
    sys.exit(main())
