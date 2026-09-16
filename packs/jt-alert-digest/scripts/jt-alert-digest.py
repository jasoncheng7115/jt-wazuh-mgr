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

Configuration comes from the manager's own ossec.conf <global> section:
smtp_server, email_from, email_to and email_alert_level are already set
there for wazuh-maild, so this needs no configuration of its own and
cannot drift away from it.

Position in the alert file is kept in a state file. A send that fails
leaves the position alone, so the next run retries rather than losing the
alerts. The first run ever records the end of the file and sends nothing,
because mailing the whole backlog is not a useful way to start.

The message is sent as HTML with a plain text alternative. That is not
decoration: the first version aligned its fields with spaces, and every
mail client rewrapped the long lines and destroyed the alignment, which
left it no easier to read than what it replaced. A table holds its shape.

Once this is delivering, turn wazuh-maild off, or both will send:
set <email_alert_level> to 15, or <email_notification> to no.
"""

import argparse
import json
import os
import re
import smtplib
import socket
import sys
from collections import OrderedDict
from email.message import EmailMessage
from email.utils import formatdate

DEFAULT_WAZUH = "/var/ossec"
MAX_GROUPS = 40       # how many rule/agent groups one message lists
MAX_SAMPLES = 3       # how many instances are shown per group
MAX_ALERTS = 5000     # ceiling for one run, so a backlog cannot exhaust memory
MAX_FIELD = 200       # longest single value printed

SEVERITY = {12: "[HIGH]", 13: "[HIGH]", 14: "[CRITICAL]", 15: "[CRITICAL]"}

# Mail clients strip <style> blocks unpredictably, so every rule is inlined.
# The palette is fixed rather than theme-aware for the same reason: a client
# that inverts colours for dark mode does so to whatever is declared, and a
# half-declared palette is what produces unreadable mail.
INK = "#16191d"
MUTED = "#6b7280"
FAINT = "#9aa1ab"
LINE = "#e3e6ea"
PANEL = "#f6f7f9"
BAND = {12: "#c2410c", 13: "#b91c1c", 14: "#991b1b", 15: "#7f1d1d"}
MONO = ("ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, "
        "'Liberation Mono', monospace")
SANS = ("-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, "
        "'Helvetica Neue', Arial, sans-serif")


# --------------------------------------------------------------------------
# Configuration, read from the manager rather than duplicated here
# --------------------------------------------------------------------------

def read_global_config(wazuh):
    """Pull the mail settings out of ossec.conf.

    ossec.conf is not a single XML document: it is a sequence of top level
    <ossec_config> blocks, so an XML parser rejects it. The settings wanted
    here are flat text inside <global>, and a targeted scan is both simpler
    and immune to the parts of the file this has no business reading.
    """
    path = os.path.join(wazuh, "etc", "ossec.conf")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
    except OSError as exc:
        raise SystemExit("cannot read %s: %s" % (path, exc))

    # Comments may contain example settings; remove them before scanning.
    body = re.sub(r"<!--.*?-->", "", body, flags=re.S)

    def one(tag, default=None):
        found = re.findall(r"<%s>\s*(.*?)\s*</%s>" % (tag, tag), body)
        return found[0] if found else default

    def many(tag):
        return [v for v in re.findall(r"<%s>\s*(.*?)\s*</%s>" % (tag, tag), body) if v]

    try:
        level = int(one("email_alert_level", "12"))
    except (TypeError, ValueError):
        level = 12

    return {
        "smtp_server": one("smtp_server"),
        "email_from": one("email_from"),
        "email_to": many("email_to"),
        "level": level,
    }


# --------------------------------------------------------------------------
# Reading the alert file
# --------------------------------------------------------------------------

def read_offset(state):
    try:
        with open(state) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def write_offset(state, value):
    tmp = state + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(str(value))
    os.replace(tmp, state)


def collect(alerts_path, state, min_level):
    """Return (groups, total, new_offset).

    new_offset is None only when the alert file cannot be read at all.
    """
    try:
        size = os.path.getsize(alerts_path)
    except OSError as exc:
        report_failure("cannot read %s: %s" % (alerts_path, exc))
        return None, 0, None

    offset = read_offset(state)
    if offset is None:
        # First run: remember where we are, do not mail the backlog.
        return OrderedDict(), 0, size
    if offset > size:
        offset = 0          # the file was rotated

    groups = OrderedDict()
    total = 0
    with open(alerts_path, errors="replace") as fh:
        fh.seek(offset)
        for line in fh:
            if total >= MAX_ALERTS:
                break
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except ValueError:
                continue
            rule = alert.get("rule") or {}
            try:
                level = int(rule.get("level", 0))
            except (TypeError, ValueError):
                continue
            if level < min_level:
                continue

            key = (rule.get("id", "?"), (alert.get("agent") or {}).get("name", "?"))
            group = groups.setdefault(key, {
                "level": level,
                "descriptions": [],
                "mitre": (rule.get("mitre") or {}).get("id", []),
                "count": 0,
                "first": alert.get("timestamp", ""),
                "last": alert.get("timestamp", ""),
                "samples": [],
            })
            group["count"] += 1
            group["last"] = alert.get("timestamp", group["last"])
            description = rule.get("description", "")
            if description and description not in group["descriptions"] \
                    and len(group["descriptions"]) < 50:
                group["descriptions"].append(description)
            if len(group["samples"]) < MAX_SAMPLES:
                group["samples"].append(alert)
            total += 1
        new_offset = fh.tell()
    return groups, total, new_offset


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


SEVERITY_MARKER = re.compile(r"^\[(?:CRITICAL|HIGH|WARN|WARNING|INFO|LOW)\]\s*")


def shared_prefix(values):
    """The part of a description that belongs to the rule, not to one alert.

    Wazuh interpolates $(field) into <description>, so every alert from one
    rule carries a different string. Taking the first one puts a single
    alert's address or path into a heading that covers a dozen of them,
    which is worse than saying less.
    """
    values = [SEVERITY_MARKER.sub("", v) for v in values if v]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    low, high = min(values), max(values)
    index = 0
    while index < len(low) and index < len(high) and low[index] == high[index]:
        index += 1
    prefix = low[:index].rstrip()
    for separator in (":", "-", ",", "("):
        if prefix.endswith(separator):
            prefix = prefix[:-1].rstrip()
    return prefix + " ..." if index < len(low) else prefix


def trim(value, limit=MAX_FIELD):
    value = " ".join(str(value).split())
    return value if len(value) <= limit else value[:limit - 1] + "..."


def interesting_fields(alert):
    """The handful of fields that say what this alert was about.

    Chosen per alert shape rather than printed wholesale: a file integrity
    event and a web access log have nothing in common, and printing every
    decoded field is exactly what makes the stock mail unreadable.
    """
    out = []

    syscheck = alert.get("syscheck")
    if syscheck:
        out.append(("File", "%s  (%s)" % (syscheck.get("path", "?"),
                                          syscheck.get("event", "?"))))
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
            out.append(("Attributes", "  ".join(attributes)))
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

    if data.get("vhost") or data.get("request") or data.get("http_status"):
        source = data.get("remote_addr") or data.get("srcip") \
            or alert.get("srcip") or "?"
        out.append(("Source", "%s  ->  %s" % (source, data.get("vhost", "?"))))
        request = data.get("request") or \
            ("%s %s" % (data.get("method", ""), data.get("path", ""))).strip()
        if request:
            out.append(("Request", "%s   -> %s" % (request,
                                                   data.get("http_status", "?"))))
        if data.get("user_agent"):
            out.append(("Client", trim(data["user_agent"], 70)))
        return out

    audit = data.get("audit") or {}
    if audit:
        name = (audit.get("file") or {}).get("name")
        if name:
            out.append(("File", name))
        if audit.get("exe"):
            out.append(("Exec", audit["exe"]))
        who = (audit.get("effective_user") or {}).get("name") or audit.get("auid")
        if who:
            out.append(("User", str(who)))
        if out:
            return out

    source = data.get("srcip") or alert.get("srcip")
    if source:
        out.append(("Source", str(source)))
    if data.get("dstuser"):
        out.append(("Account", data["dstuser"]))
    full_log = (alert.get("full_log") or "").strip()
    if full_log:
        out.append(("Log", trim(full_log)))
    return out


def ordered_groups(groups):
    return sorted(groups.items(), key=lambda kv: (-kv[1]["level"], -kv[1]["count"]))


def headline(group):
    span = clock(group["first"])
    if group["count"] > 1 and clock(group["last"]) != span:
        span = "%s-%s" % (span, clock(group["last"]))
    return "%s %s" % (day(group["first"]), span)


def render_text(groups, total, min_level, dashboard):
    """The plain text alternative.

    Deliberately not column aligned. The first version of this padded every
    label to a fixed width, which looks right in a terminal and is destroyed
    by the first mail client that rewraps a long line. Here the label ends in
    a colon and the value follows, so a rewrap costs nothing.
    """
    lines = ["%d alerts at level %d or above, %d rules, %d hosts"
             % (total, min_level, len(groups), len({k[1] for k in groups})), ""]
    items = ordered_groups(groups)
    for index, ((rule_id, agent), group) in enumerate(items):
        if index >= MAX_GROUPS:
            lines.append("(%d more groups not listed)" % (len(items) - MAX_GROUPS))
            break
        count = "  x%d" % group["count"] if group["count"] > 1 else ""
        lines.append("%s L%d  %s  rule %s%s"
                     % (SEVERITY.get(group["level"], "[HIGH]"),
                        group["level"], agent, rule_id, count))
        lines.append("  " + shared_prefix(group["descriptions"]))
        stamp = "  " + headline(group)
        if group["mitre"]:
            stamp += "   MITRE " + ", ".join(group["mitre"])
        lines.append(stamp)
        for sample in group["samples"]:
            for label, value in interesting_fields(sample):
                lines.append("  %s: %s" % (label, value))
            lines.append("")
        remaining = group["count"] - len(group["samples"])
        if remaining > 0:
            lines.append("  (%d more of the same not listed)" % remaining)
            lines.append("")
    if dashboard:
        lines.append("--")
        lines.append(dashboard)
    return "\n".join(lines)


def esc(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def render_html(groups, total, min_level, dashboard):
    """A table holds its shape when the client rewraps; spaces do not."""
    items = ordered_groups(groups)
    out = [
        '<div style="margin:0;padding:20px 12px;background:#eef0f3;'
        'font-family:%s;color:%s;">' % (SANS, INK),
        '<div style="max-width:720px;margin:0 auto;background:#ffffff;'
        'border:1px solid %s;border-radius:10px;overflow:hidden;">' % LINE,
        '<div style="padding:14px 18px;border-bottom:1px solid %s;'
        'font-size:13px;color:%s;">' % (LINE, MUTED),
        '<span style="color:%s;font-weight:600;">Wazuh</span>'
        '&nbsp;&nbsp;%d alerts at level %d or above'
        '&nbsp;&middot;&nbsp;%d rules&nbsp;&middot;&nbsp;%d hosts'
        % (INK, total, min_level, len(groups), len({k[1] for k in groups})),
        '</div>',
    ]

    for index, ((rule_id, agent), group) in enumerate(items):
        if index >= MAX_GROUPS:
            out.append('<div style="padding:12px 18px;font-size:12px;color:%s;">'
                       '%d more groups not listed</div>'
                       % (MUTED, len(items) - MAX_GROUPS))
            break
        band = BAND.get(group["level"], BAND[12])
        divider = ('border-top:1px solid %s;' % LINE) if index else ''
        out.append('<div style="%spadding:16px 18px;border-left:4px solid %s;">'
                   % (divider, band))

        count = ('<span style="color:%s;">&nbsp;&times;%d</span>'
                 % (MUTED, group["count"])) if group["count"] > 1 else ''
        out.append(
            '<div style="font-size:12px;letter-spacing:.04em;'
            'text-transform:uppercase;color:%s;font-weight:700;">'
            'Level %d<span style="color:%s;font-weight:600;">'
            '&nbsp;&middot;&nbsp;%s&nbsp;&middot;&nbsp;rule %s</span>%s</div>'
            % (band, group["level"], MUTED, esc(agent), esc(rule_id), count))

        out.append('<div style="margin:6px 0 2px;font-size:15px;line-height:1.45;'
                   'font-weight:600;">%s</div>'
                   % esc(shared_prefix(group["descriptions"])))

        meta = headline(group)
        if group["mitre"]:
            meta += '&nbsp;&middot;&nbsp;MITRE ' + esc(", ".join(group["mitre"]))
        out.append('<div style="font-size:12px;color:%s;margin-bottom:10px;">%s</div>'
                   % (FAINT, meta))

        for position, sample in enumerate(group["samples"]):
            if position:
                out.append('<div style="height:1px;background:%s;margin:10px 0;"></div>'
                           % LINE)
            out.append('<table cellpadding="0" cellspacing="0" border="0" '
                       'style="width:100%;border-collapse:collapse;font-size:13px;">')
            for label, value in interesting_fields(sample):
                long_value = label in ("Log", "Request", "File", "Exec", "Client")
                style = ('font-family:%s;font-size:12px;background:%s;'
                         'padding:4px 6px;border-radius:4px;' % (MONO, PANEL)
                         if long_value else 'font-family:%s;font-size:12.5px;' % MONO)
                out.append(
                    '<tr>'
                    '<td style="padding:3px 10px 3px 0;color:%s;font-size:12px;'
                    'white-space:nowrap;vertical-align:top;width:1%%;">%s</td>'
                    '<td style="padding:3px 0;vertical-align:top;'
                    'word-break:break-word;overflow-wrap:anywhere;">'
                    '<span style="%s">%s</span></td></tr>'
                    % (MUTED, esc(label), style, esc(value)))
            out.append('</table>')

        remaining = group["count"] - len(group["samples"])
        if remaining > 0:
            out.append('<div style="margin-top:10px;font-size:12px;color:%s;">'
                       '%d more of the same not listed</div>' % (FAINT, remaining))
        out.append('</div>')

    if dashboard:
        out.append('<div style="padding:12px 18px;border-top:1px solid %s;'
                   'font-size:12px;">'
                   '<a href="%s" style="color:#1d4ed8;text-decoration:none;">%s</a>'
                   '</div>' % (LINE, esc(dashboard), esc(dashboard)))
    out.append('</div></div>')
    return "\n".join(out)


def subject(groups, total):
    """Kept to plain ASCII on purpose.

    A subject carrying an em dash or any other non-ASCII character is sent as
    a MIME encoded word, and a client that does not decode it in the list view
    shows the reader =?utf-8?b?... instead of the alert.
    """
    (_, agent), group = ordered_groups(groups)[0]
    text = shared_prefix(group["descriptions"])
    if ": " in text:
        text = text.split(": ")[0]
    text = text.encode("ascii", "ignore").decode("ascii")
    text = trim(" ".join(text.split()), 62)
    extra = " +%d" % (len(groups) - 1) if len(groups) > 1 else ""
    return "[Wazuh] L%d %s - %s%s (%d)" % (group["level"], agent, text, extra, total)


# --------------------------------------------------------------------------
# Failure reporting
# --------------------------------------------------------------------------

_QUEUE = None


def report_failure(message):
    """Put a failure where someone will see it.

    A notifier that stops working cannot announce that by mail, and nobody
    reads a log file. Writing to the manager's own queue turns the failure
    into an ordinary alert, which rule 131100 raises in the console.
    """
    sys.stderr.write(message + "\n")
    if not _QUEUE:
        return
    payload = "1:jt-alert-digest:jt-alert-digest: ERROR %s" % trim(message, 300)
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(_QUEUE)
        sock.send(payload.encode("utf-8", "replace"))
        sock.close()
    except (OSError, socket.error):
        pass        # the stderr line above still reaches the cron log


# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--wazuh-path", default=DEFAULT_WAZUH,
                        help="manager installation root (default %s)" % DEFAULT_WAZUH)
    parser.add_argument("--level", type=int,
                        help="minimum alert level; defaults to email_alert_level")
    parser.add_argument("--to", action="append",
                        help="recipient; defaults to email_to from ossec.conf")
    parser.add_argument("--dashboard", help="URL printed at the foot of the message")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the message instead of sending it")
    parser.add_argument("--html", action="store_true",
                        help="with --dry-run, print the HTML part")
    args = parser.parse_args()

    wazuh = os.path.abspath(args.wazuh_path)
    global _QUEUE
    queue = os.path.join(wazuh, "queue", "sockets", "queue")
    _QUEUE = queue if os.path.exists(queue) else None

    config = read_global_config(wazuh)
    min_level = args.level if args.level is not None else config["level"]
    recipients = args.to or config["email_to"]

    alerts_path = os.path.join(wazuh, "logs", "alerts", "alerts.json")
    state = os.path.join(wazuh, "var", "jt-alert-digest.state")

    groups, total, new_offset = collect(alerts_path, state, min_level)
    if new_offset is None:
        return 2
    if not groups:
        if args.dry_run:
            print("no new alerts at level %d or above" % min_level)
        else:
            write_offset(state, new_offset)
        return 0

    text = render_text(groups, total, min_level, args.dashboard)
    html = render_html(groups, total, min_level, args.dashboard)
    line = subject(groups, total)

    if args.dry_run:
        print("Subject: %s\n" % line)
        print(html if args.html else text)
        return 0

    if not config["smtp_server"] or not config["email_from"] or not recipients:
        report_failure("ossec.conf has no smtp_server, email_from or email_to, "
                       "so there is nowhere to send %d alerts" % total)
        return 2

    message = EmailMessage()
    message["Subject"] = line
    message["From"] = "Wazuh <%s>" % config["email_from"]
    message["To"] = ", ".join(recipients)
    message["Date"] = formatdate(localtime=True)
    message["X-Wazuh-Alerts"] = str(total)
    message.set_content(text)
    message.add_alternative(html, subtype="html")

    try:
        with smtplib.SMTP(config["smtp_server"], 25, timeout=20) as server:
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        # Leave the offset alone so the next run retries these alerts.
        report_failure("could not send %d alerts through %s: %s: %s"
                       % (total, config["smtp_server"],
                          type(exc).__name__, exc))
        return 1

    write_offset(state, new_offset)
    return 0


if __name__ == "__main__":
    sys.exit(main())
