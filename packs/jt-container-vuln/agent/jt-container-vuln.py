#!/usr/bin/env python3
# jt-container-vuln scanner (jt-wazuh-mgr rule pack jt-container-vuln 1.0)
# License: AGPL-3.0-or-later. Author: Jason Tools.
"""Find known vulnerabilities in the images of the running Docker containers.

Wazuh 4.14's vulnerability detection reads the packages of the host. The
software inside a container image (its distribution packages, Java jars,
Python, Node, Go and Ruby dependencies) is invisible to it. This script asks
Trivy about every image a running container uses and writes the result as
JSON lines to /var/log/jt-container-vuln.json, which the agent group
"container-vuln" collects (rules 132800-132899).

How it runs, once a day from a systemd timer (see jt-container-vuln-install.sh):

 1. Trivy is not installed on the host. It runs as a container, from an image
    pinned by digest (TRIVY_IMAGE). A reference without "@sha256:" is refused:
    in March 2026 Trivy's release tags were hijacked and pointed at a
    credential stealer (GHSA-69fq-xp46-6x23); a digest cannot be re-pointed.
 2. The vulnerability database is downloaded by one Trivy container that sees
    nothing but its cache directory.
 3. Each image is exported with "docker save" by this script and handed to a
    second Trivy container as a read-only file. That container has no network
    (--network none), no Docker socket, no capabilities, a read-only root and
    limits on CPU, memory and processes. The scanner reads image contents,
    which can include baked-in secrets; without a network it cannot send them
    anywhere, and without the socket it is not root on the host.
 4. Only vulnerabilities are scanned (--scanners vuln). No secret or
    configuration scanning: nothing read from an image other than package
    names, versions and advisory ids leaves this script. Environment
    variables and registry credentials are never read.
 5. Matches with CISA's Known Exploited Vulnerabilities catalogue are marked.

Output: one "image" line per image scanned and one "status" line per run.
A "change" field, computed from this script's own state, tells the rules
whether anything worth an alert happened (new image, more critical or KEV
CVEs than were last reported, the weekly reminder), so an unchanged image
does not alert every day.

Usage:
  jt-container-vuln.py                 scan the images of running containers
  jt-container-vuln.py --image REF     scan one image (repeatable; for tests)
  jt-container-vuln.py --list          show what would be scanned, change nothing
  jt-container-vuln.py --stdout        print the lines instead of appending
  jt-container-vuln.py --force         ignore the "scanned in the last hours" skip
  jt-container-vuln.py --config PATH   (default /etc/jt-container-vuln/jt-container-vuln.conf)

Python 3.6 or later, standard library only.
"""

import argparse
import errno
import fcntl
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

VERSION = "1.0"
TOOL = "jt-container-vuln"

# Trivy v0.75.0, published 2026-10-01 as a GitHub immutable release after
# Aqua's post-incident hardening; the image index is signed by
# .github/workflows/reusable-release.yaml@refs/tags/v0.75.0 (cosign keyless,
# verified 2026-10-18). The same digest is served by ghcr.io, docker.io and
# public.ecr.aws, so a mirror of any of them works.
DEFAULT_TRIVY_IMAGE = ("ghcr.io/aquasecurity/trivy@sha256:"
                       "af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa")

DEFAULTS = {
    "TRIVY_IMAGE": DEFAULT_TRIVY_IMAGE,
    "DB_REPOSITORY": "",            # e.g. a local mirror; empty = Trivy's default list
    "JAVA_DB_REPOSITORY": "",
    "JAVA_DB": "auto",              # auto | on | off
    "KEV_URL": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "KEV_FALLBACK_URL": "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
                        "known_exploited_vulnerabilities.json",
    "HTTPS_PROXY": "",
    "NO_PROXY": "",
    "CACHE_DIR": "/var/cache/jt-container-vuln",
    "STATE_DIR": "/var/lib/jt-container-vuln",
    "OUTPUT": "/var/log/jt-container-vuln.json",
    "MAX_LOG_MB": "5",
    "SCAN_TIMEOUT": "900",          # seconds per image (export and scan)
    "DB_TIMEOUT": "900",
    "RESCAN_HOURS": "20",           # an image scanned more recently is skipped
    "DB_MAX_AGE_HOURS": "48",
    "KEV_MAX_AGE_DAYS": "7",
    "REMINDER_DAYS": "7",
    "FAIL_REMINDER_DAYS": "3",
    "TOP": "10",
    "CPUS": "1",
    "MEMORY": "3g",
    "MIN_FREE_MB": "1024",
    "CONTAINER_FILTER": "",         # docker ps --filter value(s), space separated
    "EXCLUDE_IMAGES": "",           # regular expression on the image reference
    "MAX_IMAGES": "100",
    # Kernel headers: a container runs the host's kernel, and these packages
    # carry no kernel code, yet every kernel CVE is listed against them.
    "IGNORE_PACKAGES": r"^(linux-libc-dev|linux-headers(-.*)?|kernel-headers|kernel-devel)$",
}

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
PROBLEM_ORDER = ("docker_unreachable", "scanner_unavailable", "db_missing", "db_stale",
                 "scan_failed", "kev_stale", "db_update_failed")
ALERTING_CHANGES = ("new", "grown", "fix_available", "reminder")
CVE_RE = re.compile(r"^(CVE|GHSA|RHSA|DSA|DLA|USN|ALAS|ELSA|GO|PYSEC|RUSTSEC|OSV)-[A-Za-z0-9._:-]{1,40}$")
KEV_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SAFE_TEXT = re.compile(r"[^\x20-\x7e]")


class Fail(Exception):
    """A run-level problem: (problem code, message)."""

    def __init__(self, problem, message):
        Exception.__init__(self, message)
        self.problem = problem
        self.message = message


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def now():
    return time.time()


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def parse_iso(value):
    """Trivy writes RFC 3339 with nanoseconds: 2026-10-18T13:11:41.355239553Z."""
    if not value:
        return None
    m = re.match(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)", str(value))
    if not m:
        return None
    import calendar
    stamp = calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0))
    tz = re.search(r"([+-])(\d\d):?(\d\d)$", str(value))
    if tz and not str(value).endswith("Z"):
        offset = (int(tz.group(2)) * 60 + int(tz.group(3))) * 60
        stamp -= offset if tz.group(1) == "+" else -offset
    return stamp


def clean(value, limit=200):
    """Printable ASCII on one line, bounded. Titles come from advisories."""
    value = SAFE_TEXT.sub(" ", str(value if value is not None else ""))
    value = " ".join(value.split())
    return value if len(value) <= limit else value[:limit - 3].rstrip() + "..."


def scrub(text, limit=300):
    """An error message for the log: no credentials, no long dumps.

    Docker and Trivy errors can quote a registry URL with user:password, a
    proxy URL or an Authorization header. Those are cut out before the last
    line of the error is kept.
    """
    lines = [l for l in str(text or "").splitlines() if l.strip()]
    text = lines[-1] if lines else ""
    text = re.sub(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@", r"\1***@", text)
    text = re.sub(r"(?i)\b(bearer|basic)\s+\S+", r"\1 ***", text)
    text = re.sub(r"(?i)(authorization|password|passwd|token|secret|apikey|api_key)"
                  r"([\"']?\s*[:=]\s*)(?:(?:bearer|basic) \*\*\*|\S+)", r"\1\2***", text)
    return clean(text, limit)


def as_int(value, default):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def as_float(value, default):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_config(text):
    """KEY=VALUE lines (shell-like, quotes optional); unknown keys are ignored."""
    conf = dict(DEFAULTS)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key in DEFAULTS:
            conf[key] = value
    return conf


def load_config(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_config(fh.read())
    except (IOError, OSError) as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            return dict(DEFAULTS)
        raise


def pinned(ref):
    return bool(re.search(r"@sha256:[0-9a-f]{64}$", ref or ""))


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

def fresh_state():
    return {"v": 1, "images": {}, "refs": {}, "status": {"problem": "none", "since": None,
                                                          "last_alert": None},
            "java_db_needed": None}


def load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
        if not isinstance(state, dict) or state.get("v") != 1:
            return fresh_state()
        base = fresh_state()
        base.update(state)
        for key in ("images", "refs", "status"):
            if not isinstance(base.get(key), dict):
                base[key] = fresh_state()[key]
        return base
    except (IOError, OSError, ValueError):
        return fresh_state()


def save_state(path, state):
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".state-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, sort_keys=True, separators=(",", ":"))
        os.chmod(tmp, 0o600)
        os.rename(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def prune_state(state, ts, days=30):
    """Forget images and references not seen for a month."""
    limit = ts - days * 86400
    for key in ("images", "refs"):
        for name in [k for k, v in state[key].items() if (v.get("seen") or 0) < limit]:
            del state[key][name]


def image_change(state, image_id, refs, critical, fixable, kev, ts, reminder_days):
    """What happened to this image since the last report; updates the state.

    critical, fixable (the fixable critical ids) and kev are sets of CVE ids.
    Only those are tracked; high findings alert once, on the first scan.
    Returns (change, new_ids):
      new            first scan of this image id
      rebuilt        first scan of a new image for a reference already scanned
                     (an updated tag) with nothing the old image lacked
      grown          critical or KEV ids that were not in the last report
      fix_available  a critical id reported as unfixable now has a fix
      reminder       nothing new, but a KEV id or a fixable critical id is
                     still there and the last report is reminder_days old
                     (an unfixable critical is not repeated: nothing to do
                     until a fix exists, and that is reported by itself)
      same           nothing to report
    new_ids are the ids behind grown / fix_available (all of them for new).
    """
    worst = set(critical) | set(kev)
    entry = state["images"].get(image_id)
    first = entry is None
    rebuild = False
    if first:
        entry = {"first": ts, "reported": [], "kev_reported": [], "fix_reported": [],
                 "last_alert": None}
        for ref in refs:
            known = state["refs"].get(ref) or {}
            previous = state["images"].get(known.get("image"))
            if previous is not None and known.get("image") != image_id:
                # same reference, new build: inherit what was already said
                for key in ("reported", "kev_reported", "fix_reported"):
                    entry[key] = list(previous.get(key) or [])
                entry["last_alert"] = previous.get("last_alert")
                rebuild = True
                break
        state["images"][image_id] = entry
    reported = set(entry.get("reported") or [])
    kev_reported = set(entry.get("kev_reported") or [])
    fix_reported = set(entry.get("fix_reported") or [])
    grown = (set(critical) - reported) | (set(kev) - kev_reported)
    now_fixable = (set(fixable) & reported) - fix_reported - grown
    actionable = set(kev) | (set(fixable) & set(critical))
    if first and not rebuild:
        change, new_ids = "new", worst
    elif grown:
        change, new_ids = "grown", grown
    elif now_fixable:
        change, new_ids = "fix_available", now_fixable
    elif actionable and (entry.get("last_alert") is None or
                         ts - entry["last_alert"] >= reminder_days * 86400):
        change, new_ids = "reminder", set()
    elif first:
        change, new_ids = "rebuilt", set()
    else:
        change, new_ids = "same", set()
    if change in ALERTING_CHANGES and worst:
        entry["reported"] = sorted(reported | set(critical), key=cve_sort)
        entry["kev_reported"] = sorted(kev_reported | set(kev), key=cve_sort)
        entry["fix_reported"] = sorted(fix_reported | (set(fixable) & set(critical)), key=cve_sort)
        entry["last_alert"] = ts
    entry["seen"] = ts
    entry["last_scan"] = ts
    for ref in refs:
        state["refs"][ref] = {"image": image_id, "seen": ts}
    return change, sorted(new_ids, key=cve_sort)


def status_change(state, problem, ts, reminder_days):
    """new | same | reminder | recovered | ok, for the run's main problem."""
    st = state["status"]
    previous = st.get("problem") or "none"
    if problem == "none":
        change = "recovered" if previous != "none" else "ok"
        st.update({"problem": "none", "since": None, "last_alert": None})
        return change
    if problem != previous:
        st.update({"problem": problem, "since": ts, "last_alert": ts})
        return "new"
    if st.get("last_alert") is None or ts - st["last_alert"] >= reminder_days * 86400:
        st["last_alert"] = ts
        return "reminder"
    return "same"


def cve_sort(cve):
    m = re.match(r"^CVE-(\d+)-(\d+)$", cve)
    return (0, int(m.group(1)), int(m.group(2))) if m else (1, 0, 0, cve)


# --------------------------------------------------------------------------
# Trivy output -> one summary
# --------------------------------------------------------------------------

def summarize(report, kev, top_n=10, ignore=None):
    """Reduce a Trivy JSON report to counts by unique CVE id.

    A CVE that affects two packages of an image (pcre2 and pcre2-syntax) is
    counted once, at the highest severity any finding gives it. It is fixable
    when any of its findings has a fixed version. kev: dict of CVE id -> KEV
    entry (the CISA catalogue).
    """
    vulns = {}
    ignored = set()
    ignore = re.compile(ignore) if ignore else None
    os_info = (report.get("Metadata") or {}).get("OS") or {}
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            vid = str(v.get("VulnerabilityID") or "")
            if not CVE_RE.match(vid):
                continue
            if ignore and ignore.search(str(v.get("PkgName") or "")):
                ignored.add(vid)
                continue
            sev = str(v.get("Severity") or "UNKNOWN").upper()
            if sev not in RANK:
                sev = "UNKNOWN"
            fixed = clean(v.get("FixedVersion") or "", 80)
            item = vulns.get(vid)
            finding = {
                "pkg": clean(v.get("PkgName") or "?", 80),
                "installed": clean(v.get("InstalledVersion") or "", 60),
                "fixed": fixed,
                "type": clean(result.get("Type") or "", 20),
            }
            if item is None:
                item = vulns[vid] = {"id": vid, "sev": sev, "fixable": bool(fixed),
                                     "title": clean(v.get("Title") or "", 100),
                                     "findings": [finding], "score": cvss(v)}
            else:
                if RANK[sev] < RANK[item["sev"]]:
                    item["sev"] = sev
                item["fixable"] = item["fixable"] or bool(fixed)
                item["score"] = max(item["score"], cvss(v))
                if len(item["findings"]) < 20:
                    item["findings"].append(finding)
    counts = {s.lower(): 0 for s in SEVERITIES}
    fixable = {s.lower(): 0 for s in SEVERITIES}
    for item in vulns.values():
        counts[item["sev"].lower()] += 1
        if item["fixable"]:
            fixable[item["sev"].lower()] += 1
        item["kev"] = item["id"] in kev
    kev_ids = sorted((i for i in vulns if i in kev), key=cve_sort)
    critical_ids = sorted((i for i, x in vulns.items() if x["sev"] == "CRITICAL"), key=cve_sort)
    fixable_critical_ids = sorted((i for i in critical_ids if vulns[i]["fixable"]), key=cve_sort)
    ordered = sorted(vulns.values(), key=lambda x: (not x["kev"], RANK[x["sev"]], not x["fixable"],
                                                    -x["score"], cve_sort(x["id"])))
    top = []
    for item in ordered[:max(0, top_n)]:
        f = item["findings"][0]
        entry = {"id": item["id"], "severity": item["sev"], "pkg": f["pkg"],
                 "installed": f["installed"], "fixed": f["fixed"], "kev": item["kev"],
                 "title": item["title"]}
        if len(item["findings"]) > 1:
            entry["more_packages"] = len(item["findings"]) - 1
        top.append(entry)
    ransomware = [i for i in kev_ids
                  if str((kev.get(i) or {}).get("knownRansomwareCampaignUse", "")).lower() == "known"]
    return {
        "os": clean(" ".join(str(os_info.get(k) or "") for k in ("Family", "Name")).strip(), 60),
        "counts": counts,
        "fixable": fixable,
        "kev_ids": kev_ids,
        "kev_ransomware": ransomware,
        "critical_ids": critical_ids,
        "fixable_critical_ids": fixable_critical_ids,
        "ignored": len(ignored - set(vulns)),
        "top": top,
        "total": len(vulns),
    }


def cvss(v):
    best = 0.0
    for source in (v.get("CVSS") or {}).values():
        if isinstance(source, dict):
            for key in ("V3Score", "V40Score", "V2Score"):
                best = max(best, as_float(source.get(key), 0.0))
    return best


def short_list(ids, limit=8):
    ids = list(ids)
    text = ",".join(ids[:limit])
    if len(ids) > limit:
        text += ",+%d" % (len(ids) - limit)
    return text


def image_line(info, summary, change, new_ids, meta):
    """The JSON line for one image. "msg" comes first: alert mail and chat
    show only the start of the raw line."""
    c, f = summary["counts"], summary["fixable"]
    parts = ["%d critical (%d fixable)" % (c["critical"], f["critical"]),
             "%d high (%d fixable)" % (c["high"], f["high"])]
    if summary["kev_ids"]:
        parts.append("KEV %s" % short_list(summary["kev_ids"], 4))
    words = {"new": "first scan", "grown": "new since last report: " + short_list(new_ids, 4),
             "fix_available": "fix now available for " + short_list(new_ids, 4),
             "reminder": "reminder, still present", "rebuilt": "rebuilt, nothing new",
             "same": "unchanged"}
    msg = "%s: %s; %s" % (info["ref"], ", ".join(parts), words.get(change, change))
    record = {
        "msg": clean(msg, 300),
        "type": "image",
        "change": change,
        "image": info["ref"],
        "image_id": info["id"],
        "repo_digest": info.get("repo_digest", ""),
        "containers": short_list(info["containers"], 10),
        "container_count": len(info["containers"]),
        "os": summary["os"],
        "critical": c["critical"], "high": c["high"], "medium": c["medium"],
        "low": c["low"], "unknown": c["unknown"],
        "fixable_critical": f["critical"], "fixable_high": f["high"],
        "kev_count": len(summary["kev_ids"]),
        "kev": short_list(summary["kev_ids"], 20),
        "kev_ransomware": short_list(summary["kev_ransomware"], 10),
        "ignored_kernel_headers": summary.get("ignored", 0),
        "new_count": len(new_ids) if change in ALERTING_CHANGES else 0,
        "new": short_list(new_ids, 10) if change in ALERTING_CHANGES else "",
        "top": summary["top"],
    }
    record.update(meta)
    return record


# --------------------------------------------------------------------------
# KEV
# --------------------------------------------------------------------------

def parse_kev(data):
    """bytes -> dict CVE -> entry; raises ValueError for anything implausible."""
    doc = json.loads(data.decode("utf-8"))
    items = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(items, list) or len(items) < 500:
        raise ValueError("not a KEV catalogue")
    out = {}
    for item in items:
        if isinstance(item, dict) and KEV_CVE_RE.match(str(item.get("cveID", ""))):
            out[item["cveID"]] = {"dateAdded": clean(item.get("dateAdded", ""), 12),
                                  "knownRansomwareCampaignUse":
                                      clean(item.get("knownRansomwareCampaignUse", ""), 12)}
    if len(out) < 500:
        raise ValueError("KEV catalogue has too few entries")
    return out, clean(doc.get("catalogVersion", ""), 20)


def fetch(url, timeout, proxy, headers=None):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers=dict(headers or {}, **{"User-Agent": TOOL + "/" + VERSION}))
    return opener.open(req, timeout=timeout)


def update_kev(conf, cache_dir, ts, fetcher=fetch):
    """Refresh the KEV copy at most once a day; keep the last good one.

    Returns (kev dict, info dict with age_days / version / error).
    """
    path = os.path.join(cache_dir, "kev", "known_exploited_vulnerabilities.json")
    meta_path = path + ".meta"
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    meta = {}
    try:
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
    except (IOError, OSError, ValueError):
        meta = {}
    error = ""
    if ts - (meta.get("checked") or 0) >= 20 * 3600 or not os.path.exists(path):
        for url in [u for u in (conf["KEV_URL"], conf["KEV_FALLBACK_URL"]) if u]:
            try:
                headers = {}
                if meta.get("url") == url and meta.get("last_modified") and os.path.exists(path):
                    headers["If-Modified-Since"] = meta["last_modified"]
                try:
                    resp = fetcher(url, 60, conf.get("HTTPS_PROXY"), headers)
                    body = resp.read(50 * 1024 * 1024)
                    last_modified = resp.headers.get("Last-Modified", "") if resp.headers else ""
                except urllib.error.HTTPError as exc:
                    if exc.code == 304:
                        meta.update({"checked": ts, "url": url})
                        error = ""
                        break
                    raise
                parse_kev(body)
                fd, tmp = tempfile.mkstemp(prefix=".kev-", dir=os.path.dirname(path))
                with os.fdopen(fd, "wb") as fh:
                    fh.write(body)
                os.rename(tmp, path)
                meta = {"checked": ts, "url": url, "last_modified": last_modified}
                error = ""
                break
            except Exception as exc:          # network, TLS, JSON: try the next source
                error = scrub("%s: %s" % (url.split("/")[2] if "//" in url else url, exc))
        try:
            fd, tmp = tempfile.mkstemp(prefix=".kevmeta-", dir=os.path.dirname(path))
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(meta, fh)
            os.rename(tmp, meta_path)
        except OSError:
            pass
    kev, version = {}, ""
    try:
        with open(path, "rb") as fh:
            kev, version = parse_kev(fh.read())
    except (IOError, OSError, ValueError) as exc:
        error = error or scrub("no usable KEV copy: %s" % exc)
    checked = meta.get("checked")
    age = round((ts - checked) / 86400.0, 1) if checked and kev else None
    return kev, {"age_days": age, "version": version, "error": error, "count": len(kev)}


# --------------------------------------------------------------------------
# docker and Trivy
# --------------------------------------------------------------------------

class Runner(object):
    """subprocess wrapper; tests replace it."""

    def run(self, args, timeout, stdout_path=None):
        out = open(stdout_path, "wb") if stdout_path else subprocess.PIPE
        try:
            proc = subprocess.run(args, stdout=out, stderr=subprocess.PIPE, timeout=timeout,
                                  stdin=subprocess.DEVNULL)
            text = proc.stdout.decode("utf-8", "replace") if proc.stdout is not None else ""
            return proc.returncode, text, proc.stderr.decode("utf-8", "replace")
        finally:
            if stdout_path:
                out.close()


class Docker(object):
    def __init__(self, runner, conf):
        self.r = runner
        self.conf = conf

    def ok(self, args, timeout=60):
        code, out, err = self.r.run(["docker"] + args, timeout)
        if code != 0:
            raise RuntimeError(scrub(err or out or "exit %d" % code))
        return out

    def server_version(self):
        return self.ok(["version", "--format", "{{.Server.Version}}"], 30).strip()

    def running_containers(self):
        args = ["ps", "-q", "--no-trunc"]
        for flt in self.conf["CONTAINER_FILTER"].split():
            args += ["--filter", flt]
        ids = self.ok(args).split()
        if not ids:
            return []
        # only the fields used here; Config.Env (secrets) is never requested
        fmt = '{"name":{{json .Name}},"image_ref":{{json .Config.Image}},"image":{{json .Image}}}'
        out = self.ok(["inspect", "--format", fmt] + ids, 120)
        result = []
        for line in out.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            result.append({"name": str(item.get("name", "")).lstrip("/"),
                           "ref": str(item.get("image_ref", "")), "image": str(item.get("image", ""))})
        return result

    def image_info(self, ref):
        fmt = '{"id":{{json .Id}},"tags":{{json .RepoTags}},"digests":{{json .RepoDigests}},"size":{{json .Size}}}'
        out = self.ok(["image", "inspect", "--format", fmt, ref], 60)
        item = json.loads(out.strip().splitlines()[0])
        return {"id": str(item.get("id", "")), "tags": item.get("tags") or [],
                "digests": item.get("digests") or [], "size": as_int(item.get("size"), 0)}

    def remove(self, name):
        self.r.run(["docker", "rm", "-f", name], 60)


def trivy_base(conf, name, trivy_dir, tmp_dir, network):
    """docker run options shared by both Trivy containers.

    The download container may write its database directory and nothing
    else. The scan container sees the database read-only, has no network,
    and keeps its analysis cache in memory (otherwise Trivy's layer cache
    grows by every image it has ever seen).
    """
    args = ["docker", "run", "--rm", "--name", name, "--network", network,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--pids-limit", "512",
            "--cpus", conf["CPUS"], "--memory", conf["MEMORY"],
            "--label", "jt-container-vuln=scanner",
            "-v", "%s:/cache%s" % (trivy_dir, ":ro" if network == "none" else ""),
            "-v", "%s:/tmp" % tmp_dir, "-e", "TMPDIR=/tmp"]
    if network != "none":
        for key in ("HTTPS_PROXY", "NO_PROXY"):
            if conf.get(key):
                args += ["-e", "%s=%s" % (key, conf[key])]
    return args


def update_db(runner, conf, trivy_dir, tmp_dir, java):
    """Download or refresh the vulnerability DB (and the Java DB). Returns errors."""
    errors = []
    jobs = [("db", ["--download-db-only"] + (["--db-repository", conf["DB_REPOSITORY"]]
                                              if conf["DB_REPOSITORY"] else []))]
    if java:
        jobs.append(("java-db", ["--download-java-db-only"] +
                     (["--java-db-repository", conf["JAVA_DB_REPOSITORY"]]
                      if conf["JAVA_DB_REPOSITORY"] else [])))
    for what, extra in jobs:
        name = "jt-container-vuln-db-%d" % os.getpid()
        args = trivy_base(conf, name, trivy_dir, tmp_dir, "bridge") + [
            conf["TRIVY_IMAGE"], "--cache-dir", "/cache", "image", "--no-progress", "--quiet",
            "--skip-version-check", "--disable-telemetry"] + extra
        try:
            code, out, err = runner.run(args, as_int(conf["DB_TIMEOUT"], 900))
        except subprocess.TimeoutExpired:
            runner.run(["docker", "rm", "-f", name], 60)
            errors.append("%s download timed out" % what)
            continue
        if code != 0:
            errors.append("%s download failed: %s" % (what, scrub(err or out)))
    return errors


def db_metadata(cache, which="db"):
    try:
        with open(os.path.join(cache, which, "metadata.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        return parse_iso(meta.get("UpdatedAt")), parse_iso(meta.get("DownloadedAt"))
    except (IOError, OSError, ValueError):
        return None, None


JAVA_DB_MISSING = re.compile(r"(?i)java db|javadb|trivy-java-db")


def scan_image(runner, conf, trivy_dir, image_id, tmp_dir):
    """docker save + offline Trivy scan. Returns the report dict or raises."""
    timeout = as_int(conf["SCAN_TIMEOUT"], 900)
    started = time.time()
    tar = os.path.join(tmp_dir, "image-%d.tar" % os.getpid())
    out_path = os.path.join(tmp_dir, "report-%d.json" % os.getpid())
    name = "jt-container-vuln-scan-%d" % os.getpid()
    try:
        try:
            code, _, err = runner.run(["docker", "save", "-o", tar, image_id], timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError("docker save timed out after %ds" % timeout)
        if code != 0:
            raise RuntimeError("docker save failed: %s" % scrub(err))
        left = max(60, timeout - int(time.time() - started))
        args = trivy_base(conf, name, trivy_dir, tmp_dir, "none") + [
            "-v", "%s:/input/image.tar:ro" % tar,
            conf["TRIVY_IMAGE"], "--cache-dir", "/cache", "--cache-backend", "memory", "image",
            "--input", "/input/image.tar", "--scanners", "vuln",
            "--skip-db-update", "--skip-java-db-update", "--offline-scan",
            "--no-progress", "--quiet", "--skip-version-check", "--disable-telemetry",
            "--format", "json", "--timeout", "%ds" % left]
        if conf["JAVA_DB"].lower() == "off":
            # without the Java DB Trivy refuses to analyse a jar; leave them out
            for pattern in ("**/*.jar", "**/*.war", "**/*.ear", "**/*.par"):
                args += ["--skip-files", pattern]
        try:
            code, _, err = runner.run(args + ["--output", "/tmp/" + os.path.basename(out_path)], left + 30)
        except subprocess.TimeoutExpired:
            runner.run(["docker", "rm", "-f", name], 60)
            raise RuntimeError("scan timed out after %ds" % timeout)
        if code != 0:
            if JAVA_DB_MISSING.search(err or "") and "first run" in (err or ""):
                raise JavaDbNeeded()
            raise RuntimeError("trivy failed: %s" % scrub(err))
        with open(out_path, encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        for path in (tar, out_path):
            try:
                os.unlink(path)
            except OSError:
                pass


class JavaDbNeeded(Exception):
    pass


def trivy_version(runner, conf):
    code, out, _ = runner.run(["docker", "image", "inspect", "--format",
                               '{{index .Config.Labels "org.opencontainers.image.version"}}',
                               conf["TRIVY_IMAGE"]], 30)
    return clean(out.strip(), 20) if code == 0 else ""


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

def append_lines(path, records, max_bytes):
    """Append JSON lines; rotate to <path>.1 first when the file is too big.

    Rename, then a new file: logcollector notices the new inode and reads the
    new file from its start, so nothing is lost or read twice.
    """
    try:
        if os.path.getsize(path) > max_bytes:
            os.rename(path, path + ".1")
    except OSError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps({"container_vuln": record}, separators=(",", ":"),
                                ensure_ascii=True) + "\n")


def collect_images(docker, conf):
    """Running containers grouped by image id, with references and names."""
    exclude = re.compile(conf["EXCLUDE_IMAGES"]) if conf["EXCLUDE_IMAGES"] else None
    images = {}
    for c in docker.running_containers():
        if not c["image"]:
            continue
        if exclude and exclude.search(c["ref"]):
            continue
        if c["ref"].startswith(conf["TRIVY_IMAGE"].split("@")[0]):
            continue
        item = images.setdefault(c["image"], {"id": c["image"], "refs": [], "containers": []})
        if c["ref"] and c["ref"] not in item["refs"]:
            item["refs"].append(c["ref"])
        if c["name"] and c["name"] not in item["containers"]:
            item["containers"].append(c["name"])
    return images


def describe_ref(item, info):
    """The name people know the image by: what the container was started with,
    unless that was a bare image id."""
    refs = [r for r in item["refs"] if not re.match(r"^(sha256:)?[0-9a-f]{12,64}$", r)]
    ref = refs[0] if refs else (info.get("tags") or [item["id"]])[0]
    digest = ""
    for d in info.get("digests") or []:
        digest = d
        break
    return clean(ref, 200), clean(digest, 200)


def main(argv=None, runner=None, clock=now, fetcher=None):
    parser = argparse.ArgumentParser(description="Scan the images of running containers with Trivy.")
    parser.add_argument("--config", default="/etc/jt-container-vuln/jt-container-vuln.conf")
    parser.add_argument("--image", action="append", default=[])
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--stdout", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--delay", type=int, default=0,
                        help="sleep a random 0..N seconds first (cron without systemd)")
    args = parser.parse_args(argv)
    conf = load_config(args.config)
    runner = runner or Runner()
    if args.delay > 0:
        time.sleep(random.randint(0, args.delay))

    os.umask(0o077)
    cache = conf["CACHE_DIR"]
    trivy_dir = os.path.join(cache, "trivy")      # the only directory Trivy may write
    tmp_dir = os.path.join(cache, "tmp")
    state_dir = conf["STATE_DIR"]
    for d in (cache, trivy_dir, tmp_dir, state_dir):
        os.makedirs(d, mode=0o700, exist_ok=True)
    with open(os.path.join(state_dir, "lock"), "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError):
            print("another run is in progress", file=sys.stderr)
            return 0
        return run(args, conf, runner, clock, fetcher, cache, trivy_dir, tmp_dir, state_dir)


def run(args, conf, runner, clock, fetcher, cache, trivy_dir, tmp_dir, state_dir):
    """One locked run: scan, write the lines, save the state."""
    # leftovers of a run that was killed
    for leftover in os.listdir(tmp_dir):
        if leftover.startswith(("image-", "report-")):
            try:
                os.unlink(os.path.join(tmp_dir, leftover))
            except OSError:
                pass

    state_path = os.path.join(state_dir, "state.json")
    state = load_state(state_path)
    ts = clock()
    started = time.time()
    records = []
    status = {"type": "status", "problems": [], "images": 0, "scanned": 0, "skipped_recent": 0,
              "failed": 0, "failed_images": [], "errors": []}
    docker = Docker(runner, conf)
    trivy = ""
    try:
        try:
            status["docker"] = clean(docker.server_version(), 20)
        except Exception as exc:
            raise Fail("docker_unreachable", "Docker daemon not reachable: %s" % scrub(exc))

        if args.image:
            images = {}
            for ref in args.image:
                try:
                    info = docker.image_info(ref)
                except Exception as exc:
                    status["failed"] += 1
                    status["failed_images"].append(clean(ref, 120))
                    status["errors"].append(scrub(exc))
                    continue
                images[info["id"]] = {"id": info["id"], "refs": [ref], "containers": []}
        else:
            images = collect_images(docker, conf)
        limit = as_int(conf["MAX_IMAGES"], 100)
        status["images"] = len(images)
        if args.list:
            for item in images.values():
                print("%s  %s  %s" % (item["id"][:19], ",".join(item["refs"]), ",".join(item["containers"])))
            return 0

        if not pinned(conf["TRIVY_IMAGE"]):
            raise Fail("scanner_unavailable", "TRIVY_IMAGE is not pinned by digest (@sha256:...)")
        code, _, err = runner.run(["docker", "image", "inspect", conf["TRIVY_IMAGE"]], 60)
        if code != 0:
            code, out, err = runner.run(["docker", "pull", "-q", conf["TRIVY_IMAGE"]], 900)
            if code != 0:
                raise Fail("scanner_unavailable", "cannot pull the Trivy image: %s" % scrub(err or out))
        trivy = trivy_version(runner, conf)

        java_mode = conf["JAVA_DB"].lower()
        java_present = os.path.exists(os.path.join(trivy_dir, "java-db", "metadata.json"))
        if java_mode == "auto" and java_present and state.get("java_db_needed") and \
                ts - state["java_db_needed"] > 30 * 86400:
            # no image needed it for a month: give the gigabyte back
            shutil.rmtree(os.path.join(trivy_dir, "java-db"), ignore_errors=True)
            java_present = False
            state["java_db_needed"] = None
        java = java_mode == "on" or (java_mode == "auto" and java_present)
        db_errors = update_db(runner, conf, trivy_dir, tmp_dir, java)
        updated, _ = db_metadata(trivy_dir)
        status["db_update"] = "failed" if db_errors else "ok"
        status["errors"].extend(db_errors)
        if updated is None:
            raise Fail("db_missing", "no vulnerability database" if db_errors
                       else "no vulnerability database after a download that reported no error")
        db_age = (ts - updated) / 3600.0
        status["db_updated"] = iso(updated)
        status["db_age_hours"] = round(db_age, 1)
        if db_age > as_float(conf["DB_MAX_AGE_HOURS"], 48):
            status["problems"].append("db_stale")
        elif db_errors:
            status["problems"].append("db_update_failed")
        java_updated, _ = db_metadata(trivy_dir, "java-db")
        status["java_db_updated"] = iso(java_updated) if java_updated else ""

        kev, kev_info = update_kev(conf, cache, ts, fetcher or fetch)
        status["kev_count"] = kev_info["count"]
        status["kev_version"] = kev_info["version"]
        status["kev_age_days"] = kev_info["age_days"]
        if kev_info["error"]:
            status["errors"].append(kev_info["error"])
        if not kev or kev_info["age_days"] is None or \
                kev_info["age_days"] > as_float(conf["KEV_MAX_AGE_DAYS"], 7):
            status["problems"].append("kev_stale")

        rescan = as_float(conf["RESCAN_HOURS"], 20) * 3600
        java_retry_done = False
        for n, item in enumerate(sorted(images.values(), key=lambda x: x["id"])):
            if n >= limit:
                status["errors"].append("more than %d images; the rest were not scanned" % limit)
                break
            known = state["images"].get(item["id"]) or {}
            if not args.force and known.get("last_scan") and ts - known["last_scan"] < rescan:
                status["skipped_recent"] += 1
                known["seen"] = ts
                continue
            try:
                info = docker.image_info(item["id"])
                ref, digest = describe_ref(item, info)
                free = shutil.disk_usage(tmp_dir).free
                need = info["size"] + as_int(conf["MIN_FREE_MB"], 1024) * 1024 * 1024
                if free < need:
                    raise RuntimeError("not enough free disk in %s (%d MB free, %d MB needed)"
                                       % (tmp_dir, free // 1048576, need // 1048576))
                try:
                    report = scan_image(runner, conf, trivy_dir, item["id"], tmp_dir)
                except JavaDbNeeded:
                    if java_mode != "auto" or java_retry_done:
                        raise RuntimeError("image has Java packages and the Java DB is off or missing")
                    java_retry_done = True
                    errs = update_db(runner, conf, trivy_dir, tmp_dir, True)
                    if errs:
                        raise RuntimeError("; ".join(errs))
                    report = scan_image(runner, conf, trivy_dir, item["id"], tmp_dir)
                if JAVA_TYPES & {str(r.get("Type")) for r in report.get("Results") or []}:
                    state["java_db_needed"] = ts
                summary = summarize(report, kev, as_int(conf["TOP"], 10), conf["IGNORE_PACKAGES"])
                change, new_ids = image_change(state, item["id"], item["refs"] or [ref],
                                               set(summary["critical_ids"]),
                                               set(summary["fixable_critical_ids"]),
                                               set(summary["kev_ids"]),
                                               ts, as_float(conf["REMINDER_DAYS"], 7))
                meta = {"scanner": "trivy " + trivy if trivy else "trivy",
                        "db_updated": status.get("db_updated", ""), "scanned_at": iso(time.time()),
                        "host": clean(socket.gethostname(), 64)}
                info_ref = {"ref": ref, "id": item["id"], "repo_digest": digest,
                            "containers": item["containers"]}
                records.append(image_line(info_ref, summary, change, new_ids, meta))
                status["scanned"] += 1
            except Exception as exc:
                status["failed"] += 1
                status["failed_images"].append(clean((item["refs"] or [item["id"]])[0], 120))
                status["errors"].append(scrub(exc))
        if status["failed"]:
            status["problems"].append("scan_failed")
    except Fail as exc:
        status["problems"].append(exc.problem)
        status["errors"].append(exc.message)
    except Exception as exc:                       # a bug: still say something
        status["problems"].append("scanner_unavailable")
        status["errors"].append(scrub("unexpected error: %r" % exc))

    problems = [p for p in PROBLEM_ORDER if p in status["problems"]]
    problem = problems[0] if problems else "none"
    change = status_change(state, problem, ts, as_float(conf["FAIL_REMINDER_DAYS"], 3))
    status.update({
        "status": "ok" if problem == "none" else "failed",
        "problem": problem,
        "problems": ",".join(problems),
        "change": change,
        "failed_images": short_list(status["failed_images"], 10),
        "error": clean("; ".join(status["errors"]), 600),
        "scanner": "trivy " + trivy if trivy else "trivy",
        "duration_s": int(time.time() - started),
        "host": clean(socket.gethostname(), 64),
        "version": VERSION,
    })
    del status["errors"]
    words = {"none": "scan finished", "docker_unreachable": "Docker not reachable",
             "scanner_unavailable": "scanner not available", "db_missing": "no vulnerability database",
             "db_stale": "vulnerability database is %s hours old" % status.get("db_age_hours"),
             "scan_failed": "%d image scans failed" % status["failed"],
             "kev_stale": "KEV catalogue missing or older than %s days" % conf["KEV_MAX_AGE_DAYS"],
             "db_update_failed": "database update failed, using the copy from %s" % status.get("db_updated")}
    status["msg"] = clean("%s: %d images, %d scanned, %d recent, %d failed%s" % (
        words[problem], status["images"], status["scanned"], status["skipped_recent"], status["failed"],
        ("; " + status["error"]) if status["error"] else ""), 300)
    ordered = {"msg": status.pop("msg"), "type": status.pop("type")}
    ordered.update(status)
    records.append(ordered)
    prune_state(state, ts)
    try:
        save_state(state_path, state)
    except OSError as exc:
        print("cannot save state: %s" % exc, file=sys.stderr)
    if args.stdout:
        for record in records:
            print(json.dumps({"container_vuln": record}, separators=(",", ":")))
    else:
        append_lines(conf["OUTPUT"], records, as_int(conf["MAX_LOG_MB"], 5) * 1024 * 1024)
    return 0 if problem == "none" else 1


JAVA_TYPES = {"jar", "pom", "gradle", "sbt"}

if __name__ == "__main__":
    sys.exit(main())
