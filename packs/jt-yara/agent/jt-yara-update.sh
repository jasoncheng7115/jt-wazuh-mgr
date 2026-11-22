#!/bin/bash
# jt-yara 1.1 - weekly update of the compiled YARA rules from a YARA-Forge release.
#
#   jt-yara-update [--set core|extended|full] [--min-age-days N] [--force]
#   jt-yara-update --zip FILE [--tag TAG]          (a host without Internet access)
#
# Run by /etc/cron.d/jt-yara-update (jt-yara-install.sh). Reads the latest release of
# github.com/YARAHQ/yara-forge, waits until it is min-age-days old (default 3: a release
# with problems is usually replaced by then), downloads the rule set's zip, checks it against
# the SHA-256 digest GitHub publishes for the asset, compiles it with the pipeline test rule,
# and replaces /var/ossec/etc/yara/rules.yarc only when the new set compiles and still finds
# the test marker. Writes one line to active-responses.log:
#   wazuh-yara: UPDATE - rules yara-forge-core-<tag> installed (<n> rules, was <old>)   -> 133434
#   wazuh-yara: ERROR - rules update failed: <reason>                                  -> 133412
# and nothing when the installed set is already the latest or the latest is too new.
# A proxy is taken from https_proxy as curl does.

set -uo pipefail
LOG=/var/ossec/logs/active-responses.log
YR=/usr/local/bin/yr
ETC=/var/ossec/etc/yara
API=https://api.github.com/repos/YARAHQ/yara-forge/releases/latest
SET=core MIN_AGE=3 FORCE=no ZIP= TAG=

log() { echo "wazuh-yara: $1 - $2" >> "$LOG"; }
# fetch URL FILE MAX_SECONDS: curl, or python3 where curl is missing (both honour https_proxy)
fetch() {
    if command -v curl >/dev/null; then
        curl -fsSL --max-time "$3" --max-filesize 104857600 -H 'Accept: application/vnd.github+json' "$1" -o "$2"
    else
        python3 - "$1" "$2" "$3" <<'PY'
import sys, urllib.request
url, out, limit = sys.argv[1], sys.argv[2], int(sys.argv[3])
req = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'jt-yara-update'})
with urllib.request.urlopen(req, timeout=limit) as r, open(out, 'wb') as f:
    n = 0
    while True:
        b = r.read(1 << 20)
        if not b:
            break
        n += len(b)
        if n > 104857600:
            sys.exit('too large')
        f.write(b)
PY
    fi
}
fail() { log ERROR "rules update failed: $1"; echo "jt-yara-update: $1" >&2; exit 1; }
while [ $# -gt 0 ]; do
    case "$1" in
        --set) SET=${2:?}; shift 2 ;;
        --min-age-days) MIN_AGE=${2:?}; shift 2 ;;
        --force) FORCE=yes; shift ;;
        --zip) ZIP=${2:?}; shift 2 ;;
        --tag) TAG=${2:?}; shift 2 ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done
[[ "$SET" =~ ^(core|extended|full)$ ]] || fail "unknown rule set $SET"
[[ "$MIN_AGE" =~ ^[0-9]+$ ]] || fail "--min-age-days needs a number"
[ -x "$YR" ] || fail "yr missing at $YR"
[ -r "$ETC/jt-test.yar" ] || fail "$ETC/jt-test.yar missing"
current=$(cat "$ETC/rules.name" 2>/dev/null)
work=$(mktemp -d) || fail "no temporary directory"
trap 'rm -rf "$work"' EXIT

if [ -z "$ZIP" ]; then
    fetch "$API" "$work/release.json" 60 || fail "cannot read $API"
    read -r TAG PUBLISHED URL DIGEST < <(python3 - "$work/release.json" "$SET" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
want = 'yara-forge-rules-%s.zip' % sys.argv[2]
a = next((a for a in d.get('assets') or [] if a.get('name') == want), None)
print(d.get('tag_name') or '-', d.get('published_at') or '-',
      a['browser_download_url'] if a else '-', (a.get('digest') or '-') if a else '-')
PY
)
    [[ "$TAG" =~ ^[0-9A-Za-z._-]{1,40}$ ]] || fail "unexpected release tag"
    [ "$URL" != - ] || fail "release $TAG has no yara-forge-rules-$SET.zip"
    [[ "$URL" == https://github.com/YARAHQ/yara-forge/releases/download/* ]] || fail "unexpected download address"
    [[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "release $TAG publishes no SHA-256 digest for the zip"
    if [ "$FORCE" = no ]; then
        [ "$current" = "yara-forge-$SET-$TAG" ] && exit 0
        age=$(( ( $(date +%s) - $(date -d "$PUBLISHED" +%s 2>/dev/null || echo 0) ) / 86400 ))
        [ "$age" -ge "$MIN_AGE" ] || exit 0
    fi
    fetch "$URL" "$work/rules.zip" 300 || fail "download of $URL failed"
    got=sha256:$(sha256sum "$work/rules.zip" | cut -d' ' -f1)
    [ "$got" = "$DIGEST" ] || fail "release $TAG: the zip does not match its published digest"
    ZIP=$work/rules.zip
else
    [ -r "$ZIP" ] || fail "$ZIP not readable"
    TAG=${TAG:-$(date -r "$ZIP" +%Y%m%d)}
    [[ "$TAG" =~ ^[0-9A-Za-z._-]{1,40}$ ]] || fail "unexpected --tag"
fi

python3 - "$ZIP" "$SET" "$work/rules.yar" <<'PY' || fail "the zip holds no packages/$SET/yara-rules-$SET.yar"
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
name = next(n for n in z.namelist() if n.endswith('/yara-rules-%s.yar' % sys.argv[2]) or n == 'yara-rules-%s.yar' % sys.argv[2])
with z.open(name) as src, open(sys.argv[3], 'wb') as dst:
    while True:
        b = src.read(1 << 20)
        if not b:
            break
        dst.write(b)
PY
count=$(grep -c '^rule ' "$work/rules.yar" || true)
nice -n 19 "$YR" compile -o "$work/rules.yarc" "$work/rules.yar" "$ETC/jt-test.yar" >/dev/null 2>"$work/err" \
    || fail "yara-forge-$SET-$TAG does not compile: $(head -c 200 "$work/err" | tr -d '\000-\037')"
printf '%s\n' 'JT-WAZUH-YARA-TEST-7f3a9c' > "$work/marker"
"$YR" scan -o ndjson -C "$work/rules.yarc" "$work/marker" 2>/dev/null | grep -q '"JT_Wazuh_YARA_Test"' \
    || fail "yara-forge-$SET-$TAG fails the self-test"
install -o root -g wazuh -m 0640 "$work/rules.yarc" "$ETC/rules.yarc.new" && mv -f "$ETC/rules.yarc.new" "$ETC/rules.yarc" \
    || fail "cannot write $ETC/rules.yarc"
printf '%s\n' "yara-forge-$SET-$TAG" > "$ETC/rules.name"
log UPDATE "rules yara-forge-$SET-$TAG installed ($count rules, was ${current:-unknown})"
[ -x /usr/local/sbin/jt-yara-status ] && /usr/local/sbin/jt-yara-status
exit 0
