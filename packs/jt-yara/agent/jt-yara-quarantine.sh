#!/bin/bash
# jt-yara 1.0 - Wazuh active response: quarantine a file YARA matched (rules 133401 / 133402).
#
# The file is moved to /var/ossec/quarantine/<time>-<sha256 prefix>/ with mode 000,
# next to a meta file holding the original path, owner, mode and sha256, so a
# false positive can be put back:
#   install -o <owner> -g <group> -m <mode> <quarantine>/file <original path>
# A sha256 listed in quarantine-allow.sha256 (one per line) is never moved: add
# confirmed false positives there.
# Only paths jt-yara.sh scans are touched; anything else is refused. Not installed on
# hosts that should only scan (development machines): the manager's quarantine
# command then has nothing to run there.

LOG=/var/ossec/logs/active-responses.log
YR=/usr/local/bin/yr
RULES=/var/ossec/etc/yara/rules.yarc
QDIR=/var/ossec/quarantine
ALLOW=/var/ossec/etc/yara/quarantine-allow.sha256
LOCAL_PATHS=/var/ossec/etc/yara/scan-paths.local
SCAN_PATHS='^(/var/www/|/srv/www/|/usr/share/nginx/html/|/usr/local/lib/z-push/|/usr/share/z-push/|/opt/zimbra/(jetty_base/webapps|lib/ext|zimlets-deployed)/|/tmp/|/var/tmp/|/dev/shm/)'

log() { echo "wazuh-yara: $1 - $2" >> "$LOG"; }

# the same scope as jt-yara.sh: the built-in paths and the prefixes in scan-paths.local
in_scope() {
    [[ "$1" =~ $SCAN_PATHS ]] && return 0
    [ -r "$LOCAL_PATHS" ] || return 1
    local p
    while IFS= read -r p; do
        case "$p" in /*/) [[ "$1" == "$p"* ]] && return 0 ;; esac
    done < "$LOCAL_PATHS"
    return 1
}

read -r INPUT
read -r RULE FILE < <(printf '%s' "$INPUT" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    if d.get("command") == "add":
        y = d["parameters"]["alert"]["data"]["yara"]
        print(y["rule"], y["file"])
except Exception:
    pass' 2>/dev/null)

[ -n "$FILE" ] || exit 0
if ! in_scope "$FILE" || [[ "$FILE" == */../* ]]; then
    log QUARANTINE "refused $FILE: outside the scanned paths"
    exit 0
fi
[ -f "$FILE" ] && [ ! -L "$FILE" ] || exit 0
if ! [[ "$RULE" =~ ^[A-Za-z0-9_]{1,128}$ ]] || [[ "$FILE" == *[[:cntrl:]]* ]]; then
    log QUARANTINE "refused a malformed request"
    exit 0
fi

# Never move a file on the alert's word alone: scan it again and move it only
# if the same rule matches this very path. A forged or stale "Scan result"
# (see jt-yara.sh) then moves nothing.
if ! nice -n 19 timeout 120 "$YR" scan -o ndjson -C "$RULES" "$FILE" 2>/dev/null | python3 -c '
import json, sys
path, rule = sys.argv[1], sys.argv[2]
for line in sys.stdin:
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if rec.get("path") == path and any(r.get("identifier") == rule for r in rec.get("rules") or []):
        sys.exit(0)
sys.exit(1)
' "$FILE" "$RULE"; then
    log QUARANTINE "refused $FILE: $RULE does not match it on a rescan"
    exit 0
fi

SHA=$(sha256sum "$FILE" | cut -d' ' -f1)
if [ -r "$ALLOW" ] && grep -qix "$SHA" "$ALLOW"; then
    log QUARANTINE "kept $FILE: sha256 $SHA is in the allow list ($RULE)"
    exit 0
fi

DEST="$QDIR/$(date +%Y%m%dT%H%M%S)-${SHA:0:12}"
mkdir -p "$DEST" && chmod 0700 "$QDIR" "$DEST" || { log QUARANTINE "failed to create $DEST for $FILE"; exit 0; }
{
    echo "path=$FILE"
    echo "rule=$RULE"
    echo "sha256=$SHA"
    stat --printf 'owner=%U\ngroup=%G\nmode=%a\nsize=%s\nmtime=%y\n' "$FILE"
    echo "quarantined=$(date -Is)"
} > "$DEST/meta"
if mv -f "$FILE" "$DEST/file"; then
    chmod 000 "$DEST/file"
    log QUARANTINE "moved $FILE to $DEST ($RULE, sha256 $SHA)"
else
    log QUARANTINE "failed to move $FILE ($RULE, sha256 $SHA)"
fi
exit 0
