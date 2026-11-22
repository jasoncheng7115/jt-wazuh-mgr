#!/bin/bash
# jt-yara 1.0 - Wazuh active response: scan the file a FIM alert names with YARA-X.
#
# Triggered by the FIM rules listed in the manager's <active-response> for jt-yara.
# Only web / application / temporary paths are scanned: the built-in ones below plus
# the path prefixes in /var/ossec/etc/yara/scan-paths.local (one per line, compared
# literally). Everything else FIM reports (package upgrades under /usr, /etc ...) is
# ignored here. Results go to active-responses.log as "wazuh-yara: <level> - ..." lines,
# which the agent already sends to the manager (decoder jt-yara).
#
# Installed by jt-yara-install.sh:
#   /usr/local/bin/yr                    YARA-X CLI
#   /var/ossec/etc/yara/rules.yarc       compiled rules (yr compile)
#   /var/ossec/active-response/bin/jt-yara.sh
# Counters for the daily status line (jt-yara-status.sh): /var/ossec/var/jt-yara.stats

LOG=/var/ossec/logs/active-responses.log
YR=/usr/local/bin/yr
RULES=/var/ossec/etc/yara/rules.yarc
LOCAL_PATHS=/var/ossec/etc/yara/scan-paths.local
STATS=/var/ossec/var/jt-yara.stats
LOCK=/var/run/jt-yara.lock
MAX_BYTES=104857600   # files above 100 MB are not scanned
SCAN_PATHS='^(/var/www/|/srv/www/|/usr/share/nginx/html/|/usr/local/lib/z-push/|/usr/share/z-push/|/opt/zimbra/(jetty_base/webapps|lib/ext|zimlets-deployed)/|/tmp/|/var/tmp/|/dev/shm/)'

log() { echo "wazuh-yara: $1 - $2" >> "$LOG"; }

# bump <scans> <errors> <hits>: add to the counters the status line reports and resets
bump() {
    (
        flock -w 10 8 || exit 0
        n_scans=0 n_errors=0 n_hits=0          # own names: the caller's variables must not leak in
        [ -s "$STATS" ] && read -r n_scans n_errors n_hits < "$STATS"
        echo "$(( ${n_scans:-0} + $1 )) $(( ${n_errors:-0} + $2 )) $(( ${n_hits:-0} + $3 ))" > "$STATS"
    ) 8>>"$STATS.lock"
}

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
FILE=$(printf '%s' "$INPUT" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    if d.get("command") == "add":
        print(d["parameters"]["alert"]["syscheck"]["path"])
except Exception:
    pass' 2>/dev/null)

[ -n "$FILE" ] || exit 0
in_scope "$FILE" || exit 0
[ -f "$FILE" ] || exit 0
if [ ! -x "$YR" ] || [ ! -r "$RULES" ]; then
    log ERROR "yr or compiled rules missing, cannot scan $FILE"
    bump 0 1 0
    exit 0
fi

# Uploads may still be growing: wait until the size stops changing.
size=-1
for _ in 1 2 3 4 5; do
    s=$(stat -c %s "$FILE" 2>/dev/null) || exit 0
    [ "$s" = "$size" ] && break
    size=$s
    sleep 1
done
[ "$size" -le "$MAX_BYTES" ] || exit 0

# One scan at a time: a deployment can touch thousands of files at once.
exec 9>"$LOCK"
flock -w 600 9 || { log ERROR "scan queue busy, skipped $FILE"; bump 0 1 0; exit 0; }

# A file or directory name can hold a newline. yr's text output prints it as
# is, so a name such as "x<newline>Webshell /var/www/html/index.php" made the
# first version write a forged "Scan result" line, and the quarantine then moved
# the real index.php. Results are read from yr's JSON output and kept only when
# their path is exactly the file scanned, and a path is written to the log
# escaped, never raw.
SHOWN=$(printf '%s' "$FILE" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])')
if [[ "$FILE" == *[[:cntrl:]]* ]]; then
    log ERROR "file name with control characters: $SHOWN"
fi

ERR=$(mktemp)
OUT=$(nice -n 19 ionice -c3 timeout 120 "$YR" scan -o ndjson -C "$RULES" "$FILE" 2>"$ERR")
rc=$?
if [ $rc -ne 0 ]; then
    log ERROR "yr exit $rc on $SHOWN: $(head -c 300 "$ERR" | tr -d '\000-\037')"
    rm -f "$ERR"
    bump 1 1 0
    exit 0
fi
rm -f "$ERR"
HITS=$(printf '%s' "$OUT" | python3 -c '
import json, re, sys
target = sys.argv[1]
for line in sys.stdin:
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if rec.get("path") != target:
        continue
    for rule in rec.get("rules") or []:
        name = str(rule.get("identifier", ""))
        if re.fullmatch(r"[A-Za-z0-9_]{1,128}", name):
            print(name)
' "$FILE")
n=0
while IFS= read -r rule; do
    [ -n "$rule" ] || continue
    log INFO "Scan result: $rule $SHOWN"
    n=$((n + 1))
done <<< "$HITS"
bump 1 0 "$n"
exit 0
