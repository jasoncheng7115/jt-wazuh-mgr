#!/bin/bash
# jt-yara 1.0 - daily status line for the manager (rules 133430-133433).
#
# Run by /etc/cron.d/jt-yara-status (installed by jt-yara-install.sh) and once at
# install time. Writes one line to active-responses.log, which the agent sends:
#   wazuh-yara: STATUS - state=ok yr=1.22.1 rules=8c1ddb28cf24 rules_name=<name> rules_age=24
#                        scans=12 errors=0 hits=0 quarantine=yes problem=-
# state: ok, stale (rules older than STALE_DAYS) or broken (it cannot scan: yr missing or
# failing, rules missing, the self-test marker not found, the active response missing).
# The counters cover the time since the previous status line and are reset by it.
# A host that stops sending this line is reported by the manager (jt-yara-inventory.py).

LOG=/var/ossec/logs/active-responses.log
YR=/usr/local/bin/yr
RULES=/var/ossec/etc/yara/rules.yarc
NAME_FILE=/var/ossec/etc/yara/rules.name
STATS=/var/ossec/var/jt-yara.stats
AR=/var/ossec/active-response/bin
STALE_DAYS=${JT_YARA_STALE_DAYS:-30}
MARKER='JT-WAZUH-YARA-TEST-7f3a9c'

problem=()
yrv=-
if [ -x "$YR" ]; then
    yrv=$("$YR" --version 2>/dev/null | awk '{print $NF; exit}')
    [ -n "$yrv" ] || { yrv=fails; problem+=("yr does not run (exit $?; a CPU without AVX2 needs an x86-64-v2 build)"); }
else
    problem+=("yr missing at $YR")
fi

rsha=- rage=- rname=-
if [ -r "$RULES" ]; then
    rsha=$(sha256sum "$RULES" | cut -c1-12)
    rage=$(( ( $(date +%s) - $(stat -c %Y "$RULES") ) / 86400 ))
    [ -r "$NAME_FILE" ] && rname=$(head -c 80 "$NAME_FILE" | tr -cd 'A-Za-z0-9._-')
    [ -n "$rname" ] || rname=-
else
    problem+=("compiled rules missing at $RULES")
fi

# the end-to-end check of the engine and the rules: a file with the test marker must match
if [ "$yrv" != - ] && [ "$yrv" != fails ] && [ -r "$RULES" ]; then
    t=$(mktemp /var/ossec/tmp/jt-yara-selftest.XXXXXX 2>/dev/null || mktemp)
    printf '%s\n' "$MARKER" > "$t"
    if ! timeout 120 "$YR" scan -o ndjson -C "$RULES" "$t" 2>/dev/null | grep -q '"JT_Wazuh_YARA_Test"'; then
        problem+=("self-test: the compiled rules did not match the test marker")
    fi
    rm -f "$t"
fi

[ -x "$AR/jt-yara.sh" ] || problem+=("active response $AR/jt-yara.sh missing")
q=no
[ -x "$AR/jt-yara-quarantine.sh" ] && q=yes

# counters since the previous status line, then reset
s=0 e=0 h=0
if [ -s "$STATS" ]; then
    exec 8>>"$STATS.lock"
    flock -w 10 8
    read -r s e h < "$STATS" || true
    : > "$STATS"
    flock -u 8
fi
[[ "$s$e$h" =~ ^[0-9]+$ ]] || s=0 e=0 h=0

state=ok
[ "$rage" != - ] && [ "$rage" -ge "$STALE_DAYS" ] && state=stale
[ ${#problem[@]} -gt 0 ] && state=broken
p=-
[ ${#problem[@]} -gt 0 ] && p=$(IFS='; '; echo "${problem[*]}")

echo "wazuh-yara: STATUS - state=$state yr=$yrv rules=$rsha rules_name=$rname rules_age=$rage scans=${s:-0} errors=${e:-0} hits=${h:-0} quarantine=$q problem=$p" >> "$LOG"
