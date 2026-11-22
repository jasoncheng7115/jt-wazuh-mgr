#!/bin/bash
# jt-yara 1.1.1 - install or update the YARA-X scanner on a Wazuh agent (Linux, as root).
#
#   jt-yara-install.sh [--yr PATH] [--rules FILE.yar [--rules-name NAME]]
#                      [--scan-path /prefix/ ...] [--no-quarantine] [--no-auto-update] [--restart]
#
#   --yr PATH          a YARA-X CLI binary to install as /usr/local/bin/yr (official release
#                      from github.com/VirusTotal/yara-x; a CPU without AVX2 needs a build for
#                      x86-64-v2). Without it an existing /usr/local/bin/yr is kept.
#   --rules FILE       YARA source to compile into /var/ossec/etc/yara/rules.yarc together with
#                      the pipeline test rule (YARA-Forge core: yara-rules-core.yar). Without it
#                      existing compiled rules are kept; with neither, the latest YARA-Forge core
#                      release is fetched (jt-yara-update, checked against its published digest).
#   --rules-name NAME  recorded for the status line (default: the file name and its date)
#   --scan-path P      also scan files under this prefix (repeatable; kept in scan-paths.local)
#   --no-quarantine    scan only: matches are reported, nothing is moved (development hosts)
#   --no-auto-update   no weekly rules update (a host without Internet access: update it with
#                      jt-yara-update --zip FILE)
#   --restart          restart the agent if the active response is new (see below)
#
# The files come from the same directory as this script: the agent group "yara" delivers them
# to /var/ossec/etc/shared/. Nothing is downloaded. The manager's ossec.conf must define the
# jt-yara and jt-yara-quarantine commands (the pack's setup steps).
#
# The agent's active response daemon checks which scripts exist only when the agent starts, so
# after the first install the agent must be restarted (--restart, or systemctl restart
# wazuh-agent); updates of an installed script need no restart.

set -euo pipefail
SRC=$(cd "$(dirname "$0")" && pwd)
OSSEC=/var/ossec
AR=$OSSEC/active-response/bin
ETC=$OSSEC/etc/yara
YR=/usr/local/bin/yr
NEW_YR= RULES_SRC= RULES_NAME= QUARANTINE=yes RESTART=no AUTO_UPDATE=yes PATHS=()

die() { echo "jt-yara-install: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
    case "$1" in
        --yr) NEW_YR=${2:?}; shift 2 ;;
        --rules) RULES_SRC=${2:?}; shift 2 ;;
        --rules-name) RULES_NAME=${2:?}; shift 2 ;;
        --scan-path) PATHS+=("${2:?}"); shift 2 ;;
        --no-quarantine) QUARANTINE=no; shift ;;
        --no-auto-update) AUTO_UPDATE=no; shift ;;
        --restart) RESTART=yes; shift ;;
        -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done
[ "$(id -u)" = 0 ] || die "run as root"
[ -d "$AR" ] || die "no Wazuh agent at $OSSEC"
for f in jt-yara.sh jt-yara-quarantine.sh jt-yara-status.sh jt-yara-update.sh jt-test.yar; do
    [ -r "$SRC/$f" ] || die "$SRC/$f missing (put the host in the agent group yara, or copy the pack's agent/ files here)"
done

# 1. the YARA-X CLI
if [ -n "$NEW_YR" ]; then
    "$NEW_YR" --version >/dev/null 2>&1 || die "$NEW_YR does not run here (a CPU without AVX2 needs an x86-64-v2 build)"
    install -o root -g root -m 0755 "$NEW_YR" "$YR.new" && mv -f "$YR.new" "$YR"
fi
[ -x "$YR" ] && "$YR" --version >/dev/null 2>&1 || die "no working $YR: give one with --yr"
echo "yr: $("$YR" --version)"

# 2. the compiled rules, with the self-test rule; only replaced once the new set compiles and works
install -d -o root -g wazuh -m 0750 "$ETC"
install -o root -g wazuh -m 0640 "$SRC/jt-test.yar" "$ETC/jt-test.yar"
if [ -n "$RULES_SRC" ]; then
    [ -r "$RULES_SRC" ] || die "$RULES_SRC not readable"
    "$YR" compile -o "$ETC/rules.yarc.new" "$RULES_SRC" "$ETC/jt-test.yar" >/dev/null || die "the rules did not compile"
    t=$(mktemp); echo 'JT-WAZUH-YARA-TEST-7f3a9c' > "$t"
    if ! "$YR" scan -o ndjson -C "$ETC/rules.yarc.new" "$t" | grep -q '"JT_Wazuh_YARA_Test"'; then
        rm -f "$t" "$ETC/rules.yarc.new"; die "the compiled rules failed the self-test"
    fi
    rm -f "$t"
    chown root:wazuh "$ETC/rules.yarc.new"; chmod 0640 "$ETC/rules.yarc.new"
    mv -f "$ETC/rules.yarc.new" "$ETC/rules.yarc"
    printf '%s\n' "${RULES_NAME:-$(basename "$RULES_SRC" .yar)-$(date -r "$RULES_SRC" +%Y%m%d)}" > "$ETC/rules.name"
fi
install -o root -g root -m 0750 "$SRC/jt-yara-update.sh" /usr/local/sbin/jt-yara-update
if [ ! -r "$ETC/rules.yarc" ]; then
    echo "no rules given: fetching the latest YARA-Forge core release"
    /usr/local/sbin/jt-yara-update --min-age-days 0 --force || die "no compiled rules: give the YARA source with --rules, or let this host reach github.com"
fi
[ -r "$ETC/rules.yarc" ] || die "no compiled rules: give the YARA source with --rules"

# 3. scan paths of this site
for p in ${PATHS[@]+"${PATHS[@]}"}; do
    [[ "$p" =~ ^/[A-Za-z0-9._/-]+/$ ]] || die "--scan-path $p: an absolute directory ending in /"
    grep -qxF "$p" "$ETC/scan-paths.local" 2>/dev/null || echo "$p" >> "$ETC/scan-paths.local"
done

# 4. the active responses and the status script
first=no
[ -e "$AR/jt-yara.sh" ] || first=yes
install -o root -g wazuh -m 0750 "$SRC/jt-yara.sh" "$AR/jt-yara.sh"
if [ "$QUARANTINE" = yes ]; then
    install -o root -g wazuh -m 0750 "$SRC/jt-yara-quarantine.sh" "$AR/jt-yara-quarantine.sh"
else
    rm -f "$AR/jt-yara-quarantine.sh"
fi
install -o root -g root -m 0750 "$SRC/jt-yara-status.sh" /usr/local/sbin/jt-yara-status
m=$(( $(hostname | cksum | cut -d' ' -f1) % 60 ))
printf 'SHELL=/bin/sh\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n%d 4 * * * root /usr/local/sbin/jt-yara-status\n' "$m" > /etc/cron.d/jt-yara-status.new
chmod 0644 /etc/cron.d/jt-yara-status.new && mv -f /etc/cron.d/jt-yara-status.new /etc/cron.d/jt-yara-status
if [ "$AUTO_UPDATE" = yes ]; then
    printf 'SHELL=/bin/sh\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n%d 5 * * 0 root /usr/local/sbin/jt-yara-update\n' "$m" > /etc/cron.d/jt-yara-update.new
    chmod 0644 /etc/cron.d/jt-yara-update.new && mv -f /etc/cron.d/jt-yara-update.new /etc/cron.d/jt-yara-update
else
    rm -f /etc/cron.d/jt-yara-update
fi

# 5. the agent must read active-responses.log, or nothing reaches the manager
if ! grep -qs 'active-responses.log' "$OSSEC/etc/ossec.conf" "$OSSEC/etc/shared/agent.conf"; then
    echo "WARNING: this agent does not read $OSSEC/logs/active-responses.log: scan results and status lines"
    echo "         will not reach the manager. Put the host in the agent group yara (its configuration reads"
    echo "         it), or add a <localfile> for it (log_format syslog) to ossec.conf and restart the agent."
fi

# 6. the first status line now, so the manager knows this host
/usr/local/sbin/jt-yara-status
tail -1 $OSSEC/logs/active-responses.log

if [ "$first" = yes ]; then
    if [ "$RESTART" = yes ]; then
        systemctl restart wazuh-agent && echo "agent restarted: the active response is active"
    else
        echo "NOTE: restart the agent (systemctl restart wazuh-agent): its active response daemon only sees scripts present when it starts"
    fi
fi
echo "jt-yara installed (quarantine: $QUARANTINE, weekly rules update: $AUTO_UPDATE)"
