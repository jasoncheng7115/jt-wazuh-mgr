#!/bin/sh
# jt-container-vuln installer (jt-wazuh-mgr rule pack jt-container-vuln 1.0)
# License: AGPL-3.0-or-later. Author: Jason Tools.
#
# Installs the container image scanner on one Docker host and schedules it
# once a day. Run as root on the host, from the copy the agent group
# "container-vuln" delivers:
#
#   sh /var/ossec/etc/shared/jt-container-vuln-install.sh            install or update
#   sh /var/ossec/etc/shared/jt-container-vuln-install.sh --run-now  ... and start a first scan
#   sh /var/ossec/etc/shared/jt-container-vuln-install.sh --uninstall
#   sh /var/ossec/etc/shared/jt-container-vuln-install.sh --uninstall --purge
#
# Running it again updates the script and the schedule and keeps the
# configuration. It installs no package and changes nothing in Docker: the
# scanner (Trivy) runs as a container from an image pinned by digest and is
# pulled on the first run.
#
# What it writes:
#   /usr/local/lib/jt-container-vuln/jt-container-vuln.py   the scanner
#   /etc/jt-container-vuln/jt-container-vuln.conf          settings (kept on update)
#   /etc/systemd/system/jt-container-vuln.service + .timer daily, 01:00 plus a
#                                                          fixed random delay of up to 4 h
#   (no systemd: /etc/cron.d/jt-container-vuln)
#   /var/cache/jt-container-vuln   vulnerability databases (about 1.6 GB, plus
#                                  1.5 GB when an image has Java packages)
#   /var/lib/jt-container-vuln     state (what was already reported)
#   /var/log/jt-container-vuln.json  results, rotated at 5 MB

set -eu
umask 022
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

NAME=jt-container-vuln
LIB=/usr/local/lib/$NAME
ETC=/etc/$NAME
CONF=$ETC/$NAME.conf
UNIT=/etc/systemd/system/$NAME.service
TIMER=/etc/systemd/system/$NAME.timer
CRON=/etc/cron.d/$NAME
CACHE=/var/cache/$NAME
STATE=/var/lib/$NAME
LOG=/var/log/$NAME.json
SRC=$(cd "$(dirname "$0")" && pwd)

action=install
run_now=no
purge=no
for arg in "$@"; do
    case "$arg" in
        --uninstall) action=uninstall ;;
        --purge) purge=yes ;;
        --run-now) run_now=yes ;;
        --source=*) SRC=${arg#--source=} ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

say() { printf '%s: %s\n' "$NAME" "$*"; }
die() { printf '%s: %s\n' "$NAME" "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"

has_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

uninstall() {
    if has_systemd; then
        systemctl disable --now "$NAME.timer" >/dev/null 2>&1 || true
        systemctl stop "$NAME.service" >/dev/null 2>&1 || true
    fi
    rm -f "$UNIT" "$TIMER" "$CRON"
    has_systemd && systemctl daemon-reload || true
    rm -rf "$LIB"
    # scanner containers of an interrupted run
    if command -v docker >/dev/null 2>&1; then
        docker ps -aq --filter label=$NAME=scanner 2>/dev/null | xargs -r docker rm -f >/dev/null 2>&1 || true
    fi
    if [ "$purge" = yes ]; then
        rm -rf "$ETC" "$CACHE" "$STATE"
        rm -f "$LOG" "$LOG.1"
        say "removed, including settings, databases, state and results"
        say "the Trivy image is left in Docker: docker image ls ghcr.io/aquasecurity/trivy"
    else
        say "removed; kept $ETC, $CACHE, $STATE and $LOG (use --purge to delete them)"
    fi
}

install_files() {
    [ -f "$SRC/$NAME.py" ] || die "$SRC/$NAME.py not found (is this host in the container-vuln agent group?)"
    command -v docker >/dev/null 2>&1 || die "docker not found"
    command -v python3 >/dev/null 2>&1 || die "python3 not found"
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' \
        || die "python3 3.6 or later needed"
    python3 -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "$SRC/$NAME.py" 2>/dev/null \
        || die "$SRC/$NAME.py is incomplete or damaged"

    install -d -m 0755 -o root -g root "$LIB"
    install -m 0750 -o root -g root "$SRC/$NAME.py" "$LIB/$NAME.py"
    install -d -m 0700 -o root -g root "$ETC" "$CACHE" "$STATE"
    if [ ! -f "$CONF" ]; then
        cat > "$CONF" <<'EOF'
# jt-container-vuln settings. Lines are KEY=VALUE; every key is optional and
# the values shown are the defaults. Updating the pack never rewrites this file.
#
# Scanner image, pinned by digest (a tag is refused). Leave commented to use
# the version the installed script was tested with; set it to use a local
# registry mirror of the same digest.
#TRIVY_IMAGE=ghcr.io/aquasecurity/trivy@sha256:<digest>
#
# Database sources (default: mirror.gcr.io, then ghcr.io). A local OCI mirror:
#DB_REPOSITORY=registry.example.com/aquasec/trivy-db:2
#JAVA_DB_REPOSITORY=registry.example.com/aquasec/trivy-java-db:1
# Java DB: auto = downloaded the first time an image has Java packages and
# deleted after a month without one; on; off (jar files are then skipped).
#JAVA_DB=auto
#KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
#KEV_FALLBACK_URL=https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json
#HTTPS_PROXY=http://proxy.example.com:3128
#NO_PROXY=
#
# Limits
#SCAN_TIMEOUT=900
#CPUS=1
#MEMORY=3g
#MIN_FREE_MB=1024
#MAX_IMAGES=100
#
# Which containers: docker ps --filter values (space separated), and a
# regular expression of image references to leave out.
#CONTAINER_FILTER=
#EXCLUDE_IMAGES=
#
# Repeats and staleness
#RESCAN_HOURS=20
#REMINDER_DAYS=7
#FAIL_REMINDER_DAYS=3
#DB_MAX_AGE_HOURS=48
#KEV_MAX_AGE_DAYS=7
EOF
        chmod 0600 "$CONF"
        say "created $CONF"
    else
        say "kept $CONF"
    fi
    if [ ! -e "$LOG" ]; then
        : > "$LOG"
    fi
    chmod 0640 "$LOG"
}

install_schedule() {
    if has_systemd; then
        rm -f "$CRON"
        cat > "$UNIT" <<EOF
[Unit]
Description=jt-container-vuln: scan the images of running containers (Trivy)
Documentation=https://github.com/jasoncheng7115/jt-wazuh-mgr
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/env python3 $LIB/$NAME.py
Nice=19
IOSchedulingClass=idle
CPUSchedulingPolicy=batch
TimeoutStartSec=6h
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
EOF
        cat > "$TIMER" <<EOF
[Unit]
Description=jt-container-vuln: daily container image scan

[Timer]
OnCalendar=*-*-* 01:00:00
RandomizedDelaySec=4h
FixedRandomDelay=true
Persistent=true
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF
        chmod 0644 "$UNIT" "$TIMER"
        systemctl daemon-reload
        systemctl enable --now "$NAME.timer" >/dev/null
        say "timer enabled: $(systemctl show -p NextElapseUSecRealtime --value $NAME.timer 2>/dev/null || true)"
        if [ "$run_now" = yes ]; then
            systemctl start --no-block "$NAME.service"
            say "first scan started; follow it with: journalctl -fu $NAME.service"
        fi
    else
        minute=$(awk 'BEGIN{srand(); print int(rand()*60)}')
        cat > "$CRON" <<EOF
# jt-container-vuln: daily container image scan (written by $NAME-install.sh)
$minute 1 * * * root nice -n 19 ionice -c 3 python3 $LIB/$NAME.py --delay 14400 >/dev/null 2>&1
EOF
        chmod 0644 "$CRON"
        say "no systemd: scheduled in $CRON"
        if [ "$run_now" = yes ]; then
            (nice -n 19 ionice -c 3 python3 "$LIB/$NAME.py" >/dev/null 2>&1 &)
            say "first scan started in the background"
        fi
    fi
}

case "$action" in
    uninstall) uninstall ;;
    install)
        install_files
        install_schedule
        say "installed. Results: $LOG (collected by the container-vuln agent group)"
        say "dry run, lists what would be scanned: python3 $LIB/$NAME.py --list"
        ;;
esac
