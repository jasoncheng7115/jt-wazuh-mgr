#!/bin/sh
# jt-nextcloud log relay check (jt-nextcloud 1.2.5)
# Copyright Jason Tools Co., Ltd. / AGPL-3.0-or-later
#
# Run by root from cron every 15 minutes, for example /etc/cron.d/jt-nextcloud-relay:
#   */15 * * * * root /usr/local/sbin/jt-nextcloud-relay-check
#
# If rsyslog stops copying, Wazuh simply receives nothing, and nothing says so.
# This compares the modification times: when Nextcloud wrote to its log within
# LIMIT seconds but the copy is more than LIMIT seconds behind, it appends one
# JSON line to the copy itself, which the Wazuh agent reads (rule 131786). The
# line updates the copy's time, so a relay that stays broken is reported again
# about every LIMIT seconds, not every run.
#
# Arguments: the Nextcloud log, its copy, LIMIT (default 1800). With no
# arguments both default logs are checked.
check() {
    src=$1; dst=$2; limit=$3
    now=$(date +%s)
    s=$(stat -c %Y "$src" 2>/dev/null) || return 0      # no such log on this host
    [ $((now - s)) -le "$limit" ] || return 0             # Nextcloud quiet: nothing to compare
    [ -d "$(dirname "$dst")" ] || return 0                # relay never set up here
    d=$(stat -c %Y "$dst" 2>/dev/null || echo 0)
    [ $((s - d)) -gt "$limit" ] || return 0
    printf '{"jt_relay":"stale","source":"%s","relay":"%s","lag_seconds":%d}\n' \
        "$src" "$dst" $((s - d)) >> "$dst"
}
if [ $# -ge 2 ]; then
    check "$1" "$2" "${3:-1800}"
else
    check /var/www/nextcloud/data/nextcloud.log /var/log/jt-nextcloud/nextcloud.log 1800
    check /var/www/nextcloud/data/audit.log /var/log/jt-nextcloud/audit.log 1800
fi
