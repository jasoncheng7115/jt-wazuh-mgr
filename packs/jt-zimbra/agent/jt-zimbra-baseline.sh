#!/bin/sh
# jt-zimbra-baseline.sh - build etc/lists/zimbra-webfiles from Zimbra's own packages.
# Part of the jt-zimbra rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
#
# Run as root on each Zimbra server after every install and every upgrade.
# Copy the result to the manager's etc/lists/zimbra-webfiles (on a cluster, the
# master; the cluster copies it on) and reload the ruleset. With several
# servers, merge their outputs: sort -u server1 server2 > zimbra-webfiles.
#
# The list names the files Zimbra itself ships under the directories rule
# 100802 watches: jsp, jspx, jar, class, war and html files under
# /opt/zimbra/jetty_base/webapps, and every file under /opt/zimbra/lib/ext.
# They come from the package database (dpkg -L, or rpm -ql), not from what is
# on disk, so a web shell already present when the list is made is not blessed.
# Files on disk that no package owns are printed for review (third-party
# extensions in lib/ext, Zimbra's generated downloads page) and left out unless
# --include-unpackaged is given. Packaged files whose content no longer matches
# the package (dpkg --verify / rpm -V) are printed as a warning and left out.
#
# The list also gets one marker key per Zimbra release on this server,
# jt-zimbra-release/<x.y.z>:legit, which jt-zimbra-baseline-check.py on the
# manager reads to know which releases the list covers. A marker never matches
# a file path.
#
#   jt-zimbra-baseline.sh [-o FILE|-] [--include-unpackaged]
#
# Only reads the system; writes FILE (default ./zimbra-webfiles; "-" writes the
# list to standard output and the summary to standard error). Its temporary
# directory is removed on exit.

set -eu
OUT=./zimbra-webfiles
INCLUDE_UNPACKAGED=no
while [ $# -gt 0 ]; do
    case "$1" in
        -o) OUT=$2; shift 2 ;;
        --include-unpackaged) INCLUDE_UNPACKAGED=yes; shift ;;
        -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

WEBAPPS=/opt/zimbra/jetty_base/webapps
EXT=/opt/zimbra/lib/ext
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

watched() {     # stdin: paths; stdout: the ones 100802's directories cover
    awk -v w="$WEBAPPS/" -v e="$EXT/" '
        index($0, w) == 1 && $0 ~ /\.(jsp|jspx|jar|class|war|html)$/ { print; next }
        index($0, e) == 1 { print }'
}

if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W 'zimbra-core' >/dev/null 2>&1; then
    dpkg-query -W -f='${Package} ${Version}\n' 'zimbra*' > "$TMP/pkgs"
    awk '{print $1}' "$TMP/pkgs" | xargs dpkg -L 2>/dev/null > "$TMP/owned.all" || true
    # "??5??????   /path": the file's checksum differs from the package's
    awk '{print $1}' "$TMP/pkgs" | xargs dpkg --verify 2>/dev/null \
        | awk '$1 ~ /^..5/ {print $NF}' > "$TMP/modified.all" || true
elif command -v rpm >/dev/null 2>&1 && rpm -q zimbra-core >/dev/null 2>&1; then
    rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'zimbra*' > "$TMP/pkgs"
    awk '{print $1}' "$TMP/pkgs" | xargs rpm -ql 2>/dev/null > "$TMP/owned.all" || true
    awk '{print $1}' "$TMP/pkgs" | xargs rpm -V 2>/dev/null \
        | awk '$1 ~ /^..5/ {print $NF}' > "$TMP/modified.all" || true
else
    echo "no Zimbra packages found (dpkg or rpm): run this on a Zimbra server" >&2
    exit 1
fi

watched < "$TMP/owned.all" | while IFS= read -r f; do [ -d "$f" ] || printf '%s\n' "$f"; done \
    | sort -u > "$TMP/owned"
watched < "$TMP/modified.all" | sort -u > "$TMP/modified"
{ find "$WEBAPPS" -type f \( -name '*.jsp' -o -name '*.jspx' -o -name '*.jar' -o -name '*.class' \
       -o -name '*.war' -o -name '*.html' \) 2>/dev/null
  find "$EXT" -type f 2>/dev/null; } | sort -u > "$TMP/disk"
comm -23 "$TMP/disk" "$TMP/owned" > "$TMP/unpackaged"
comm -23 "$TMP/owned" "$TMP/modified" > "$TMP/keep"

# Releases: the highest x.y.z among the packages that carry the web directories
# (a patch release updates the web packages before zimbra-core).
awk '$1 ~ /^zimbra-(core|store|patch|mbox-(webclient-war|admin-console-war|service|war|store-libs)|common-core-jar|common-mbox-conf)$/ {
        if (match($2, /^[0-9]+\.[0-9]+\.[0-9]+/)) { v = substr($2, RSTART, RLENGTH); split(v, p, ".");
            if (p[1] + 0 >= 8) print v } }' "$TMP/pkgs" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1 > "$TMP/release"

{
    sed 's/$/:legit/' "$TMP/keep"
    if [ "$INCLUDE_UNPACKAGED" = yes ]; then sed 's/$/:legit/' "$TMP/unpackaged"; fi
    sed 's|^|jt-zimbra-release/|; s/$/:legit/' "$TMP/release"
} | sort -u > "$TMP/list"
if [ "$OUT" = - ]; then cat "$TMP/list"; exec 1>&2; else cp "$TMP/list" "$OUT"; fi

echo "Zimbra release:            $(cat "$TMP/release" 2>/dev/null || echo unknown)"
echo "from the package database: $(wc -l < "$TMP/keep") files"
echo "on disk, owned by no package: $(wc -l < "$TMP/unpackaged") ($( [ "$INCLUDE_UNPACKAGED" = yes ] && echo included || echo 'left out; --include-unpackaged after review'))"
if [ -s "$TMP/unpackaged" ]; then
    while IFS= read -r f; do
        echo "    $f  $(stat -c '%U %y' "$f" 2>/dev/null | cut -c1-30)"
    done < "$TMP/unpackaged"
fi
if [ -s "$TMP/modified" ]; then
    echo "WARNING: packaged files whose content differs from the package (left out, check them):"
    sed 's/^/    /' "$TMP/modified"
fi
echo "written: $OUT ($(wc -l < "$TMP/list") lines)"
