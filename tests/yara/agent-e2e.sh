#!/bin/bash
# jt-yara agent scripts, end to end, inside a throwaway Debian container (run by
# tests/test_pack_yara.py): install, status line, a match, quarantine, the site's own scan
# paths, a file name with a newline, the counters, and an install that must refuse.
# /pack holds packs/jt-yara/agent, /yr the YARA-X CLI. Prints PASS/FAIL lines.
set -u
fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }
LOG=/var/ossec/logs/active-responses.log

groupadd -r wazuh 2>/dev/null
mkdir -p /var/ossec/active-response/bin /var/ossec/etc /var/ossec/logs /var/ossec/var /var/ossec/tmp /var/ossec/etc/shared /etc/cron.d
touch $LOG
cp /pack/* /var/ossec/etc/shared/
# a harmless rule standing in for YARA-Forge: it matches only a marker string
cat > /tmp/rules.yar <<'R'
rule JT_E2E_Fake_Webshell {
  strings:
    $m = "JT-E2E-FAKE-WEBSHELL-4c1d"
  condition:
    $m
}
R

# 1. install refuses without yr, then installs
bash /var/ossec/etc/shared/jt-yara-install.sh --rules /tmp/rules.yar >/tmp/o 2>&1 && bad "install without yr must fail" || ok "install without yr refused"
bash /var/ossec/etc/shared/jt-yara-install.sh --yr /yr --rules /tmp/rules.yar --rules-name e2e-rules --scan-path /srv/app/ >/tmp/o 2>&1 \
    && ok "install" || { bad "install"; cat /tmp/o; }
grep -q 'restart the agent' /tmp/o && ok "first install asks for an agent restart" || bad "restart note"
[ -x /usr/local/bin/yr ] && [ -r /var/ossec/etc/yara/rules.yarc ] && [ -x /var/ossec/active-response/bin/jt-yara.sh ] \
    && [ -x /var/ossec/active-response/bin/jt-yara-quarantine.sh ] && [ -f /etc/cron.d/jt-yara-status ] && ok "files in place" || bad "files in place"
[ "$(stat -c %G /var/ossec/active-response/bin/jt-yara.sh)" = wazuh ] && ok "scripts owned by group wazuh" || bad "group"
tail -1 $LOG | grep -Eq '^wazuh-yara: STATUS - state=ok yr=1\.[0-9.]+ rules=[0-9a-f]{12} rules_name=e2e-rules rules_age=0 scans=0 errors=0 hits=0 quarantine=yes problem=-$' \
    && ok "status line after install" || { bad "status line after install"; tail -1 $LOG; }

ar() { printf '{"command":"add","parameters":{"alert":{"syscheck":{"path":%s}}}}\n' "$(printf '%s' "$1" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')" | /var/ossec/active-response/bin/jt-yara.sh; }
qr() { printf '{"command":"add","parameters":{"alert":{"data":{"yara":{"rule":"%s","file":"%s"}}}}}\n' "$1" "$2" | /var/ossec/active-response/bin/jt-yara-quarantine.sh; }

# 2. a match in a built-in path, then quarantine
mkdir -p /var/www/html
echo 'x JT-E2E-FAKE-WEBSHELL-4c1d x' > /var/www/html/up.php
ar /var/www/html/up.php
tail -1 $LOG | grep -qx 'wazuh-yara: INFO - Scan result: JT_E2E_Fake_Webshell /var/www/html/up.php' && ok "match reported" || { bad "match"; tail -2 $LOG; }
qr JT_E2E_Fake_Webshell /var/www/html/up.php
[ ! -e /var/www/html/up.php ] && ls /var/ossec/quarantine/*/file >/dev/null 2>&1 && ok "quarantined" || bad "quarantine"
grep -q '^path=/var/www/html/up.php$' /var/ossec/quarantine/*/meta && ok "meta keeps the path" || bad "meta"

# 3. a clean file: no line; the quarantine refuses a file the rule does not match
echo 'clean' > /var/www/html/ok.php
n=$(wc -l < $LOG); ar /var/www/html/ok.php
[ "$(wc -l < $LOG)" = "$n" ] && ok "clean file: no line" || bad "clean file"
qr JT_E2E_Fake_Webshell /var/www/html/ok.php
[ -e /var/www/html/ok.php ] && tail -1 $LOG | grep -q 'does not match it on a rescan' && ok "forged quarantine request refused" || bad "rescan refusal"

# 4. the site's own path from --scan-path, and a path outside every scope
mkdir -p /srv/app /opt/other
echo 'JT-E2E-FAKE-WEBSHELL-4c1d' > /srv/app/a.php; ar /srv/app/a.php
tail -1 $LOG | grep -q 'Scan result: JT_E2E_Fake_Webshell /srv/app/a.php' && ok "scan-paths.local prefix scanned" || bad "local prefix"
echo 'JT-E2E-FAKE-WEBSHELL-4c1d' > /opt/other/a.php; n=$(wc -l < $LOG); ar /opt/other/a.php
[ "$(wc -l < $LOG)" = "$n" ] && ok "path outside the scope ignored" || bad "out of scope"
qr JT_E2E_Fake_Webshell /opt/other/a.php
[ -e /opt/other/a.php ] && ok "quarantine refuses outside the scope" || bad "quarantine scope"
# a name with ".." inside it is still scanned (only a real ../ component is refused)
echo 'JT-E2E-FAKE-WEBSHELL-4c1d' > '/var/www/html/x..php'; ar '/var/www/html/x..php'
tail -1 $LOG | grep -q 'Scan result: JT_E2E_Fake_Webshell /var/www/html/x..php' && ok "a name containing .. is scanned" || bad "dotdot name"

# 5. a file name with a newline: reported escaped, never a forged result line
d=$'/var/www/html/n\nWebshell /var/www/html/index.php'
mkdir -p "$(dirname "$d")"; echo 'JT-E2E-FAKE-WEBSHELL-4c1d' > "$d"; ar "$d"
grep -q 'file name with control characters' $LOG && ok "control character name reported" || bad "control name"
grep -qx 'wazuh-yara: INFO - Scan result: Webshell /var/www/html/index.php' $LOG && bad "forged result line written" || ok "no forged result line"

# 6. the counters reach the next status line, then reset
/usr/local/sbin/jt-yara-status
tail -1 $LOG | grep -Eq 'scans=5 errors=0 hits=4 quarantine=yes problem=-$' && ok "counters in the status line" || { bad "counters"; tail -1 $LOG; }
/usr/local/sbin/jt-yara-status
tail -1 $LOG | grep -q 'scans=0 errors=0 hits=0' && ok "counters reset" || bad "counter reset"

# 7. broken states: rules not matching the self-test, then yr removed
cp /var/ossec/etc/yara/rules.yarc /tmp/good.yarc
/yr compile -o /var/ossec/etc/yara/rules.yarc /tmp/rules.yar >/dev/null 2>&1
/usr/local/sbin/jt-yara-status
tail -1 $LOG | grep -q 'state=broken .*problem=self-test: the compiled rules did not match the test marker' && ok "self-test failure is broken" || { bad "self-test broken"; tail -1 $LOG; }
cp /tmp/good.yarc /var/ossec/etc/yara/rules.yarc
mv /usr/local/bin/yr /tmp/yr.saved; /usr/local/sbin/jt-yara-status
tail -1 $LOG | grep -q 'state=broken yr=- .*problem=yr missing at /usr/local/bin/yr' && ok "missing yr is broken" || { bad "missing yr"; tail -1 $LOG; }
echo 'JT-E2E-FAKE-WEBSHELL-4c1d' > /var/www/html/b.php; ar /var/www/html/b.php
tail -1 $LOG | grep -q 'ERROR - yr or compiled rules missing' && ok "scan without yr logs an error" || bad "scan without yr"
mv /tmp/yr.saved /usr/local/bin/yr
# stale rules
touch -d '40 days ago' /var/ossec/etc/yara/rules.yarc; /usr/local/sbin/jt-yara-status
tail -1 $LOG | grep -q 'state=stale .*rules_age=40 ' && ok "old rules are stale" || { bad "stale"; tail -1 $LOG; }

# 8. scan-only install removes the quarantine; a second install changes nothing else and asks no restart
bash /var/ossec/etc/shared/jt-yara-install.sh --no-quarantine >/tmp/o 2>&1 && ok "update to scan only" || { bad "scan-only"; cat /tmp/o; }
[ ! -e /var/ossec/active-response/bin/jt-yara-quarantine.sh ] && ok "quarantine removed" || bad "quarantine still there"
grep -q 'restart the agent' /tmp/o && bad "an update asked for a restart" || ok "an update needs no restart"
tail -1 $LOG | grep -q 'quarantine=no' && ok "status says quarantine=no" || bad "quarantine=no"
bash /var/ossec/etc/shared/jt-yara-install.sh --scan-path 'relative/' >/tmp/o 2>&1 && bad "bad --scan-path accepted" || ok "bad --scan-path refused"
grep -c '^/srv/app/$' /var/ossec/etc/yara/scan-paths.local | grep -qx 1 && ok "scan path kept once" || bad "scan path duplicated"

[ $fail = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
