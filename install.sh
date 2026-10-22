#!/bin/bash
#
# jt-wazuh-mgr - Installation Script
# https://github.com/jasoncheng7115/jt-wazuh-mgr
#
# Online (downloads everything from GitHub and PyPI):
#   curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/install.sh | sudo bash
#
# Offline (no network at all; run from an extracted release directory):
#   sudo bash /path/to/jt-wazuh-mgr-X.Y.Z/install.sh --offline [--wheels DIR]
#   Program files are copied from the directory this script is in. Python
#   dependencies come from DIR (default: wheels/ beside this script); without
#   any wheels, an existing vendor/ that still imports is kept.
#   See offline-install.html on the project site.
#

# -E so the ERR trap below is inherited by functions and subshells; without it a
# failure inside one of those exits silently, which is the complaint this whole
# mechanism exists to answer.
set -eE

INSTALL_DIR="/opt/jt-wazuh-mgr"
BASE_URL="https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main"
DOCS_URL="https://jasoncheng7115.github.io/jt-wazuh-mgr"
SERVICE_NAME="jt-wazuh-mgr"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

OFFLINE=false
WHEELS_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --offline) OFFLINE=true ;;
        --wheels)
            [ -n "${2:-}" ] || { echo "--wheels needs a directory" >&2; exit 2; }
            WHEELS_DIR="$2"; shift ;;
        --wheels=*) WHEELS_DIR="${1#--wheels=}" ;;
        -h|--help)
            sed -n '2,15p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done
if [ -n "$WHEELS_DIR" ] && [ "$OFFLINE" != true ]; then
    echo "--wheels only applies together with --offline" >&2
    exit 2
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Point the reader at the troubleshooting page in the language their system is
# set to, defaulting to English. Under "curl ... | sudo bash" the environment is
# usually reset, so the shell variables are checked first and the system-wide
# locale file second -- that file is what survives sudo.
detect_lang_suffix() {
    local loc="${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}"
    if [ -z "$loc" ] || [ "$loc" = "C" ] || [ "$loc" = "POSIX" ]; then
        loc=$(cat /etc/locale.conf /etc/default/locale 2>/dev/null \
              | grep -m1 -E '^(LANG|LC_ALL)=' | cut -d= -f2 | tr -d '"')
    fi
    case "$loc" in
        zh*) echo "-zh-TW" ;;
        ja*) echo "-ja" ;;
        *)   echo "" ;;
    esac
}
LANG_SUFFIX=$(detect_lang_suffix)
HELP_URL="$DOCS_URL/troubleshooting${LANG_SUFFIX}.html"
OFFLINE_URL="$DOCS_URL/offline-install${LANG_SUFFIX}.html"
# An offline install that fails is best answered by the offline page.
[ "$OFFLINE" = true ] && HELP_URL="$OFFLINE_URL"

show_help_url() {
    echo
    echo -e "${YELLOW}----------------------------------------${NC}"
    case "$HELP_URL" in
        *zh-TW*)
            echo -e "${YELLOW} 安裝／升級疑難排解（含搜尋）：${NC}"
            echo -e "${YELLOW} $HELP_URL${NC}"
            echo -e " 找不到答案時，請附上上面的錯誤訊息開 issue。" ;;
        *-ja*)
            echo -e "${YELLOW} インストール／アップグレードのトラブルシューティング（検索可）：${NC}"
            echo -e "${YELLOW} $HELP_URL${NC}"
            echo -e " 該当がない場合は、上のエラーメッセージを添えて issue を作成してください。" ;;
        *)
            echo -e "${YELLOW} Install / upgrade troubleshooting (searchable):${NC}"
            echo -e "${YELLOW} $HELP_URL${NC}"
            echo -e " If it is not covered there, open an issue with the error above." ;;
    esac
    echo -e "${YELLOW}----------------------------------------${NC}"
    echo
}

on_error() {
    local code=$? line=$1
    echo
    case "$HELP_URL" in
        *zh-TW*) echo -e "${RED}安裝中斷：第 ${line} 行失敗（結束碼 ${code}）${NC}" ;;
        *-ja*)   echo -e "${RED}${line} 行目で失敗しました（終了コード ${code}）${NC}" ;;
        *)       echo -e "${RED}Failed at line ${line} (exit ${code})${NC}" ;;
    esac
    show_help_url
    exit "$code"
}
trap 'on_error $LINENO' ERR

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} jt-wazuh-mgr Installer${NC}"
echo -e "${GREEN}========================================${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    show_help_url
    exit 1
fi

# Offline: everything comes from the release directory this script sits in.
# Checked before anything is written, so a wrong directory changes nothing.
if [ "$OFFLINE" = true ]; then
    SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    if [ ! -f "$SRC_DIR/wazuh_agent_mgr.py" ] || [ ! -f "$SRC_DIR/lib/web_ui.py" ]; then
        echo -e "${RED}--offline: $SRC_DIR is not an extracted jt-wazuh-mgr release${NC}"
        echo "Extract the release archive and run the install.sh inside it."
        show_help_url
        exit 1
    fi
    if [ "$SRC_DIR" = "$(cd "$INSTALL_DIR" 2>/dev/null && pwd)" ]; then
        echo -e "${RED}--offline: run the install.sh of the new release, not one inside $INSTALL_DIR${NC}"
        show_help_url
        exit 1
    fi
    if [ -n "$WHEELS_DIR" ]; then
        if [ ! -d "$WHEELS_DIR" ]; then
            echo -e "${RED}--wheels: $WHEELS_DIR is not a directory${NC}"
            show_help_url
            exit 1
        fi
        WHEELS_DIR=$(cd "$WHEELS_DIR" && pwd)
    elif [ -d "$SRC_DIR/wheels" ]; then
        WHEELS_DIR="$SRC_DIR/wheels"
    fi
    echo -e "Offline install from ${YELLOW}$SRC_DIR${NC}"
fi

# Put one release file in place: from GitHub, or with --offline from the
# release directory.
fetch() {
    if [ "$OFFLINE" = true ]; then
        cp -f "$SRC_DIR/$1" "$2"
    else
        curl -fsSL "$BASE_URL/$1" -o "$2"
    fi
}

# Check if this is an update
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Existing installation detected. Updating...${NC}"
    UPDATE_MODE=true
else
    echo -e "${GREEN}Installing to $INSTALL_DIR ...${NC}"
    UPDATE_MODE=false
    mkdir -p "$INSTALL_DIR"
fi

# Create directories
mkdir -p "$INSTALL_DIR/lib"
mkdir -p "$INSTALL_DIR/images"

# Download main files
if [ "$OFFLINE" = true ]; then
    echo -e "${GREEN}Copying files...${NC}"
else
    echo -e "${GREEN}Downloading files...${NC}"
fi

fetch wazuh_agent_mgr.py "$INSTALL_DIR/wazuh_agent_mgr.py"
echo "  - wazuh_agent_mgr.py"

fetch create_api_user.py "$INSTALL_DIR/create_api_user.py"
echo "  - create_api_user.py"

fetch requirements.txt "$INSTALL_DIR/requirements.txt"
echo "  - requirements.txt"

# Download config.yaml only if it doesn't exist (don't overwrite user config)
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
    fetch config.yaml "$INSTALL_DIR/config.yaml"
    echo "  - config.yaml (new)"
else
    echo -e "  - config.yaml ${YELLOW}(skipped, keeping existing)${NC}"
fi

# Download lib files
LIB_FILES="__init__.py config.py wazuh_cli.py wazuh_api.py agent_ops.py group_ops.py node_ops.py stats.py output.py web_ui.py"

for file in $LIB_FILES; do
    fetch "lib/$file" "$INSTALL_DIR/lib/$file"
    echo "  - lib/$file"
done

# Download the Jason Tools rule packs (catalogue for the Rule Packs tab).
# This is only the catalogue in $INSTALL_DIR/packs; packs already installed on
# the manager are not touched -- they are updated from the Rule Packs tab.
echo -e "${GREEN}Rule packs...${NC}"
mkdir -p "$INSTALL_DIR/packs"
if fetch packs/INDEX "$INSTALL_DIR/packs/INDEX" 2>/dev/null; then
    while read -r pf; do
        [ -n "$pf" ] || continue
        mkdir -p "$INSTALL_DIR/$(dirname "$pf")"
        fetch "$pf" "$INSTALL_DIR/$pf" 2>/dev/null || true
    done < "$INSTALL_DIR/packs/INDEX"
    echo "  - packs/ ($(wc -l < "$INSTALL_DIR/packs/INDEX") files)"
else
    echo -e "  - packs ${YELLOW}(skipped, index unavailable)${NC}"
fi

# Logo and the icons the web UI links to (favicon, touch icon)
for img in logo-1.png icon.svg favicon.ico icon-16.png icon-32.png icon-48.png \
           icon-64.png icon-180.png icon-192.png icon-256.png icon-512.png; do
    fetch "images/$img" "$INSTALL_DIR/images/$img" 2>/dev/null || true
done
echo "  - images/"

# Download systemd service file
fetch jt-wazuh-mgr.service "$INSTALL_DIR/jt-wazuh-mgr.service"
echo "  - jt-wazuh-mgr.service"

# Download uninstall helper (enables one-line local removal)
fetch uninstall.sh "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true
chmod +x "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true
echo "  - uninstall.sh"

# Set permissions
chmod +x "$INSTALL_DIR/wazuh_agent_mgr.py"
chmod +x "$INSTALL_DIR/create_api_user.py"

# Install Python dependencies into $INSTALL_DIR/vendor, never the system Python.
#  - Ubuntu 24.04 and Debian 12 refuse "pip install" into the system (PEP 668),
#    so the plain form stopped the installer outright there.
#  - What pip put in /usr/local/lib/python3.10 is invisible to Python 3.12, so a
#    22.04 -> 24.04 upgrade left the service unable to start -- and only after
#    the next reboot, because the running process still had the old Python.
# "pip --target" sidesteps both, and wazuh_agent_mgr.py puts vendor/ on its own
# path. Built in a fresh directory and swapped in only once it imports, so a
# failed download leaves the working copy untouched.
# Offline without pip: a wheel is a zip, so unpack the ones that fit this
# interpreter (pure Python, or built for this CPython and CPU) into vendor.new.
# This is what pip --target does for these packages, minus the resolver; the
# import check after it is what proves the set is complete.
unpack_wheels() {
    python3 - "$1" "$2" <<'PY'
import os, platform, re, shutil, sys, zipfile
src, dest = sys.argv[1], sys.argv[2]
mine = sys.version_info[:2]
tag = 'cp%d%d' % mine
arch = platform.machine()

def cp(t):
    m = re.match(r'cp(\d)(\d+)$', t)
    return (int(m.group(1)), int(m.group(2))) if m else None

def fits(py, abi, plat):
    pys = py.split('.')
    if plat == 'any':
        return any(p.startswith('py3') or p == 'py2.py3' for p in pys) or tag in pys
    if 'linux' not in plat or arch not in plat:
        return False
    if abi == tag:
        return tag in pys
    if abi == 'abi3':
        return any(cp(p) and cp(p) <= mine for p in pys)
    return False

def vkey(v):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r'[.+-]', v))

best = {}
for name in sorted(os.listdir(src)):
    parts = name[:-4].split('-') if name.endswith('.whl') else []
    if len(parts) < 5 or not fits(parts[-3], parts[-2], parts[-1]):
        continue
    dist = re.sub(r'[-_.]+', '-', parts[0]).lower()
    if dist not in best or vkey(parts[1]) > vkey(best[dist][0]):
        best[dist] = (parts[1], name)
if not best:
    sys.exit('no wheel in %s fits Python %d.%d on %s' % (src, mine[0], mine[1], arch))
os.makedirs(dest)
for dist, (ver, name) in sorted(best.items()):
    with zipfile.ZipFile(os.path.join(src, name)) as zf:
        zf.extractall(dest)
# Library files a wheel keeps under <name>.data/purelib|platlib belong at the top.
for d in os.listdir(dest):
    if d.endswith('.data'):
        for sub in ('purelib', 'platlib'):
            lib = os.path.join(dest, d, sub)
            if os.path.isdir(lib):
                for item in os.listdir(lib):
                    shutil.move(os.path.join(lib, item), os.path.join(dest, item))
print('  - unpacked %d wheels from %s' % (len(best), src))
PY
}

install_python_deps() {
    local py_ver
    py_ver=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
    rm -rf "$INSTALL_DIR/vendor.new"
    if [ "$OFFLINE" = true ]; then
        if [ -z "$WHEELS_DIR" ]; then
            # An upgrade whose requirements.txt did not change needs no wheels.
            if PYTHONPATH="$INSTALL_DIR/vendor" python3 -c 'import flask, yaml, requests, rich, tabulate' 2>/dev/null; then
                echo "  - no wheels/ directory; the installed dependencies still import, keeping them"
                return 0
            fi
            echo -e "${RED}No wheels/ directory beside install.sh and no working dependencies in $INSTALL_DIR/vendor.${NC}"
            echo "Download the wheels for Python $py_ver on a connected machine (see the page below),"
            echo "then run again with --wheels DIR."
            show_help_url
            exit 1
        fi
        if python3 -m pip --version >/dev/null 2>&1; then
            if ! PIP_ROOT_USER_ACTION=ignore python3 -m pip install -q --disable-pip-version-check \
                    --no-warn-script-location --no-index --find-links "$WHEELS_DIR" \
                    --target "$INSTALL_DIR/vendor.new" -r "$INSTALL_DIR/requirements.txt"; then
                echo -e "${RED}The wheels in $WHEELS_DIR do not cover requirements.txt for Python $py_ver.${NC}"
                show_help_url
                exit 1
            fi
        else
            echo "  - pip not found, unpacking the wheels directly"
            if ! unpack_wheels "$WHEELS_DIR" "$INSTALL_DIR/vendor.new"; then
                show_help_url
                exit 1
            fi
        fi
        if ! PYTHONPATH="$INSTALL_DIR/vendor.new" python3 -c 'import flask, yaml, requests, rich, tabulate'; then
            rm -rf "$INSTALL_DIR/vendor.new"
            echo -e "${RED}The wheels in $WHEELS_DIR do not import on Python $py_ver (missing, or built for another Python version).${NC}"
            show_help_url
            exit 1
        fi
    else
        if ! python3 -m pip --version >/dev/null 2>&1; then
            echo "  - pip not found, installing python3-pip"
            if command -v apt-get >/dev/null 2>&1; then
                apt-get install -y -qq python3-pip >/dev/null || { apt-get update -qq && apt-get install -y -qq python3-pip >/dev/null; }
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y -q python3-pip
            elif command -v yum >/dev/null 2>&1; then
                yum install -y -q python3-pip
            fi
        fi
        PIP_ROOT_USER_ACTION=ignore python3 -m pip install -q --disable-pip-version-check \
            --no-warn-script-location --target "$INSTALL_DIR/vendor.new" \
            -r "$INSTALL_DIR/requirements.txt"
        PYTHONPATH="$INSTALL_DIR/vendor.new" python3 -c 'import flask, yaml, requests, rich, tabulate'
    fi
    rm -rf "$INSTALL_DIR/vendor.old"
    if [ -d "$INSTALL_DIR/vendor" ]; then
        mv "$INSTALL_DIR/vendor" "$INSTALL_DIR/vendor.old"
    fi
    mv "$INSTALL_DIR/vendor.new" "$INSTALL_DIR/vendor"
    rm -rf "$INSTALL_DIR/vendor.old"
    echo "  - $(ls -d "$INSTALL_DIR"/vendor/*.dist-info | wc -l) packages in $INSTALL_DIR/vendor (Python $py_ver)"
}

echo
echo -e "${GREEN}Installing Python dependencies...${NC}"
install_python_deps

# Install and enable systemd service
echo
echo -e "${GREEN}Setting up systemd service...${NC}"
cp "$INSTALL_DIR/jt-wazuh-mgr.service" "$SERVICE_FILE"
systemctl daemon-reload

if [ "$UPDATE_MODE" = true ]; then
    # Update: restart if already running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl restart "$SERVICE_NAME"
        echo -e "  - Service restarted"
    else
        systemctl enable "$SERVICE_NAME"
        systemctl start "$SERVICE_NAME"
        echo -e "  - Service enabled and started"
    fi
else
    # Fresh install: enable and start
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    echo -e "  - Service enabled and started"
fi

# systemctl start returns 0 as soon as the unit is launched, so a service that
# starts and then dies -- a missing dependency, a port already taken -- reports
# success here. Give it a moment and look again.
sleep 2
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    echo
    case "$HELP_URL" in
        *zh-TW*) echo -e "${RED}服務已安裝但沒有執行中。最後幾行記錄：${NC}" ;;
        *-ja*)   echo -e "${RED}サービスはインストールされましたが起動していません。直近のログ：${NC}" ;;
        *)       echo -e "${RED}The service was installed but is not running. Last log lines:${NC}" ;;
    esac
    journalctl -u "$SERVICE_NAME" -n 15 --no-pager 2>/dev/null || true
    show_help_url
    exit 1
fi

# Get version
VERSION=$(grep -o '__version__ = "[^"]*"' "$INSTALL_DIR/lib/__init__.py" | cut -d'"' -f2)

echo
echo -e "${GREEN}========================================${NC}"
if [ "$UPDATE_MODE" = true ]; then
    echo -e "${GREEN} Update complete! (v$VERSION)${NC}"
else
    echo -e "${GREEN} Installation complete! (v$VERSION)${NC}"
fi
echo -e "${GREEN}========================================${NC}"
echo
echo -e "Service status: ${YELLOW}systemctl status $SERVICE_NAME${NC}"
echo -e "View logs:      ${YELLOW}journalctl -u $SERVICE_NAME -f${NC}"
echo
echo -e "Open Web UI:    ${YELLOW}https://<this-server-ip>:5000${NC}"
echo
if [ "$OFFLINE" = true ]; then
    echo -e "Upgrade:        ${YELLOW}sudo bash <new release dir>/install.sh --offline${NC}"
    echo -e "Offline guide:  ${YELLOW}$OFFLINE_URL${NC}"
else
    echo -e "Upgrade:        ${YELLOW}curl -fsSL $BASE_URL/install.sh | sudo bash${NC}"
fi
echo -e "Uninstall:      ${YELLOW}sudo bash $INSTALL_DIR/uninstall.sh${NC}"
echo
echo -e "Troubleshooting: ${YELLOW}$DOCS_URL/troubleshooting${LANG_SUFFIX}.html${NC}"
echo
