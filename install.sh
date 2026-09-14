#!/bin/bash
#
# JT Wazuh Manager - Installation Script
# https://github.com/jasoncheng7115/jt-wazuh-mgr
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

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Point the reader at the troubleshooting page in the language their system is
# set to, defaulting to English. Under "curl ... | sudo bash" the environment is
# usually reset, so the shell variables are checked first and the system-wide
# locale file second -- that file is what survives sudo.
detect_help_url() {
    local loc="${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}"
    if [ -z "$loc" ] || [ "$loc" = "C" ] || [ "$loc" = "POSIX" ]; then
        loc=$(cat /etc/locale.conf /etc/default/locale 2>/dev/null \
              | grep -m1 -E '^(LANG|LC_ALL)=' | cut -d= -f2 | tr -d '"')
    fi
    case "$loc" in
        zh*) echo "$DOCS_URL/troubleshooting-zh-TW.html" ;;
        *)   echo "$DOCS_URL/troubleshooting.html" ;;
    esac
}
HELP_URL=$(detect_help_url)

show_help_url() {
    echo
    echo -e "${YELLOW}----------------------------------------${NC}"
    case "$HELP_URL" in
        *zh-TW*)
            echo -e "${YELLOW} 安裝／升級疑難排解（含搜尋）：${NC}"
            echo -e "${YELLOW} $HELP_URL${NC}"
            echo -e " 找不到答案時，請附上上面的錯誤訊息開 issue。" ;;
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
        *)       echo -e "${RED}Failed at line ${line} (exit ${code})${NC}" ;;
    esac
    show_help_url
    exit "$code"
}
trap 'on_error $LINENO' ERR

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} JT Wazuh Manager Installer${NC}"
echo -e "${GREEN}========================================${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    show_help_url
    exit 1
fi

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
echo -e "${GREEN}Downloading files...${NC}"

curl -fsSL "$BASE_URL/wazuh_agent_mgr.py" -o "$INSTALL_DIR/wazuh_agent_mgr.py"
echo "  - wazuh_agent_mgr.py"

curl -fsSL "$BASE_URL/create_api_user.py" -o "$INSTALL_DIR/create_api_user.py"
echo "  - create_api_user.py"

curl -fsSL "$BASE_URL/requirements.txt" -o "$INSTALL_DIR/requirements.txt"
echo "  - requirements.txt"

# Download config.yaml only if it doesn't exist (don't overwrite user config)
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
    curl -fsSL "$BASE_URL/config.yaml" -o "$INSTALL_DIR/config.yaml"
    echo "  - config.yaml (new)"
else
    echo -e "  - config.yaml ${YELLOW}(skipped, keeping existing)${NC}"
fi

# Download lib files
LIB_FILES="__init__.py config.py wazuh_cli.py wazuh_api.py agent_ops.py group_ops.py node_ops.py stats.py output.py web_ui.py"

for file in $LIB_FILES; do
    curl -fsSL "$BASE_URL/lib/$file" -o "$INSTALL_DIR/lib/$file"
    echo "  - lib/$file"
done

# Download the Jason Tools rule packs (catalogue for the Rule Packs tab)
echo -e "${GREEN}Downloading rule packs...${NC}"
mkdir -p "$INSTALL_DIR/packs"
if curl -fsSL "$BASE_URL/packs/INDEX" -o "$INSTALL_DIR/packs/INDEX" 2>/dev/null; then
    while read -r pf; do
        [ -n "$pf" ] || continue
        mkdir -p "$INSTALL_DIR/$(dirname "$pf")"
        curl -fsSL "$BASE_URL/$pf" -o "$INSTALL_DIR/$pf" 2>/dev/null || true
    done < "$INSTALL_DIR/packs/INDEX"
    echo "  - packs/ ($(wc -l < "$INSTALL_DIR/packs/INDEX") files)"
else
    echo -e "  - packs ${YELLOW}(skipped, index unavailable)${NC}"
fi

# Download logo / favicon
curl -fsSL "$BASE_URL/images/logo-1.png" -o "$INSTALL_DIR/images/logo-1.png" 2>/dev/null || true
echo "  - images/logo-1.png"

# Download systemd service file
curl -fsSL "$BASE_URL/jt-wazuh-mgr.service" -o "$INSTALL_DIR/jt-wazuh-mgr.service"
echo "  - jt-wazuh-mgr.service"

# Download uninstall helper (enables one-line local removal)
curl -fsSL "$BASE_URL/uninstall.sh" -o "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true
chmod +x "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true
echo "  - uninstall.sh"

# Set permissions
chmod +x "$INSTALL_DIR/wazuh_agent_mgr.py"
chmod +x "$INSTALL_DIR/create_api_user.py"

# Install Python dependencies
echo
echo -e "${GREEN}Installing Python dependencies...${NC}"
pip install -q -r "$INSTALL_DIR/requirements.txt"

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
echo -e "Upgrade:        ${YELLOW}curl -fsSL $BASE_URL/install.sh | sudo bash${NC}"
echo -e "Uninstall:      ${YELLOW}sudo bash $INSTALL_DIR/uninstall.sh${NC}"
echo
echo -e "Troubleshooting: ${YELLOW}$HELP_URL${NC}"
echo
