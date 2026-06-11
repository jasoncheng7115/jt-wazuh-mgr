#!/bin/bash
#
# JT Wazuh Agent Manager - Uninstall Script
# https://github.com/jasoncheng7115/jt-wazuh-mgr
#
# One-line uninstall:
#   curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/uninstall.sh | sudo bash
#

set -e

INSTALL_DIR="/opt/jt-wazuh-mgr"
SERVICE_NAME="jt-wazuh-mgr"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} JT Wazuh Agent Manager Uninstaller${NC}"
echo -e "${GREEN}========================================${NC}"
echo

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Stop and disable service
if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
    echo -e "${GREEN}Stopping service...${NC}"
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    echo "  - service stopped and disabled"
fi

# Remove service file
if [ -f "$SERVICE_FILE" ]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    echo "  - removed $SERVICE_FILE"
fi

# Preserve config.yaml as a backup before removing the install dir
if [ -f "$INSTALL_DIR/config.yaml" ]; then
    BACKUP="/root/jt-wazuh-mgr-config.yaml.bak"
    cp -f "$INSTALL_DIR/config.yaml" "$BACKUP" 2>/dev/null || true
    echo -e "  - ${YELLOW}config.yaml backed up to $BACKUP${NC}"
fi

# Remove install directory
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo "  - removed $INSTALL_DIR"
fi

echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Uninstall complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo
echo -e "${YELLOW}Note:${NC} Python dependencies installed via pip were left in place."
echo -e "      Wazuh Manager itself was NOT touched."
echo
