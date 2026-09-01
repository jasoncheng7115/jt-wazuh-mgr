# JT Wazuh Manager v1.6.0

[English](README.md) | [繁體中文](README-zh-TW.md)

A powerful web-based management tool for Wazuh agents in cluster environments.

> **Purpose**: This tool is designed to supplement the Wazuh Dashboard by providing missing or inconvenient management features. It is **NOT** intended to replace the Wazuh Dashboard, but to complement it.

> **Recommended**: Use the Web UI as the primary interface — it's the main feature of this tool with full functionality.

![Version](https://img.shields.io/badge/version-1.6.16-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Apache--2.0-orange)
![Languages](https://img.shields.io/badge/UI-English%20%7C%20%E7%B9%81%E9%AB%94%E4%B8%AD%E6%96%87-blueviolet)

🌐 **Project site:** https://jasoncheng7115.github.io/jt-wazuh-mgr/

---

## ⚡ One-line Install / Upgrade / Uninstall

Run as **root** on your Wazuh Manager (Master node in cluster mode):

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/install.sh | sudo bash

# Upgrade (re-run the installer; your config.yaml is preserved)
curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/install.sh | sudo bash

# Uninstall
curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/uninstall.sh | sudo bash
```

The installer downloads the app to `/opt/jt-wazuh-mgr`, installs Python dependencies, and registers + starts a `systemd` service (`jt-wazuh-mgr`). After installation, open **https://YOUR_WAZUH_MANAGER_IP:5000** and log in with your Wazuh API credentials.

> Already installed? You can also upgrade/uninstall locally:
> ```bash
> curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/install.sh | sudo bash   # upgrade
> sudo bash /opt/jt-wazuh-mgr/uninstall.sh                                                                # uninstall
> ```

---

## ✨ What's New

### 1.6.1

- **New rule pack: Zenarmor (OPNsense)** — decoder plus severity-graded rules for Zenarmor NGFW events, where an *unblocked* malicious connection outranks a blocked one. No catch-all rule, so ordinary traffic never floods the console.
- Packs can now ship **decoders** alongside rules and CDB lists.

### 1.6.0

- **New Rule Packs tab**: a catalogue of installable detection rule series, run as a package manager — conflict detection, backup, ruleset validation and **full rollback on any failure**. Removal restores what it replaced and refuses to discard files you edited.

### 1.5.2

- **Node config drift detection**: `ossec.conf` is exactly what a Wazuh cluster does *not* sync — this compares it across nodes and shows you the difference.

### 1.5.1

- **Cluster-wide ruleset reload**: pushing rules to a worker is not enough, because the cluster does not reload the worker's analysisd. This reloads every node.

### 1.5.0

- **New Inventory tab**: search packages, open ports, processes, services, users, hotfixes and more *across every agent at once* — the reverse of the Dashboard's one-agent-at-a-time view.
- **Rules tab is now a ruleset workbench**: Hierarchy, All Rules, **Decoders**, **CDB Lists** and **Log Test** (paste a log line, see which rule and decoder match).
- **Safer config editing**: validate `ossec.conf` before restarting, and reload the ruleset without a restart.
- **Custom WPK upgrades** for managers with no internet access.
- **Active Response** on selected agents, **agent pre-registration** with keys, **running-config** and **agent key** viewers, per-node **daemon health**, and group **file browser**.

### 1.4.3

- Security hardening (CSP and other response headers, SRI on CDN assets, login CSRF token), verified with an OWASP ZAP baseline scan.
- Rules tab: keyword search across the full XML of every rule; the hierarchy view scrolls again.
- Agents tab: an Exit Selection button.
- Much wider zh-TW coverage, and the project now ships a test suite (`tests/`).

### 1.4.2

- The Rules tab now reports rule files it could not parse, instead of silently omitting them.

### 1.4.1 — maintenance

- Verified against **Wazuh 4.14.7**; hardened request validation and fixed a rule-hierarchy crash.

### 1.4.0

- **Bilingual UI (English / 繁體中文)** with a one-click language toggle in the header. Your choice is remembered in the browser.
- Project renamed and published as a standalone repository: **`jasoncheng7115/jt-wazuh-mgr`**.
- One-line **install / upgrade / uninstall** workflow.
- Now licensed under **Apache-2.0**.

See the full [CHANGELOG](CHANGELOG.md) for details.

## Features

### Language
- **English / Traditional Chinese (繁體中文)** switchable from the header (EN ⇄ 中文); the preference is saved per browser.

### Agent Management
- View all agents with real-time status
- Advanced filtering (status, group, node, OS, version, IP, name, sync)
- **Convenient multi-select** for batch operations
- **Distribution bar**: visual statistics bar showing agent distribution by status, OS, version, group, node, or sync status
  - Click on segments to filter agents
  - Animated transitions when switching views
- **Auto-refresh stats**: top statistics refresh every 10 seconds with slide animation
- **Group operations**: add to / remove from group, merge into another group, keep in a specific group only, rename group, **import from CSV** (with preview), **export to CSV**
- Batch operations: restart, reconnect, delete, upgrade
- **Move to Node** (planned): migrate agents to a specific node via HAProxy integration (under development)
- Health check and duplicate detection
- **Queue DB size check**: monitor agent queue database usage with batch clean support
- Agent upgrade with real-time progress tracking

### Cluster Support
- Full master/worker cluster support
- Node service status monitoring
- **Edit ossec.conf** for master and worker nodes
- **Restart services** on any node
- **Download cluster.key** from the master node
- **WPK file management**: upload and delete WPK upgrade files
- **Sync status checking** between master and workers (Rules, Decoders, Groups, Keys, Lists, SCA), including a view of files that differ between nodes
- SSH remote management for worker nodes
- **Email Alerts management**: form-based management of `<email_alerts>` rules in `ossec.conf` — add/edit/delete without manual XML editing, one-click sync to all worker nodes, auto-backup before every change

### Statistics & Reports
- Statistics by status, group, node, OS, version, network segment
- Sortable columns in all statistics tables
- Export to JSON/CSV

### Rules Viewer
- **Browse all rules** in a sortable, searchable, paginated table; filter by level range, file, and type (Custom/Built-in)
- **Rule hierarchy visualization** as a collapsible tree (parent/child via `if_sid`, `if_matched_sid`)
- Click any Rule ID to jump to its hierarchy view; expand to view full rule XML with syntax highlighting

### Rule Packs
- **Catalogue of detection rule series** maintained by Jason Tools, installable from the UI
- Each pack bundles rules, decoders and CDB lists behind a manifest; open one to see the files it installs, where they go, and which rule IDs it claims
- Install is guarded: **rule-ID conflict detection**, backup of anything overwritten, `wazuh-analysisd -t` validation, and **full rollback if any step fails**
- Removal restores replaced files and **refuses to discard files you edited** after installing
- Ships with: portable-executable detection (Windows/Linux/macOS), IP threat intelligence, malware hash matching, Zimbra detection, Zenarmor (OPNsense), AdGuard Home, and fail2ban

### Security
- Input validation for all parameters; command-injection and path-traversal protection
- Secure file-upload handling
- **Complete logging & audit** of operations
- **API user management**: create, modify, and manage Wazuh API users and roles
- Brute-force protection (IP lockout: 3 failed logins = 30-minute lockout)
- See [SECURITY.md](SECURITY.md) for the security policy and hardening notes
- See [TEST-PLAN.md](TEST-PLAN.md) for what is verified before a release, and what is not

## Screenshots

| | |
|---|---|
| Login | ![Login](screenshots/1_login.png) |
| Agent List | ![Agents](screenshots/2_agents.png) |
| Agent Actions & Queue DB | ![Agent Actions](screenshots/3_selected_action_queuedb.png) |
| Groups | ![Groups](screenshots/4_groups.png) |
| Nodes | ![Nodes](screenshots/5_nodes.png) |
| WPK Files Management | ![WPK Files](screenshots/6_nodes_wpkfiles.png) |
| Rules Viewer | ![Rules](screenshots/7_rule.png) |
| API Users | ![API Users](screenshots/8_apiusers.png) |
| Logs Viewer | ![Logs](screenshots/9_logs.png) |
| Edit ossec.conf | ![Edit Config](screenshots/10_node_editconfig.png) |
| Agent Upgrade | ![Upgrade 1](screenshots/11_upgrade_agent_1.png) ![Upgrade 2](screenshots/11.5_upgrade_agent_2.png) ![Upgrade 3](screenshots/12_upgrade_agent_3.png) |
| Agent Detail | ![Agent Detail](screenshots/13_agent_detail.png) |
| Inventory (search across every agent) | ![Inventory](screenshots/14_inventory.png) |
| Rule Packs | ![Rule Packs](screenshots/15_rule_packs.png) |
| Rule Pack Detail | ![Rule Pack Detail](screenshots/16_rule_pack_detail.png) |
| Rules by File Name | ![Rules by file](screenshots/17_rules_by_file.png) |
| Statistics | ![Statistics](screenshots/18_statistics.png) |

## Quick Start

### Requirements
- Python 3.8+
- Wazuh Manager 4.x
- **Must be installed on the Wazuh Manager** (for cluster mode, install on the Master node)

### Install

Use the [one-line installer](#-one-line-install--upgrade--uninstall) above, or run manually after cloning:

```bash
./wazuh_agent_mgr.py --web --ssl-auto
```

Open **https://YOUR_WAZUH_MANAGER_IP:5000** and log in with your Wazuh API credentials.

> **Note**: Use the `wazuh` or `wazuh-wui` account. The password can be found in `wazuh-install-files.tar` (created during installation) or in your installation records.

### Other Options

```bash
# Custom port
./wazuh_agent_mgr.py --web --port 8443 --ssl-auto

# Custom SSL certificate
./wazuh_agent_mgr.py --web --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem
```

### systemd Service

The installer registers and starts a systemd service automatically. Management commands:

```bash
systemctl status jt-wazuh-mgr       # Check status
systemctl restart jt-wazuh-mgr      # Restart service
journalctl -u jt-wazuh-mgr -f       # View logs
```

## CLI Usage

```bash
# List all agents
./wazuh_agent_mgr.py agent list

# Filter agents
./wazuh_agent_mgr.py agent list --status=Active --group=production

# Quick status queries
./wazuh_agent_mgr.py agent disconnected
./wazuh_agent_mgr.py agent pending

# Group management
./wazuh_agent_mgr.py group list
./wazuh_agent_mgr.py group add-agent webservers 001 002 003

# Node management
./wazuh_agent_mgr.py node list
./wazuh_agent_mgr.py node reconnect 001 002

# Statistics
./wazuh_agent_mgr.py stats report
```

### Output Formats

Supports three output formats: `table` (default), `json`, `csv`.

```bash
./wazuh_agent_mgr.py agent list --format=json
./wazuh_agent_mgr.py agent list --format=csv > agents.csv
./wazuh_agent_mgr.py stats report --format=json > report.json
```

### Dry-Run Mode

All write operations support `--dry-run` to preview actions without executing:

```bash
./wazuh_agent_mgr.py agent delete 001 --dry-run
# Output: [DRY-RUN] Would execute: /var/ossec/bin/manage_agents -r 001
```

## Configuration

`config.yaml` (a template is included; **no credentials are required for Web UI mode**):

```yaml
wazuh_path: /var/ossec

# API settings
# Web UI mode: username/password NOT required (users log in via the browser)
# CLI mode: username/password REQUIRED for commands like ./wazuh_agent_mgr.py agent list
api:
  enabled: false           # set to true for CLI mode
  host: localhost
  port: 55000
  username: wazuh          # only for CLI mode
  password: ""             # only for CLI mode, see wazuh-install-files.tar
  verify_ssl: false

# Web UI settings
web:
  session_timeout: 120     # minutes

# Optional: SSH for remote worker node management
# ssh:
#   enabled: true
#   key_file: /root/.ssh/wazuh_cluster_key
#   nodes:
#     worker01:
#       host: 192.168.1.100
#       port: 22
#       user: root
```

### Web UI vs CLI Configuration

| Setting | Web UI | CLI |
|---------|--------|-----|
| `api.enabled` | Not required | `true` |
| `api.username` | Not required (login via browser) | Required |
| `api.password` | Not required (login via browser) | Required |
| `ssh.*` | Optional (for remote node management) | Optional |

## Internationalization (i18n)

The UI ships in English and translates to Traditional Chinese entirely on the
client side. UI strings live in `lib/i18n_engine.js`, which is embedded into
`lib/web_ui.py` by `tools/build_i18n.py`. To extend or edit translations:

```bash
# edit lib/i18n_engine.js, then re-embed into web_ui.py
python3 tools/build_i18n.py
```

## Tech Stack

- **Backend**: Python, Flask
- **Frontend**: Vanilla JavaScript, CSS (no framework)
- **Wazuh Integration**: CLI commands + REST API

## Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The author is not responsible for any damages or losses arising from the use of this software. Use at your own risk.

Before performing any operations (especially delete, restart, or upgrade), it is strongly recommended to:
- Use `--dry-run` mode to preview actions
- Back up important configurations
- Test in a non-production environment first

## License

Licensed under the [Apache License 2.0](LICENSE).

## Author

Jason Cheng (Jason Tools)
