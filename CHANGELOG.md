# Changelog

All notable changes to **JT Wazuh Manager** are documented here.

[English](CHANGELOG.md) | [繁體中文](CHANGELOG-zh-TW.md)

## v1.4.0 (2026-06-11)
- **Bilingual UI (English / 繁體中文)**: one-click language toggle in the header; the choice is remembered per browser. Translations are applied entirely on the client side (text nodes + `placeholder`/`title`), with a `MutationObserver` keeping dynamically-rendered content translated. UI strings live in `lib/i18n_engine.js` and are embedded into `lib/web_ui.py` by `tools/build_i18n.py`.
- **Standalone repository**: project renamed from `jt_wazuh_agent_mgr` to **`jt-wazuh-mgr`** and split out into its own repo `jasoncheng7115/jt-wazuh-mgr`. Install path is now `/opt/jt-wazuh-mgr` and the systemd service is `jt-wazuh-mgr`.
- **One-line install / upgrade / uninstall**: hardened `install.sh` (idempotent update mode) plus a new `uninstall.sh` for clean removal.
- **License**: relicensed under **Apache-2.0**.

## v1.3.136 (2026-03-18)
- **Browse All Rules**: new "All Rules" mode in the Rules tab
  - Sortable, paginated table listing all rules (built-in + custom)
  - Search across Rule ID, level, description, file, and groups
  - Filters: level range (min/max), file, type (Custom/Built-in)
  - Click any Rule ID to jump to hierarchy view
  - New API endpoint `GET /api/rules`

## v1.3.135 (2026-02-25)
- **Email Alerts save validation**: validates rule IDs, groups, and levels exist in the Wazuh ruleset before saving
- **Multi-ossec_config support**: fixed email alerts sync for configs with multiple `<ossec_config>` sections (common on worker nodes)

## v1.3.134 (2026-02-24)
- **Email Alerts visual management**: form-based management of `<email_alerts>` rules in ossec.conf on the master node
- **Sync to all workers**: one-click sync of email alerts configuration to all worker nodes (with auto-backup)
- Only modifies `<email_alerts>` blocks — other config content, comments and formatting are preserved

## v1.3.133 (2026-02-23)
- **Extended web session**: session timeout now defaults to 2 hours (configurable via `web.session_timeout`)
- **Auto JWT token renewal**: automatically re-authenticates before token expiry — no re-login needed during a session
- **SSH Setup Guide in Settings**: quick access to the SSH configuration tutorial

## v1.3.131 (2026-02-22)
- **Batch clean Queue DB**: select agents and batch-delete queue DB files with automatic agent restart
- **Precise node targeting**: only connects to nodes that actually have queue DB files
- **Detailed results display**: modal shows per-agent, per-node deletion results and restart status
- **Installer improvements**: auto-install systemd service and start on install, auto-restart on update, self-updating `install.sh`

## v1.3.10x (2026-01-04)
- **Distribution bar**: new visual statistics bar above the agent list (status, OS, version, group, node, sync status); click segments to quick-filter; left-to-right and slide-in animations
- **Auto-refresh stats**: top statistics auto-refresh every 10 seconds
- Various distribution-bar styling, alignment and animation fixes

## v1.3.3x (2026-01-02)
- **New Rules tab**: rule hierarchy viewer — search by Rule ID, parent/child relationships (`if_sid`, `if_matched_sid`), collapsible tree, XML syntax highlighting, Expand/Collapse All
- Supports built-in (`/var/ossec/ruleset/rules/`) and custom rules (`/var/ossec/etc/rules/`)

## v1.3.2x (2025-01-01)
- **Security hardening**: input validators (`validate_node_name`, `validate_agent_id`, `validate_group_name`, `validate_username`), path whitelist (`validate_path`, `ALLOWED_PATHS`), shell-arg escaping (`safe_shell_arg` / `shlex.quote`), log sanitization, `secure_filename()` for uploads, `ALLOWED_SYNC_ITEMS` whitelist against path traversal
- **Sortable statistics columns** and semantic version sorting
- **Sync Status** styling and loading indicators; **Favicon** + `/images/` static route

## v1.2.x
- Agent upgrade feature, upgrade files management, and upgrade progress tracking

## v1.1.x (2024-12-31)
- **Agent table column customization** (show/hide columns, saved in localStorage)
- **Queue DB multi-node support** via SSH; node download/restart over SSH
- **Responsive width**; unified 24-hour time format; sync filter fixes

## v1.0.8x – v1.0.9x (2024-12-31)
- SSH remote management for worker nodes (read/save ossec.conf, restart services, download cluster.key)
- SSH Setup Guide with copy-to-clipboard; Settings modal (API connection, SSH status, About)
- Numerous fixes to node detection, version parsing, and JavaScript regex escaping

> For the complete, fine-grained history prior to 1.4.0, see the project's earlier release notes.
