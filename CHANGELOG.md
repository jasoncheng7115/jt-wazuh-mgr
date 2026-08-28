# Changelog

All notable changes to **JT Wazuh Manager** are documented here.

[English](CHANGELOG.md) | [繁體中文](CHANGELOG-zh-TW.md)

## v1.5.1 (2026-08-29)

- **Reload the ruleset across the whole cluster from the Rules tab.** Editing rules
  on the master does not make them active on the workers: the cluster syncs the
  files, but each node's `analysisd` keeps its own in-memory ruleset until it is
  told to reload. A rule fix can therefore look live while the node that actually
  processes those agents still runs the old rules — which is exactly what happened
  on a production cluster: a corrected rule kept firing false positives for four
  hours because only the master had reloaded.
  `POST /api/cluster/reload-ruleset` now reloads every node in one call
  (`PUT /cluster/analysisd/reload` with no `nodes_list`), falling back to
  `PUT /manager/analysisd/reload` on a standalone manager, and reports the result
  and any ruleset warnings per node. Verified against `analysisd` directly: it is a
  hot reload, the process is not restarted.

## v1.5.0 (2026-08-26)

Eleven capabilities the Wazuh Dashboard either lacks or buries, chosen by auditing
all 150 endpoints of the 4.14.7 API against what this tool already used.

**New Inventory tab**
- `GET /api/inventory/search` queries one syscollector category across every agent
  in parallel and returns a single table: packages, open ports, processes,
  services, local users, hotfixes, network interfaces, OS, browser extensions.
  Answers "which agents have this package / this port open", which the Dashboard's
  per-agent inventory cannot. Results export to CSV.

**Rules tab becomes a ruleset workbench**
- **Log Test** — paste a log line and see the rule and decoder it matches, the
  extracted fields and analysisd's messages (`PUT /logtest`).
- **Decoders** — browse and search decoders, view their XML.
- **CDB Lists** — list, create, edit and delete CDB lists.

**Safer configuration changes**
- **Validate** `ossec.conf` before restarting a node.
- **Reload Ruleset** applies rule changes without restarting the manager.

**Agents**
- **Custom WPK upgrade** — upgrade from a WPK already on the manager, the only
  path that works on an air-gapped install.
- **Active Response** — run a command on the selected agents.
- **Register Agents** — pre-register by name and get IDs and keys back.
- **Running Config** — the configuration an agent actually applied, so a group
  `agent.conf` change can be confirmed on the agent itself.
- **Agent Key** — retrieve an enrollment key for re-registering a broken agent.

**Nodes / Groups**
- **Health** — analysisd / remoted / wazuh-db counters per node.
- **Files** — browse and view every file in a group directory, not just agent.conf.

**Also**
- 127 new zh-TW dictionary entries and 57 new patterns covering all of the above.
- The test suite grows to 85 tests.
- OWASP ZAP baseline unchanged from 1.4.3: 0 failures, 8 warnings, 59 passes.

## v1.4.3 (2026-08-26)

**Security hardening** (verified with an OWASP ZAP baseline scan: 12 warnings -> 8,
0 failures; the remaining Mediums are the inherent `unsafe-inline` CSP entries):

- **Security response headers** on every response: `Content-Security-Policy`,
  `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`,
  `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Resource-Policy`, `Cache-Control: no-store`, and HSTS when
  running over HTTPS.
- **Subresource Integrity** for the CodeMirror assets loaded from cdnjs. They were
  fetched with no integrity check, so a compromised CDN response would have run
  arbitrary JavaScript inside a console that holds a Wazuh API token.
- **CSRF token on the login form.** The JSON API is covered by `SameSite=Lax`, but
  the login form itself had no token.
- **The WSGI server no longer advertises its version** in the `Server` header.

**Rules tab**

- **New: keyword search across the full XML of every rule** (`GET /api/rules/search`),
  with multiple space-separated keywords and an all/any selector. The table filter
  only ever saw id/level/description/file/groups, so terms inside `<field>`,
  `<regex>`, `<decoded_as>` or `<options>` were unfindable. Because it greps raw
  text it also finds rules in files the XML parser rejects.
- **Fixed: the hierarchy view could not scroll.** It had no sizing of its own, so
  `.rules-content`'s `flex:1; overflow:auto` never applied and a tall rule tree was
  clipped by the panel with no scrollbar.

**Agents tab**

- **New: an Exit Selection button** next to the selection count, to clear a batch
  selection without unticking each row.

**Translation**

- Much wider zh-TW coverage, found by scanning every user-visible string in the
  template against the dictionary: the whole agent upgrade flow (dialog, options,
  progress table, status values, summary counts), the confirmation prompts, and
  modal titles that carry a value. 40+ dictionary entries and 38 regex patterns
  added, including "Found N related rules".
- The "Upgrade to manager version" label was restructured so its text node no
  longer includes a trailing `(`, which had made it untranslatable.

**Tests**

- **The project now has a test suite** (`tests/test_web_ui.py`, 46 tests): run it with
  `python3 -m unittest discover -s tests`. It runs fully offline -- the Wazuh API is
  mocked and the ruleset is faked -- and covers authentication, request validation,
  the rule endpoints, security headers, CSRF, reflected-XSS escaping, SRI, the
  version comparator, and translation consistency.

## v1.4.2 (2026-08-24)

- **Rules tab now reports unparseable rule files.** `parse_rule_file()` swallowed
  XML errors, so rules in a malformed file were silently missing from the tab with
  no indication anything was wrong. `GET /api/rules` now returns a `parse_errors`
  list, and the tab shows a warning linking to a modal naming each file and the
  parser's reason. (Wazuh 4.14.7 itself ships one such file:
  `0910-ms-exchange-proxylogon_rules.xml`, whose `pcre2` regex contains `\<` and
  `\>`; ElementTree rejects it at line 57, hiding its rules.)
  Parse failures are also logged at WARNING instead of DEBUG.

## v1.4.1 (2026-08-24)

Maintenance release. Verified against **Wazuh 4.14.7** — no API or CLI changes were
required; every endpoint and path the tool uses is still present and non-deprecated.

- **Fixed: rule hierarchy could crash the Rules tab.** `find_children()` recursed
  without a depth limit, so a long `if_group` / `if_sid` chain raised
  `RecursionError: maximum recursion depth exceeded` and the request failed with a
  500. Descent is now capped (and the truncation is logged).
- **Fixed: requests without a JSON body returned 500.** `request.get_json()` raises
  a werkzeug `BadRequest` when the caller sends no body or a non-JSON
  `Content-Type`; the generic handler in each route reported that as a server
  error. 20 routes now use `get_json(silent=True)`.
- **Added: input validation on bulk agent actions.** `restart`, `reconnect`,
  `delete` and `upgrade` now reject a missing or empty `agent_ids`, and validate
  every ID, instead of calling the Wazuh API with an empty list.
- **Added: `POST /api/groups` validates the group name** (the `DELETE` route
  already did), so a malformed or missing name is a 400 rather than a group
  literally named `None`.
- **Fixed: version comparison was defined three times**, and the definition that
  actually won at runtime differed from the one written first. Consolidated into a
  single numeric comparator, so `4.14.7` correctly ranks above `4.9.0`.
- **Removed dead code:** the `wazuh-user` CLI fallback for listing roles (Wazuh
  ships no such binary — RBAC is API-only), plus five unused imports.
- zh-TW strings added for the new validation messages.

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
