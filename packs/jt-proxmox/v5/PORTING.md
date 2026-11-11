# jt-proxmox on Wazuh 5.x (beta): porting notes

Ported from jt-proxmox 1.2.1 (4.x) and tested on 5.0.0-rc2 with `tools/pack5_dev.py all jt-proxmox`:
**129 / 129 logtest cases pass** (125 converted from `tests/pack_cases/jt-proxmox.json`, 4 new).
The 19 file integrity cases of the 4.x file are not in `cases.json` (see "File integrity").

## What was ported

- **Decoders** (7, own decoders; Wazuh 5.0 ships no Proxmox integration: on rc2 the standard space
  leaves pvedaemon, corosync, jt-pveproxy and Ceph lines at `wazuh-core`, i.e. unclassified and not
  indexed, so there is no double indexing):
  `jt-proxmox-actor` (tasks, logins, guest configuration, passwords, cluster membership: every
  "<user@realm> ..." line of pvedaemon and the CLI tools), `jt-proxmox-authfail` (pvedaemon failed
  logins, replacing the 4.x built-in pvedaemon decoder), `jt-proxmox-ha`, `jt-proxmox-backup`,
  `jt-proxmox-cluster` (corosync, pmxcfs, pve-firewall), `jt-proxmox-api` (pveproxy access log under
  the program name `jt-pveproxy`), `jt-proxmox-ceph` (under `jt-core`: the Ceph line is not syslog).
- **Rules**: 60 Sigma rules, one per 4.x single-event rule of level >= 3, plus `jt-proxmox-87201`
  (tag jt.rule.87201): 4.x relied on the built-in rule 87201 for a failed login, which 5.x does not
  ship. Every rule selects on `event.dataset` (or `wazuh.integration.name: wazuh-fim`), because the
  detector reads the whole system-activity index.
- **Monitors** (`monitors/jt-proxmox.yml`): 131202, 131234, 131243, 131267 as in 4.x (131267's
  window is 5m instead of 2m); 131206 and 131270 are **approximations**: a monitor cannot order events
  or combine "six failures" with "then a success", so they fire on a failed and a successful login
  for one account (131206, events) or one public address (131270, findings) within the window, at
  `medium` instead of 4.x level 12.
- `detector.yml`: wazuh-events-v5-system-activity (the pack's category, and where wazuh-fim lands).
- `agent/agent.conf` of the 4.x pack is used unchanged (out_format `jt-pveproxy:` is still needed:
  the API decoder only takes that program name; a bare access line stays out, as in 4.x).

## Not ported, and why

- Level < 3 (no finding on 5.x; events are indexed anyway): 131201, 131203, 131205, 131209, 131221,
  131242, 131256, 131287, 131292; level 0 bases 131210-131212, 131223, 131230, 131240, 131246,
  131248, 131250, 131279, 131280, 131290, 131291.
- 131200 and the list `jt-pve-service-accounts`: it only lowered routine logins (level 2, no finding
  on 5.x) to 0. No KVDB.
- 131268, 131288, 131289: first-time-seen (fts) does not exist in 5.x. Every public login is now
  131269 (informational); "first change from an address" is gone.
- Active response `block-login-bruteforce` (firewall-drop on 131267): on 5.x it is a dashboard AR
  channel (`block-ip`) plus an "Active Response" Alerting monitor on the 131267 monitor's output or
  on findings of jt-proxmox-131266; not shippable as pack content yet. `source.ip` is the plain IPv4
  address, as the 4.x decoder made sure.
- 131290 / 131291 / 131292 lowered the built-in FIM rule 550 for pmxcfs churn; standard rules cannot
  be lowered on 5.x. Whether Wazuh's standard FIM detection raises findings for /etc/pve churn is
  not known yet.

## File integrity (131293-131299): written, not verified

The rules read Wazuh's standard `wazuh-fim` events (`file.path`, `event.changed_fields`). No sample
of a 5.x agent's stateless FIM event was available, and `pack5_dev.py` cases need a raw line, so they
are pushed (WCS validation passes) but never matched in a test. "Content changed" (4.x
`changed_fields size|md5|sha1|sha256`) is `event.changed_fields|contains` those words, and an event
**without** `event.changed_fields` still matches, so a wrong guess about the field gives extra
findings rather than none. 131293 (snippets) also fires on a deletion (event type unknown).

## WCS field choices

- Tasks: `event.action` = task type (qmdestroy, vncshell, vzdump ...), `event.type` start/end,
  `orchestrator.resource.id` = the task's object (vmid, disk, pool, daemon; absent for a node shell),
  `user.name` = UPID owner, `service.node.name` = UPID node, `event.reason` = end status,
  `event.outcome` success for OK and "WARNINGS: n".
- Logins: `event.action` login-success / login-failure / second-factor-failure /
  second-factor-lockout, `user.name` = full userid (alice@pve), `source.ip` without ::ffff:.
- HA: `orchestrator.resource.type` node|service, `orchestrator.resource.name`,
  `service.previous.state` / `service.state`.
- Cluster messages: `user.name` actor, `user.target.name` (password change), `orchestrator.resource.id`
  (guest of "update VM"), `orchestrator.resource.name` (node added / removed). The "update VM"
  parameters are not copied into any field (guest descriptions can hold passwords).
- API: `http.request.method`, `url.original/path/query`, `http.response.status_code`,
  `event.outcome` (2xx success, 4xx/5xx failure), `event.action` = request class (login,
  access-change, api-token-change, second-factor-delete, guest-delete, firewall-change,
  firewall-options-change, storage-upload, cluster-config-change, backup-job-delete, backup-delete,
  guest-agent-exec, guest-password-set, api-change, api-request). The 4.x URL regexes are kept
  verbatim (RE2) in the decoder; rules match the class.
- Ceph: `service.node.name` (mon.pve1), `log.level` (warning, error ...), `message`, `event.code`
  (health check code), `event.action` health-check-failed/update/cleared. `event.start` is not set
  (the "+0800" zone needs a date sample; not tried).
- Datasets: proxmox.task, proxmox.auth, proxmox.cluster, proxmox.ha, proxmox.backup,
  proxmox.corosync, proxmox.pmxcfs, proxmox.firewall, proxmox.api, ceph.cluster.

## Hardening carried over / added

- Address first, status second to last (API); UPID fields colon-separated; rhost before the
  account name (failed logins).
- New: a failed-login `msg` that contains " msg=" (an account name typed with spaces) is never
  classified as a second-factor failure or lockout (4.x matched `msg=` anywhere and could be fooled).
- pmxcfs "[status] notice: received log" (about 20,000 a day per node) is not decoded.

## Open questions

- 60 rules exceed `plugins.security_analytics.max_rules_per_detector` (default 50): the detector
  needs that setting raised (or the pack split). Also `plugins.content_manager.max_rules` (200) is
  shared by all packs.
- 131206 / 131270 approximations: acceptable, or drop them?
- FIM rules need a real 5.x FIM event to verify (field names and values of `event.changed_fields`).
