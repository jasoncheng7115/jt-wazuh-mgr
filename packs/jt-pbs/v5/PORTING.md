# jt-pbs on Wazuh 5.x (beta): porting notes

Ported from jt-pbs 1.2.1 (4.x) and tested on the shared 5.0.0-rc2 test machine with
`tools/pack5_dev.py all jt-pbs`. 5.x support is beta until Wazuh 5.0 GA is re-tested.

## What was ported

- **Decoders** (own integration `jt-pbs`, category `applications`), all under the shared `jt-base` root:
  - `jt-pbs-syslog` (child of `decoder/jt-syslog/0`): only `proxmox-backup-proxy` / `proxmox-backup-api`.
  - `jt-pbs-authlog` (child of `decoder/jt-core/0`): `api/auth.log` (ISO time, no syslog header).
  - `jt-pbs` (child of both): classifies the message into `event.action` (see the decoder comment).
  - `jt-pbs-access`: `api/access.log`; `event.action` names the part of the API (the 4.x URL regexes of
    131861-131885, RE2, verbatim apart from the lookaheads, which became ordered blocks).
  - `jt-pbs-task`: `tasks/archive`.
  - `jt-pbs-df`: `df -P` and the optional `jt-pbs-datastores` command; only datastore filesystems are kept,
    every other df line is marked `discard_events()` in this space (the standard space keeps its copy).
- **KVDB** `jt-pbs-datastore-mounts` (the 4.x CDB list, placeholder key only), used by `jt-pbs-df`.
- **Rules**: every 4.x single-event rule with level >= 3 (see the counts in the final report). Where a 4.x
  child replaced its parent the parent excludes the child's case (one finding per event); where a higher
  level sibling won in 4.x (131822 / 131846 out of disk space, 131886 protected snapshots) the others
  exclude that case.
- **Configuration files** (131895-131898): FIM events of `/etc/proxmox-backup` are decoded by the
  standard `wazuh-fim` integration (`decoder/wazuh-fim-legacy/0` takes the 4.x agent's syscheck JSON, tested
  with queue 8 / location `syscheck`), which gives `file.path`, `event.action` (created / modified / deleted; the 4.x type "added" becomes "created"),
  `event.category: file`. The four rules select `wazuh.integration.name: wazuh-fim` and the file paths, so
  the pack has no FIM decoder (no double indexing); `detector.yml` adds `wazuh-events-v5-system-activity`.
  The FIM cases carry `decode: standard`. The built-in 550/553/554 for the other files are the standard
  space's business (those cases expect no finding of this pack).
- **Monitors** (`monitors/jt-pbs.yml`): 131805, 131806, 131809, 131812, 131819, 131823, 131836, 131866,
  131877, 131880, 131881.
- The agent side (`packs/jt-pbs/agent/agent.conf`, group `pbs`) is unchanged.

## Not ported, and why

- Level 0-2 rules (bases 131800/131810/131830/131860/131890/131891/131894, 131801, 131803, 131811,
  131813, 131818, 131831, 131832, 131876, 131889): on 5.x every decoded event is indexed anyway.
- **131808** (first login of an ordinary account, `if_fts`): 5.x has no first-time-seen. An ordinary
  account's login stays without a finding (the 4.x level 2 behaviour); only administrator logins
  (131807) give one.
- `ignore=` (131812 daily, 131814/131827/131828/131829/131859 hourly, 131806 hourly, 131892/131893 every
  6 hours): no equivalent. The rules fire on every event; a monitor fires on every run while over the
  threshold. Dashboard / Alerting throttling has to replace it.
- **Active responses** (block-login-bruteforce on 131805, block-api-probe on 131819): 5.x AR is a
  dashboard channel plus an "Active Response" monitor; not part of this port.
- 131889 (the PAM copy of a failed login, a child of the built-in 5503): that line is decoded by the
  standard system-auth integration in its own space; this pack cannot lower a standard rule.

## WCS field choices

- `user.name`: the account of a login (realm kept), the user/token of an API request or task
  (4.x `dstuser`). The ECS mapping table suggests `user.target.name` for `dstuser`; here the account is
  the actor, so `user.name`.
- `source.ip` / `source.port`: client address with `::ffff:` removed; absent when rhost is `unknown`.
- `event.reason`: the `msg=` part of a failed login, the result of a task, or `<n>% full` for df.
- `error.message`: the error of a failed task / datastore / notification / refused request.
- `service.target.name`: the datastore (syslog), the notification target, or the task worker id
  (kept with the log's systemd escaping, e.g. `store1\x3act-122`).
- `http.request.method`, `url.original`, `url.path`, `url.query`, `http.response.status_code` (long),
  `user_agent.original`: access log and the syslog copy of refused requests.
- `tags`: `pbs-protection-removed`, `pbs-destroy-data` (query string flags of 131888 / 131864).
- `volume.mount_name`, `volume.device_name`: df lines. WCS has no field for a usage percentage, so the
  decoder classifies it (`event.action` datastore-usage / -high / -critical) and writes `<n>% full` to
  `event.reason`.
- `event.dataset`: pbs.syslog, pbs.auth, pbs.access, pbs.task, pbs.df; `event.module`: proxmox-backup.
  Every rule selects on one of them, so its `event.action` values cannot match another integration's
  events in the same index.

## Open questions

- The `df -P` line shape (`ossec: output: 'df -P': ...`) is the 4.x agent's; not verified with a 5.0
  agent.
- 4.x relied on the agent group to drop GET/HEAD and routine lines of the access log and the task
  archive; the agent.conf is unchanged, so this still holds.
- Detector size: 71 rules, more than the default `plugins.security_analytics.max_rules_per_detector`
  (50, a dynamic setting). Either raise it or split the pack into two detectors (for example the 4 FIM
  rules plus the 23 API rules in one, the rest in the other); `tools/pack5_dev.py detector` makes one.
- Monitors 131809, 131823 and 131877 are approximations (see the comments in monitors/jt-pbs.yml): the
  monitor format has one condition, so "three failures then a login" became "a failure and a login in
  the same bucket", order not checked. A two-condition trigger (failures >= 3 AND a login) needs a
  bucket-selector over two filter sub-aggregations.
- The task worker id keeps the systemd escaping (`\x3a`); unescaping with `replace` was not attempted.
