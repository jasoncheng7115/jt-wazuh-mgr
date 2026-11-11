# jt-synology on Wazuh 5.x (beta) — porting notes

Ported from jt-synology 1.2.1 (4.x, rules 132000-132099) to Wazuh 5.0.0-rc2. Beta until Wazuh 5.0 GA
and a new check.

## What is here

- `integration.yml` — integration `jt-synology`, category `security`.
- `decoders/10-jt-synology-syslog.yml` — DSM 7 BSD lines (program name Connection, System,
  Hyper_Backup) under `decoder/jt-syslog/0`; splits the acting account (`SYSTEM:<tab>`).
- `decoders/20-jt-synology-raw.yml` — under `decoder/jt-core/0`: DSM 6 (`Connection SYSTEM: ...`,
  `Backup SYSTEM: ...`), file transfer logs (`WinFileService Event: ...`) and IETF (RFC 5424) lines,
  which the syslog header decoder does not take. Only those shapes are accepted.
- `decoders/30-jt-synology.yml` — one classifier for both: every DSM event gets an `event.action`
  (one value per 4.x rule), plus the WCS fields below.
- `kvdbs/` — the two optional 4.x CDB lists as KVDBs (placeholder key only, as on 4.x).
- `rules/jt-synology.yml` — 63 Sigma rules, one per 4.x single-event rule of level 3 or more.
- `monitors/jt-synology.yml` — 7 of the 12 frequency / correlation rules.
- `cases.json` — the 225 4.x cases plus 3 new ones (injection, KVDB placeholders).

## Why the patterns live in the decoder

The 4.x System and Hyper Backup rules match DSM's message catalogue case-insensitively with
look-aheads (`^(?!.*partially)...`). Sigma on rc2 has no case-insensitive regex (`|re|i` is refused,
`|re` never matched `message`), and `|contains` is case-sensitive. The engine's `regex_match` is RE2
(no look-ahead, `(?i)` works), so each 4.x pattern became a decoder block `regex_match AND
regex_not_match`, in the order 4.x evaluated the sibling rules (level 0 first, then highest level),
each one guarded by `not_exists($event.action)` so a line still gets one result. The Sigma rules then
match `event.action` and add the address / account logic (`source.ip|cidr`, `user.roles`). The
catalogue wording is unchanged from 4.x.

Escaping: helper string arguments unescape once, so a regex backslash is written `\\` in the YAML
(`\\b` = `\b`); brackets are `[[]` / `[]]`. Values containing `(?: ` must be quoted in YAML.

## WCS field choices

- `user.name` — the account that signed in, failed or was locked (4.x `dstuser`); on other System /
  Hyper Backup lines the acting account (SYSTEM, admin). File transfer: the `User:` field.
- `user.roles` — `builtin-administrator` (admin, administrator, root, also `DOMAIN\Administrator`),
  `administrator` (KVDB jt-synology-admin-accounts), `service-account` (KVDB
  jt-synology-service-accounts). Replaces the 4.x `<list>` lookups and the `<user>` regex.
- `source.ip` / `source.address` / `related.ip` — client address, `::ffff:` removed;
  `source.domain` — the client name in `from [pc1(192.0.2.10)]`.
- `network.direction` — `internal` (10/8, 172.16/12, 192.168/16, 127/8, 100.64/10, 169.254/16,
  fc00::/7, fe80::/10) or `inbound`; the brute force monitors split on it (4.x 132024 vs 132025),
  because a monitor `match` is term filters only.
- `network.application` — the DSM service as written: DSM, SSH, SMB, CIFS(SMB3), WebDAV, HTTPS, FTP.
- `event.reason` — text after "due to" / "because"; `file.name` — the shared folder opened.
- `process.title` — the Hyper Backup task or Task Scheduler task (4.x `synology.task`). No WCS field
  is meant for a job name; this is the least wrong one (open question).
- File transfer: `event.action` (delete, rename, read, upload...), `file.path`, `file.target_path`
  (rename target), `file.type` (file/dir), `event.provider` (WinFileService, FileStation, ...).
  The size ("9.81 KB") is not mapped.
- `event.dataset` — synology.connection / .system / .hyper_backup / .file_transfer;
  `observer.vendor` Synology, `observer.product` DSM.
- Not kept: the sign-in method (password, OTP) has no WCS field; it only selects
  `second-factor-failed`.

Injection (4.x lesson kept and tightened): the account in `User [...]` is attacker-chosen on a failed
sign-in. The decoder reads it greedily and requires the rest of the line to be one whole DSM template
up to the end of the line, so address, service and verb come from the template DSM wrote last. 4.x
took the first `from [...]` anywhere. New case: an account name imitating an outside sign-in decodes
as the real internal failure. File transfer lines are read from the end the same way. One residual
ambiguity: "failed to log in via [S]" is both a template of its own (no address, some SMB failures)
and the end of "from [ip] failed to log in via [S]"; the address form is preferred, so an account
name ending in `] from [192.0.2.9` on a no-address failure is read as coming from that address (4.x
had the same ambiguity, and worse: it took the first `from [...]`).

## Not ported, and why

- **132033** (first login of an account/address/service, `if_fts`): no first-time-seen on 5.x. An
  ordinary account signing in from a private address now raises nothing (it is still indexed).
  11 cases changed to `rules: []`.
- **132034** (first internal shell login, `if_fts`, L5): ported **without** FTS, so every internal
  SSH/Telnet login is a finding (low). Scheduled SSH jobs will produce one per run; 4.x recorded
  repeats at level 2. Disable the rule if that is too noisy. Case 19 changed accordingly.
- **132015** (listed service account, level 0) and every level 1-2 rule: not rules on 5.x; the
  service-account role still suppresses 132018 and 132016 as on 4.x.
- **132030, 132031** (success after ≥ 4 failures, same address / account) and **132037-132039**
  (success from an address or for an account that set off brute force): these need "N failures, then
  a success" in one bucket. The monitor format of `tools/pack5_dev.py` has one `count` or `distinct`
  per monitor, and successes from private addresses are not findings, so it cannot be expressed. A
  bucket-level monitor over the events index with two filtered sub-aggregations (failures ≥ 4 and
  successes ≥ 1 per `source.ip` or `user.name`, 10 min) would do it; that needs the tool to support
  it. Cases 51, 53-59 carry `monitor` for reference and expect the per-event finding.
- Active response: 4.x had none for this pack (the NAS runs no agent).

## Monitors (4.x frequency rules)

132024 / 132025 (8 failures per address; internal / external), 132026 (10 failures per account),
132046 (same Hyper Backup task failed 3 times, 3 days, grouped by `process.title`), 132055 (5
snapshot deletions per NAS, `host.hostname`, 10 min), 132052 / 132053 (300 deletes / 100 renames per
account over the events, since 132050 / 132051 are level 2). 4.x windows shorter than 5 minutes
(120 s, 60 s) became 5 minutes with the same count, so they fire somewhat more readily.

## Open questions

- 63 rules exceed the default `plugins.security_analytics.max_rules_per_detector` (50): one detector
  for this integration needs that setting raised, or two detectors.
- `process.title` for task names, `network.application` for the DSM service: better WCS homes?
- No System-category line has been captured from a real NAS (same as 4.x): wording follows the
  DSM 7.2.2 / 7.4.1 catalogues.
- `is_public_ip` decides internal for IPv6 (fc00::/7, fe80::/10, ::1); 4.x did not list ::1.
