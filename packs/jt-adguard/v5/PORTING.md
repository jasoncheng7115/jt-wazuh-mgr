# jt-adguard 4.x (1.4.1) to Wazuh 5.x (beta)

Tested on the shared 5.0.0-rc2 machine with `tools/pack5_dev.py all jt-adguard` (logtest: decoders
and rules). Monitors and the detector were not created on the test machine (not allowed for this
port); their definitions are in `monitors/jt-adguard.yml` and `detector.yml`.

## What was ported

- **Decoders** (no standard integration decodes AdGuard Home; CoreDNS / Microsoft DNS are other
  products): `decoder/jt-adguard-query/0` (program `adguard`, JSON body, under `jt-syslog`),
  `decoder/jt-adguard-home-syslog/0` (program `AdGuardHome`, journald / syslog) and
  `decoder/jt-adguard-home-file/0` (the same line read from a file, under `jt-core`), both feeding
  `decoder/jt-adguard-home/0`.
- **Rules** (`rules/jt-adguard.yml`): 29 single-event rules, every 4.x rule of level 3 or more that
  does not depend on correlation or first-time-seen: 130901, 130903, 130915, 130918, 130917, 130920,
  130921, 130922, 130923, 130925, 130964, 130931, 130932, 130941, 130942, 130934, 130935, 130936,
  130937, 130945, 130946, 130947, 130948, 130949, 130970, 130972, 130973, 130940, 130974.
- **Monitors** (`monitors/jt-adguard.yml`): 19. Frequency rules 130910, 130911, 130912, 130914,
  130929, 130963; first-time-seen rules 130905, 130913, 130924, 130951, 130953, 130955, 130957,
  130959, 130961, 130966, 130968; "success after failures / after lockout" 130939, 130944.

## Not ported, and why

- Level 0 / 2 rules (bases 130900/130907/130908/130916/130930/130927/130938/130926, repeats 130902,
  130950, 130952, 130954, 130956, probes 130904, 130943, level-0 classes 130958/130960/130962/130965/
  130967, successful login 130933): every decoded event is indexed anyway. The three "bases" existed
  only because built-in 1002/1003 stole events on 4.x; 5.x has no such rules.
- **130975** (program file replaced within 15 minutes of the built-in updater, level 3): it only
  lowers 130974. A Sigma rule cannot suppress or re-grade another rule's finding, and a monitor can
  only raise. 130974 now fires for updater replacements too; the 130972 finding next to it tells.
- **Flood control** (`ignore=`) of 130918, 130917, 130920, 130925, 130964, 130932, 130970: no 5.x
  equivalent. Every event is a finding.
- **First-time-seen** (`<if_fts />`): no 5.x equivalent. Done as monitors with count 1 per
  (agent, client, domain) over 24 hours (see the monitors file header), except 130942 (first login of
  a user from a private address): logins are few, so every private login is an informational
  130942 finding; 4.x level-2 repeats (130933) now also give 130942 (cases say so).
- **130939** is looser than 4.x: the monitor format has one condition (count *or* distinct), so it
  is "a failure and a success from one address within 10 minutes", not "three or more failures,
  then a success". Order is not checked either (130944 likewise). Suggested tool change below.
- **130910** window 5 minutes (monitors use 5 minutes or more) with 250 instead of 100 in 2 minutes.
- **FIM cases** (9 cases of `tests/pack_cases/jt-adguard.json`): the 5.x FIM events come from the
  standard `wazuh-fim` integration, whose raw input shape is not known here, so they cannot be
  replayed with `pack5_dev.py`. Rules 130940/130974 match `file.path|endswith` and exclude
  `event.type: deletion`; **untested** - check the wazuh-fim field values on a real agent
  (does it set event.type deletion for a removed file?).
- The agent group (`agent/agent.conf`, FIM of AdGuardHome.yaml and the binary) is unchanged and can
  be pushed as in jt-fail2ban.

## WCS field choices

- Query events: `source.ip`/`source.address` (client, `::ffff:` removed), `network.type`
  (ipv4/ipv6: public-client rules are IPv4 only, as in 4.x), `dns.question.name` (QH, **lower case**,
  trailing dot removed), `dns.question.type` (upper case), `event.action` blocked/allowed,
  `event.duration` (Elapsed, ns), `rule.id` / `rule.ruleset` / `rule.name` = filterlist_id /
  filterlist_name / filtertext.
- `rule.category` = class of the blocking list (threat, bypass, bypass-probe, dyndns, rebind,
  abused-tld, nrd, safe-browsing, other), decided in the decoder with the 4.x expressions
  (case-insensitive, word boundaries, the "abuse but not Abused TLD" exclusion rewritten without
  lookahead). Sigma here has no case-insensitive matching (`|re|i` is refused) and monitors filter by
  terms only, so classification cannot live in the rules.
- `tags` jt-adguard.{oast, mining-pool, reverse-tunnel, tor, telegram-bot-api, ip-lookup, long-label,
  pattern-rule, vulnerable-version, outdated-version}: same reason (name lists, label length, version
  ranges). Base64 labels are matched in the rule (`dns.question.name|contains: '==.'`).
- Service log: `source.ip`, `user.name` (the 4.x `dstuser`; the user who logs in), `url.path`,
  `http.request.method`, `http.response.status_code`, `error.message` (err text), `event.action`
  login-success / login-failure / login-locked-out / http-error / started, `event.category`
  authentication + `event.outcome`, `observer.version` (no `v`), `file.path` (refused filter path),
  `rule.id` (deleted list), `server.address` (pprof), `url.original` (list URL that failed).
  Trusted fields come from expressions anchored at both ends of the line (err text and filter paths
  are client data), as the 4.x decoder comments require.
- Every rule requires `event.module: adguard`: the detector reads whole category indices.

## Cases

`cases.json`: 152 cases. 149 come from the 4.x case file (its 9 FIM cases are left out, see above;
multi-line cases replay their last line), 3 are new (a public client outranks mining / AXFR / ANY).
A 4.x frequency, first-time-seen or "after failures" expectation becomes the per-event finding the
line still produces (often none) plus `"monitor": "<4.x id>"`. Field checks cover the classes the
monitors filter on.

## rc2 findings worth sharing

- A Sigma condition with a negated group, `not (ipv4 and not internal)`, compiled but never matched;
  `(internal or not ipv4)` works. Keep negations on single selections.
- The engine's single-quoted string literal unescapes backslashes: RE2 `\b` / `\s` / `\^` are
  written doubled (in YAML block scalars, so YAML adds no third layer). `(?i)` and `(?i:...)` work.
- Pushes sometimes fail with the indexer's parent circuit breaker (`Data too large`, 429, heap near
  820 MB); a retry later went through.

## Open questions

- FIM rules: field values of the standard wazuh-fim events (see above); `detector.yml` adds
  `wazuh-events-v5-system-activity` for them.
- Does the detector apply this integration's rules to wazuh-fim events in system-activity (the
  brief says custom rules over standard events produced findings on rc2)?
- 24-hour "first time" monitors: composite size is 1000 buckets per run; a site with more than 1000
  active (client, domain) pairs a day (IP lookups) would page through only the first 1000.
