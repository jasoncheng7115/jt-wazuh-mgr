# jt-zenarmor on Wazuh 5.x (beta) - porting notes

Source: jt-zenarmor 1.6 (4.x), 65 rules. Tested on the 5.0.0-rc2 test machine with
`tools/pack5_dev.py all jt-zenarmor`: **143/143 cases pass** (all 143 cases of
`tests/pack_cases/jt-zenarmor.json`).

## What was ported

- **Decoders** (own; no standard 5.0 integration decodes Zenarmor):
  - `decoder/jt-zenarmor/0` under `decoder/jt-syslog/0`: program name `zenarmor*` (zenarmorngfw
    too), message `daemon=..., index=<type>, data={json}` anchored at the start; the JSON is parsed
    with `parse_json` and every trusted value is read from the parsed object (never "the first
    `"key":` in the line": query names, DHCP device names and TLS server names are client text).
  - `decoder/jt-zenarmor-classify/0` (child): the 4.x rules' case-insensitive pcre2 now runs here
    in RE2 and becomes tags `zenarmor.*`, because Sigma on rc2 is case-sensitive and `|re` does not
    match. Lookaheads were rewritten: the threat families are computed in precedence order into one
    exclusive tag (`zenarmor.st-malware` > `st-phishing` > `st-dns-tunnel` >
    `st-potentially-dangerous` > `st-evasion` > `st-weak` > `st-malformed-dns` > `st-parked`), and
    "Botnet but not Botnet DGA" is spelled out without lookahead. Word boundaries are
    `[^a-z0-9_]` against a `|`-wrapped joined list (no backslashes in engine arguments).
- **KVDBs** (4.x CDB lists, placeholders only): `jt-zenarmor-resolvers` (address, or a prefix
  ending in a dot: the decoder looks up the address and its /24, /16, /8 prefixes, like 4.x
  `address_match_key`) and `jt-zenarmor-domain-allow` (exact, lower case).
- **Rules**: 24 Sigma rules, one per 4.x single-event rule of level 3 or more: 130801-130806,
  130819, 130820, 130828, 130840, 130841, 130851-130855, 130857, 130861, 130864, 130866, 130868,
  130870, 130874, 130875. 4.x tried siblings in level order and the first match won; every rule
  here excludes what a 4.x rule tried before it, so one event gives one finding (e.g. 130802
  excludes C2 (130820) and mining names (130874); 130868 excludes the evasion categories, which
  4.x tried first at the same level).
- **Monitors**: 130830, 130831 (findings of 130801 / 130802), 130832-130835, 130860 (events, by
  the tags `zenarmor.client-query`, `resolver-query`, `threat-block`, `st-malformed-dns`).
  Not yet created or dry-run on the test machine (`monitors`/`monrun` are outside this brief).

## Not ported, and why

- 33 rules below level 3 (130800, the parked rules 130807/130808, the record-copy and lookup
  bookkeeping rules 1308xx at level 2): on 5.x every decoded event is indexed anyway; their
  classification survives as tags that the monitors count.
- **Correlation demotions 130844, 130847, 130848, 130850, 130865**: "a client-style lookup from a
  source that sent a resolver-style record in the last 15 minutes is a forwarded lookup". 5.x rules
  have no per-event correlation. Consequences, written into the cases:
  - case 53: a C2 lookup forwarded by a recognised resolver gives **130819** (low), 4.x 130848 (L2);
  - case 97: the same for an unblocked C2 name gives **130864** (medium), 4.x 130865 (L4);
  - such lookups are tagged `zenarmor.client-query` and count towards the beaconing monitors
    130832 / 130833 (4.x moved them to 130834 / 130835). Listing the forwarder in
    `jt-zenarmor-resolvers` restores the 4.x behaviour.
- The 4.x sibling order also kept a lookup out of the counts when a name rule (OAST, mining,
  tunnel, stager) or the evasion rule took it; the decoder cannot know that, so such a lookup can
  also be counted. Minor.

## WCS field choices

- `event.dataset` `zenarmor.<index>`; `event.kind` `alert` for alert records, else `event`;
  `event.action` `blocked` / `allowed` (is_blocked); `event.reason` the alert message.
- `source.ip/port`, `destination.ip/port`, `network.transport` / `network.protocol` (lower case).
- `destination.domain` = the 4.x `zenarmor.domain` (alert: the matched name; dns: the query;
  others: dst_hostname when it is a name), **lower case**; `destination.address` = dst_hostname as
  logged (on a DNS block: the DNS server).
- `dns.question.name/type/class`, `dns.header_flags` (RD, RA, AA, TC), `tls.client.server_name`.
- `rule.category` = the category the record is about (array as logged); `rule.id` = alertinfo.sid.
- `tags` carry the classification (`zenarmor.*`, documented in the classify decoder).

## Cases

From `tests/pack_cases/jt-zenarmor.json`. Multi-line 4.x cases test their last line (the line the
4.x expectation was about); repeated cases keep the per-event finding of the base rule and name the
monitor. Tuning cases use the shipped KVDB placeholders instead of the 4.x sandbox list values
(192.0.2.53 -> 192.0.2.255, vpn.example.com -> allowlisted-domain.example.invalid,
myapp.ngrok.app -> allowlisted-tunnel-placeholder.onion), since the tool pushes the KVDB as shipped.
`location` is a syslog sender address (192.0.2.1).

## Open questions

- An event this pack decodes is also decoded by the standard space (generic syslog), so it may be
  indexed twice (standard copy plus this integration's `wazuh-events-v5-network-activity`); not
  measured for this pack.
- The prefix form of `jt-zenarmor-resolvers` (`192.0.2.`) is implemented but not covered by a case
  (a prefix key in the shipped KVDB would list every documentation-range source in the cases).
- `{{rule.category}}` in titles is an array; how the finding title renders it was not checked.
- The monitors and their dry runs, and a detector over `wazuh-events-v5-network-activity`, still
  have to be created on the test machine.
- At 2 KB per record and about 10 million records a week on one site, every record is now indexed
  (4.x left most of them at level 0); a pre-filter or `discard_events()` for empty-tag conn
  records may be wanted on 5.x.
