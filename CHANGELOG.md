# Changelog

All notable changes to **JT Wazuh Manager** are documented here.

[English](CHANGELOG.md) | [繁體中文](CHANGELOG-zh-TW.md)

## v1.6.21 (2026-09-04)

- **The /dev/shm change is now verified end to end, on the live engine.**
  Temporarily monitoring `/dev/shm` on a manager and creating two files settled
  it: `jt_probe_kdevtmpfsi` raised rule 906203 at level 6, and
  `jt_probe_mailbox_0_shm` raised nothing at all, suppressed by 906224 as
  intended. The configuration was reverted afterwards.

  This mattered because the rule could not be checked any other way.
  `wazuh-logtest` replays log lines through decoders; a file integrity event is
  produced inside the manager and never passes through one, so it decodes as
  generic JSON and reaches no rule. Waiting for the real events to recur would
  not have proved anything either — see below.

- **A correction to the v1.6.20 note.** It described 53 false alerts "over a
  week", which reads as a steady drip. They arrived in a single four-hour burst
  on one host, with nothing in the seven days either side. The fix is unchanged
  and the reasoning is stronger without the volume argument: every one of the 53
  was wrong, and file integrity monitoring structurally cannot tell an ELF from
  a shared memory segment, whatever the rate. The burst shape is what an
  application restart looks like, so it recurs.

- **The READMEs no longer carry release notes.** The English one had a "What's
  New" section listing 1.6.1 while the badge above it said 1.6.19 — a second
  place to record releases is a second place to forget. A pre-release check now
  fails if such a section comes back. The changelog is the one place, and the
  READMEs link to it.

## v1.6.20 (2026-09-04)

- **The Linux side of portable-executable detection had a level 12 rule that was
  wrong every time it fired.** Rule 906203 alerted on any file with the execute
  bit appearing under `/dev/shm`. On a live estate it produced 53 alerts in a
  single four-hour burst on one host and nothing in the seven days either side.
  Every one of the 53 was a POSIX shared memory object — segments, mutexes and
  event objects that a mail application creates at mode 0777, which is normal
  for `shm_open()`. The burst shape matters: this is what a host looks like when
  an application restarts, or when file integrity monitoring first sees the
  directory, so it recurs rather than being a one-off.

  The rule was right about the mode and wrong about what it meant. File
  integrity monitoring reports a path, a mode, a size and hashes; it never sees
  the file's magic bytes, so it cannot tell an ELF binary from a shared memory
  segment. It is now a level 6 that describes what it actually knows, and rule
  906224 excludes the IPC naming conventions. Verified against all 53 real
  paths, and against `kdevtmpfsi`, `xmrig` and five other names a dropper
  would plausibly use, which still alert.

  Execution from `/dev/shm` remains level 12 as rule 906211, because auditd
  proves a program ran rather than that a file appeared.

- **The pack now ships the agent-side collection its Linux rules depend on.**
  It had none. The audit rules file referenced in the comments did not exist, so
  rules 906210 and 906211 could never fire, and the file rules relied on
  monitoring nobody had configured.

  Added: an agent group `portable-detect` with file integrity monitoring of
  `/tmp`, `/var/tmp` and `/dev/shm` in real time, the user download directories
  on the scheduled scan, and the audit log; plus `jt-portable.rules` for auditd,
  which now rides along in the group directory so it reaches the agents rather
  than sitting on the manager. `/home` watching ships commented out, with the
  reason stated: it is accurate and noisy, and that trade is the operator's.

- **Rule 906212**: a program that runs once from `/tmp` may be an installer; one
  that runs six times in ten minutes is living somewhere nothing should live.

- A pack's agent group can now carry files beyond `agent.conf`, listed under
  `agent_group.files`. Names are validated, existing files are never
  overwritten, and a rolled-back install takes them with it.

- The pre-release check for agent configurations was rejecting valid files:
  `agent.conf` is a fragment and several `<agent_config>` blocks with different
  `os` attributes is its normal shape. It now parses it as one.

- Verified on a live 4.14.7 cluster: `wazuh-analysisd -t` clean, both nodes
  reloaded with no warnings and holding the same file, and each scenario checked
  with `wazuh-logtest` on the master and again on the worker — including a
  negative case that must not match the pack.

## v1.6.19 (2026-09-01)

- **Relicensed to AGPL-3.0.** The project was Apache-2.0, which permits closed
  derivatives. GPL-3 would stop those being distributed, but this is a hosted
  admin console, and the GPL's obligations trigger on distribution: running a
  modified copy as a service for other people is not distribution. AGPL section
  13 closes that, and the interface now carries the source offer it requires.

- **Browser journeys, automated.** `tests/e2e/run.sh` runs 17 journeys and 65
  checks in a real browser against a mocked, stateful Wazuh API. The unit tests
  reach Flask routes and can only check that the front end parses; everything a
  person does -- switching a tab, ticking rows, confirming a dialog, reading a
  table -- ran code nothing tested.

  The harness starts the application the way production does. An early version
  called `app.run()` directly, which skips the header hardening, and a check
  promptly reported the `Server` header advertising werkzeug's version. That was
  the harness measuring a different program from the one that ships, and it is
  the reason the startup path is now shared.

  One finding about the interface came out of writing them: it refreshes on a
  timer, and a refresh landing between typing into a dialog and pressing its
  button repaints the modal. The dialog checked out a moment earlier and had no
  button left when pressed.

- **Five more pre-release checks**, all of which failed the first time they ran:

  The README heading carries the version, and nothing had been looking at it --
  it still said v1.6.0, nine releases later, while the badge below it was
  correct. One licence, stated the same way everywhere, rather than AGPL in the
  badge and Apache in seven pack manifests. The project name is `jt-wazuh-mgr`,
  lower case, in one form rather than three. The icon set exists and is
  referenced. The interface offers its source, which under AGPL is a licence
  term rather than a nicety.

- **A project icon.** The mark until now was the author's company logo. This one
  is the project's own: a manager holding a cluster of agents, drawn to survive
  16 pixels, shipped as SVG, PNG at six sizes, and a multi-size `.ico`.

- **The project pages say what the project does.** Rule packs were not mentioned
  at all, and they are the part of this tool that Wazuh has no answer for.
  Added: the seven packs and what each detects; what a cluster synchronises and
  what it leaves to you; and what is verified before a release, including what
  is not.

- The published name is now `jt-wazuh-mgr` everywhere, including the interface.

## v1.6.18 (2026-09-01)

- **The ruleset reload now shows what analysisd warned about.** Reloading with a
  CDB list a node cannot load returns this:

  ```
  error: 0   message: "ok"
  data: ["List 'etc/lists/x' could not be loaded. Rule '199990' will be ignored."]
  ```

  A successful reload, carrying the news that a rule has just been switched off.
  The per-node reload read only `failed_items`, so it reported a clean success
  and dropped the warning. It is now returned and shown in a dialog rather than a
  toast, because a rule that loads and can never match is worth stopping for.

  This was measured, not assumed: on the production cluster a probe rule reading
  an undeclared list produced exactly that warning on the worker, matched nothing,
  and began matching the moment the declaration was added.

- **The cluster-wide reload no longer lists the plain success sentence as a
  warning.** It showed "Ruleset reload request sent successfully." in the warnings
  column of every node on every clean reload, which teaches people to skim past
  the column a real warning would appear in.

- The v1.6.17 note said an undeclared list is ignored "with no error at load and
  no warning on reload". The first half is right and the second is not: analysisd
  warns, on an otherwise successful reload. Corrected here, in the test plan and
  in the code comments. It is the reason this release exists — the information was
  always there, and the tool was throwing it away.

## v1.6.17 (2026-09-01)

- **A pack that ships a CDB list is now declared on every cluster node, not just
  the one running the tool.** The cluster synchronises `etc/rules`, `etc/decoders`
  and `etc/lists`, but `ossec.conf` is in its own `excluded_files`, alongside
  `ar.conf`. So the rules and the list arrived on every worker while the `<list>`
  declaration they depend on stayed behind on the master — and a rule whose list
  is undeclared loads but can never match. analysisd does say so, but as a warning
  on an otherwise **successful** reload: never an error, never blocking anything,
  and easy to miss. Workers are where agent events are processed, so on a
  master-plus-workers cluster the detection simply did not run.

  Four of the seven packs ship a CDB list and were affected: `jt-ioc`,
  `jt-malware-hash`, `jt-portable-detect` and `jt-zimbra`.

  The declaration now goes out over the Wazuh API
  (`PUT /cluster/{node_id}/configuration`), which needs no setup. If that fails,
  it falls back to SSH using the same optional per-node configuration the node
  configuration editor already uses. Each write is then **read back**, because a
  200 means the upload was accepted, not that the file holds what was sent.

- **What happens when a worker cannot be reached is now a decision, not a
  default.** The install aborts and rolls back, naming the node, its address and
  the reason, and saying what to do: configure SSH for that node, or add the
  `<list>` entries to its `ossec.conf` by hand and reload. To install on this
  node alone, repeat the request with `local_only`.

  Choosing that records the nodes that are short in the pack's installed state,
  and the pack detail shows it every time it is opened. A warning shown once at
  install time is gone by the time anyone wonders why the worker is not alerting.

- Removing a pack now withdraws the declaration from the other nodes too, and
  logs any node it could not reach rather than leaving it silently declared.

- 13 more tests, 159 in total, covering the declaration text itself, the peer
  write path, a node that accepts a write without applying it, a redundant
  declaration writing nothing a second time, the abort-and-roll-back path, and
  `local_only`.

## v1.6.16 (2026-09-01)

- **Three input-validation gaps, found by writing the tests that were missing.**
  Of 82 routes, 45 had no test of any kind. Writing them turned up three real
  faults, all in the routes that change something:

  `..` was a valid group and node name. The pattern behind both validators
  permits `.`, so a name made only of dots matched it, and those names are
  interpolated into API URLs and into paths. Both validators now reject `.`,
  `..`, and any name containing `..`.

  The two group membership routes forwarded whatever agent IDs they were given,
  without validation, although a correct helper for exactly this had existed and
  was already used by six other routes.

  Worst of the three: queue DB cleaning iterated `agent_ids` directly. A string
  is iterable, so `{"agent_ids": "001"}` became `['0', '0', '1']` — three IDs
  that each pass validation — and the route deletes queue DB files and restarts
  every ID it is given. Agent `0` is the manager. All four routes now use the
  shared helper, which requires a non-empty list.

- **A second test module, `tests/test_ui_operations.py`, covering the routes that
  change something.** 20 tests over group, node, agent, pack and configuration
  operations: unsafe names, path traversal, non-list bodies, XML external
  entities, and the file-download route that takes a keyword rather than a path.

  Destructive routes are exercised along the rejection path only. Several of them
  shell out or delete files once validation passes, and the machine running these
  tests is usually a live manager. The guard is what is worth asserting.

  The authentication test now derives its route list from the app's own
  `url_map` rather than a hand-written list of eight, so a route added later is
  covered without anyone remembering to add a test. The suite is 146 tests.

- **A test plan, in both languages** ([TEST-PLAN.md](TEST-PLAN.md)), covering all
  five layers — automated suite, mechanical checks, security scan, browser
  checklist, deployment — and stating plainly what is still not covered: no
  DOM-level automation, no load testing, no cross-version upgrade testing, and
  detection rules verified by hand rather than in CI.

- **The IOC pack's IP list is renamed `jason_tools_threat_ip`.** It was
  `jason_tools_blacklist`. The word carries a racial connotation that has nothing
  to do with what the file holds, and a list of addresses seen in threat feeds is
  described perfectly well without it. The updater is renamed to match, and all
  30 rule references move with it.

  Renaming a CDB list is not a text substitution, because the cluster synchronises
  `etc/lists` but not `ossec.conf`. Each node needs its own `<list>` declaration,
  and a rule pointing at an undeclared list is ignored **silently** — no error at
  load, no warning on reload, just a rule that never fires. Both declarations are
  deliberately left in place for now; the old list is removed only once the new
  name has been running long enough to trust.

- **Two threat feeds are back after being dropped by accident.** Rewriting the
  updater in v1.6.14 silently lost three of the original sources, and the list
  fell from 259,839 entries to 220,957 — a 15% loss of coverage that nothing
  reported, because a shorter list is still a valid list. Tor exit nodes and the
  matthewroberts threat list are restored; the third, maltrail, is genuinely gone
  upstream. The list is back to 247,383 entries.

  The updater already refuses to install a list that has shrunk by more than
  half. That threshold was too generous to catch this, and the check only ever
  compares against the previous run, so a loss that arrives in the same change
  that rewrites the script cannot be caught by the script. The feeds are now
  listed one per line with the count each contributes, so a missing one is
  visible when reading the file rather than only when counting the output.

- **Zimbra rule 100990 is removed rather than repaired.** It matched a hash list
  that shipped with a single placeholder entry, so a level 15 rule had never
  fired and never could. Inspecting it turned up two further faults: it read a
  field named `sha256`, while a file integrity event carries `syscheck.sha256_after`,
  and the jt-malware-hash pack's rule 100141 already does this exact job against
  a list of roughly 1.1 million hashes rebuilt nightly. Install that pack for
  hash matching on file integrity events.

- **The approved-portable-executable allowlist now ships genuinely empty.** It
  contained one fabricated entry, which made the list look populated while
  approving nothing. Empty is the correct default for an allowlist. The file now
  documents the key format instead — the whole `hashes` field including the
  `SHA256=` prefix, as Sysmon reports it, which is not obvious and was previously
  conveyed only by the shape of a fake entry.

- A pre-release check now fails on any CDB list that still contains a placeholder,
  so a rule cannot again be published pointing at a list that cannot match.

## v1.6.15 (2026-09-01)

- **Portable-executable detection: tuned against a week of live traffic.** The
  pack's own rules turned out to be fine — verified end to end by running a
  binary from Downloads and from Temp on a real host, which produced rules 906100
  and 906102 as intended. They had been silent for a week because nothing on that
  estate runs portable executables, which is a different thing from being broken.

  What was broken, and what was noisy, were both elsewhere. Rules 906120, 906121
  and 906122 could never fire: the first keyed on a syscheck path no agent
  monitors, the other two on a Sysmon event the deployed configuration does not
  emit. And Wazuh's own Sysmon file-creation rules produced 4,245 alerts in seven
  days, of which essentially all were noise:

  | rule | level | 7 days | what it actually was |
  |---|---|---|---|
  | 92205 | 9 | 3,122 | PowerShell probing its own execution policy |
  | 92217 | 6 | 799 | .NET native image generation |
  | 92200 | 6 | 278 | a Windows pool-tag dump, written twice each time |
  | 92213 | **15** | 33 | browser updaters unpacking their own downloads |
  | 92207 | 12 | 5 | the Chrome installer writing a Public shortcut |

  Rules 906160-906166 suppress exactly those, each tied to a specific path or
  filename rather than to "this process is trusted", since an attacker chooses
  the process name. Verified live: eight PowerShell script executions during the
  measurement window produced no alerts at all, against roughly one every two
  minutes before.

  A level 15 rule that is wrong every time is worse than no rule, because it
  teaches people that level 15 means nothing.

- 906120 is gone rather than rewritten. Wazuh's rules 92200-92217 already detect
  executables landing in user directories, and anything we add under the same
  group is a sibling that is never reached once one of them matches — confirmed
  by creating a file on a live host and watching rule 92203 take it.

## v1.6.14 (2026-09-01)

- **Packs now install what they need to actually work.** Until now a pack put
  rules, decoders and lists on the manager and stopped there, which quietly meant
  several of them did nothing at all. jt-ioc shipped thirty rules matching a CDB
  list nobody filled. jt-fail2ban's rules cannot see a log the agent never reads.
  A pack is now allowed to carry two more things:

  **An updater and its schedule.** jt-ioc and jt-malware-hash each ship a rewritten
  updater, installed to `etc/jt-packs/bin/` and scheduled through `/etc/cron.d`.
  Both are standard library only, so a manager needs no pip packages, and both use
  absolute paths throughout: the job they replace used relative paths, cron ran it
  without a `cd`, and it failed silently for ten and a half months while the list
  it feeds sat frozen. Both refuse to install a list that has lost more than half
  its entries, because a feed changing format looks exactly like the threat
  landscape improving.

  **An agent group.** jt-fail2ban and jt-zimbra carry the collection their rules
  depend on. An existing group of the same name is never overwritten -- agents may
  be assigned to it and it may hold settings the pack knows nothing about.

  Installing an executable that runs as root on a schedule is a privileged act, so
  it is declared in the manifest, shown in the detail dialog before installing,
  reported in the result, and removed again on uninstall.

- The dead maltrail feed was dropped rather than left to log a 404 forever, and
  reserved and well-known public addresses are now excluded whatever a feed says.

## v1.6.13 (2026-08-31)

- **fail2ban log collection decoupled from the Zimbra group.** The pack was
  already standalone, but the localfile entry that feeds it had been added to the
  Zimbra agent group, which quietly made "we monitor fail2ban" mean "we monitor
  fail2ban on mail servers". fail2ban runs on web servers, jump hosts and
  anything else facing the internet; collection now lives in a group of its own,
  to be assigned to any agent running it regardless of what else that host does.

## v1.6.12 (2026-08-31)

- **New pack: fail2ban.** Wazuh ships no decoder and no rules for fail2ban at
  all, which was confirmed rather than assumed: every real log line fed to
  `wazuh-logtest` came back "No decoder matched". Two mail servers had been
  banning attackers for months with nothing recording it.

  A ban and the unban that ends it are both reported, because the pair is what
  makes an incident readable afterwards. A ban of an RFC 1918 address is graded
  above a ban of an external one: an outside address failing authentication is
  the internet being the internet, an inside host doing it is either a client
  left with a stale password or a machine working through a credential list.
  Correlation escalates a source that keeps earning bans, and treats an internal
  host doing so as a possible compromise.

  The address is decoded into `srcip`, so these events correlate with the rest of
  the ruleset and are usable by an active response command.

- The pre-release privacy check now recognises CIDR notation. An address with a
  `/nn` suffix is a range definition, not a host, and a rule that classifies
  RFC 1918 sources has to name those ranges to do its job.

## v1.6.11 (2026-08-31)

- **Every screenshot recaptured against a mocked API.** The published images were
  taken from a live console and carried a complete inventory of the network they
  came from: forty-one agent names, their addresses, operating systems and agent
  versions, the cluster node names, the manager's hostname in the address bar and
  the operator's login. They are now generated by a headless browser against a
  fully mocked Wazuh API, so the data is invented — and chosen to illustrate what
  each screen is for, which a real console does less well.

  Three separate leaks only showed up on inspecting the rendered images rather
  than the code: the local node is labelled with the host's own name, the
  ossec.conf viewer reads the real file from disk, and the log viewer shows
  whatever the application last wrote. Screenshots cannot be checked by grep, so
  they are reviewed by eye before publishing; the release checklist now says so.

- Nine screens that had never been documented are included: the upgrade flow,
  inventory search, rule packs and their detail view, rules listed by file name,
  and statistics. The GitHub Pages gallery lists all nineteen.

## v1.6.10 (2026-08-31)

- **`tools/preflight.py`: the release checklist now runs itself.** Every check in
  it exists because something was missed at least once. The version badge in both
  READMEs and on the Pages site had sat at 1.6.0 for nine releases while the
  checklist plainly said to update it, and a decoder comment carrying a real
  hostname and client address had already shipped in a published pack despite a
  written rule against exactly that. Both are now caught mechanically.

  It verifies version and badge consistency, a changelog entry for the current
  version, that `github/` has not drifted from the working tree, that nothing
  published names a private address or internal host, pack manifest hashes and
  rule-ID ranges, `INDEX` consistency, English-only rule descriptions, that the
  i18n dictionary is actually embedded, that the template JavaScript parses, that
  every screenshot the READMEs reference exists, and that no correlation rule
  hangs off a level-0 parent — which never fires.

- The privacy pattern is pinned by tests, because a check that silently stops
  matching fails open. Those tests also cover the case that first broke it:
  a Zimbra jar named `10.1.20.1762506875` is a version, not an address.

- Fixed what the new checks found: stale version badges, a real hostname and
  client IP in the AdGuard decoder comment, an internal hostname in a source
  comment, and `install.sh`/`uninstall.sh` still carrying the pre-rename product
  name in the working tree.

## v1.6.9 (2026-08-31)

- **The rule hierarchy search accepts a file name.** Until now it took a rule ID
  and nothing else, which answers "what is related to this rule" but not "what
  does this file actually contain" — the question being asked when reviewing a
  pack or auditing a single ruleset file. Any non-numeric query is now treated as
  a file-name fragment: `zenarmor`, `ZENARMOR`, `zenarmor-rule` and
  `zenarmor-rule.xml` all find the same file, and matching files appear as tree
  roots with their rules nested beneath by parent-child relationship.

  A query that could not be a file name — anything with a path separator, or
  longer than 64 characters — is refused rather than searched. The value is only
  ever substring-matched against names already read from disk, so it never
  reaches the filesystem itself.

## v1.6.8 (2026-08-31)

- **AdGuard: a filter-evasion block alerts, and persistence is summarised.** The
  bypass rule keeps its level 3 — a block is a control that fired, and the
  operator wants to see each one. The volume behind it is real, four Apple and
  Chrome devices produced 152 blocks in a single day for the same five
  encrypted-DNS endpoints, so a new correlation rule reports once an hour per
  client instead of leaving that pattern to be spotted by eye.

## v1.6.7 (2026-08-31)

- **Pack names and descriptions follow the reader's language.** The Rule Packs
  table and its detail dialog rendered `name_zh` and `summary_zh`
  unconditionally, so an English-speaking operator opened the tab and found the
  entire pack catalogue written in Chinese. Both now select by the current UI
  language, matching the fix already applied to the pack notes. Found by looking
  at the screenshots rather than the code.

- Screenshots added for the Inventory and Rule Packs tabs, which had shipped
  undocumented since 1.5.0 and 1.6.0. They are captured against a mocked Wazuh
  API rather than a live one, so the published images carry demonstration
  hostnames and addresses instead of anything real.

## v1.6.6 (2026-08-30)

- **Zimbra baseline rebuilt from live servers.** `zimbra-webfiles` is the list
  that tells the FIM rules which files are stock. It had drifted: measured
  against the previous seven days of alerts, 78% of the Zimbra file-integrity
  false positives are eliminated by the new baseline plus one new suppression.

  Two real gaps were behind them. The baseline held no entries at all for
  `/opt/zimbra/lib/ext`, where rule 100806 fires at level 15 — so every stock
  extension jar, 34 of them, was one modification away from a CRITICAL alert
  claiming the mail server's passwords were being stolen. And the baseline was
  built from `*.jar` only, while 100806 alerts on *any* file in that directory,
  so the `.wsdl`, `.xsd` and `.properties` files shipped alongside were
  unaccounted for.

  Every file added was checked before being trusted: ownership, modification
  time against the recorded upgrade dates, and for the one JSP, an identical
  SHA256 on both servers plus a scan for web-shell indicators.

- **Package-manager transient files no longer alert.** dpkg, ucf and rpm write
  new content to a `.dpkg-new`-style name and rename it into place seconds
  later. Those names can never appear in a baseline, and the file that actually
  gets installed still alerts under its final name. Suppressed across the Zimbra
  FIM rules and the persistence rules, which also settles the level-13
  "scheduled task modified" alert that `apt-compat.dpkg-new` was raising on
  every host.

- The Zimbra pack notes now carry the correct regeneration command, and say
  plainly that the baseline must be rebuilt after every upgrade — a Zimbra
  upgrade replaces version-stamped jars, and each new filename is unknown to
  the old baseline.

## v1.6.5 (2026-08-30)

- **New pack: AdGuard Home.** A decoder and rules for AdGuard's query log,
  covering rule IDs 130900-130999.

  This pack is the attribution layer for every DNS-based detection. A recursive
  resolver or a firewall only ever sees the resolver's own address as the source
  of a query, so a malicious lookup cannot be traced back to a host. Measured on
  a live network: 17% of DNS traffic reached the resolver through AdGuard and was
  therefore unattributable, including the one client generating the most
  suspicious activity — it never appeared in the resolver's log at all.

  Ordinary ad and tracker blocking stays silent. Only two things surface
  directly: a lookup blocked by a threat-oriented filter list, and a lookup
  blocked by a filter-evasion list such as DoH or Private Relay. Volume from a
  single client is left to correlation, since one blocked lookup means nothing
  and four hundred of them means a host worth examining.

- The base rule sits at level 2 rather than level 0, and the pack notes say why:
  `if_matched_sid` does not fire against a level 0 rule at all. Measured
  directly — 45 matching events never triggered the frequency rule until the
  level changed. Level 2 is still below the alert threshold, so it stays silent
  while remaining available for correlation. Every existing correlation rule in
  the other packs was audited against this; all 35 were already sound.

## v1.6.4 (2026-08-30)

- **Packs now state what they need in order to work.** Several shipped rules
  could never fire, and nothing said so: 906121 and 906122 need Sysmon event ID
  15, 906142 and 100990 match against CDB lists that ship containing only a
  placeholder line, and 906120 needs syscheck to watch `C:\Users`. A dashboard
  showing those rules installed looked like coverage that did not exist. Each
  manifest now marks these as prerequisites.

- **Pack notes are shown in the reader's language.** The detail panel only ever
  rendered `notes_zh`, so an English-speaking operator saw Chinese or nothing.
  Every manifest now carries an English `notes` list as well, and the panel picks
  whichever matches the current UI language.

- **Zenarmor: parked-domain matches drop to level 0.** The category turned out to
  be badly over-eager — one client produced roughly 2,900 alerts in a day, 88% of
  the pack's entire volume, all for a CDN-fronted application backend whose apex
  domain simply has no A record. Real DGA activity is already covered by
  Zenarmor's own Botnet DGA Domains tag, so nothing is lost.

## v1.6.3 (2026-08-30)

- **Rule descriptions are now English across every pack.** 128 of the 179 shipped
  rules described themselves in Traditional Chinese, which made the alert text
  unreadable for anyone outside the author's own console — and these packs are
  published for general use. Every description is now English, with the
  `$(field)` placeholders and the `[CRITICAL]` / `[HIGH]` / `[WARN]` prefixes
  unchanged, so existing dashboards and downstream parsers keep working.

  Punctuation is half-width throughout; the full-width colons and em-dashes that
  had crept in are gone.

- Pack versions bumped accordingly: jt-zimbra 2.1, jt-portable-detect 1.3,
  jt-zenarmor 1.2. The bilingual `name_zh` / `summary_zh` / `notes_zh` fields in
  each manifest are unaffected — those are deliberately dual-language, and the UI
  still shows Chinese pack names and notes.

## v1.6.2 (2026-08-30)

- **Zenarmor pack reworked against live traffic.** The first version keyed every
  classification on `security_tags`, which turned out to leave real signals on the
  floor: Zenarmor emits `security_tags` and `category` *alternately* — when one is
  present the other is null — so half the risk events fell through to level 0 and
  alerted on nothing. Both fields are now matched.

  Content classifications are graded as the weak signals they are: Proxy and
  Parked Domains sit at level 5 and 3, because `is_blocked` mostly means a
  browsing-policy block rather than a threat. Genuine threat tags keep the
  original grading, and a second correlation rule catches a host that keeps
  retrying malicious connections even while they are being blocked.

- Short tokens in the tag patterns are now anchored on word boundaries. Without
  them `Tor` matched `Torrent` under case-insensitive matching, which would have
  reported ordinary peer-to-peer traffic as anonymiser use.

## v1.6.1 (2026-08-30)

- **New pack: Zenarmor (OPNsense).** A decoder and severity-graded rules for
  Zenarmor NGFW events forwarded by syslog, covering rule IDs 130800-130899.

  Alerting is graded by threat class *and* by whether the firewall actually
  blocked the connection, with the deliberate choice that **an unblocked malicious
  connection outranks a blocked one** — if it was not blocked, the session was
  established and the host may already be compromised. Malware, botnet, C2 and
  ransomware traffic that got through raises level 12; the same traffic blocked
  raises level 7. Phishing, cryptomining and DGA follow at 10 and 5. Hacking
  tools, proxies, Tor and known-compromised hosts sit at 7. Six unblocked
  malicious connections from one internal host within five minutes raise level 13.

  The pack deliberately ships **no catch-all rule**: unclassified traffic stays at
  level 0 and does not alert, so normal browsing cannot flood the console. Routine
  policy blocks are best read in Zenarmor's own reporting rather than duplicated
  into Wazuh.

- Packs may now ship decoders as a first-class file type, installed to
  `etc/decoders/` with the same backup, validation and rollback as rules and lists.
- The shipped pack catalogue is now covered by tests: manifest hashes, install
  destinations, XML validity, rule-ID uniqueness across packs, and `INDEX`
  consistency are all verified, so a rule edit that forgets to refresh its
  manifest hash fails the build instead of surfacing at uninstall time.

## v1.6.0 (2026-08-30)

- **New Rule Packs tab.** A catalogue of the detection rule series maintained by
  Jason Tools, presented as a package manager rather than another read-only view
  of the Rules tab — installing and removing rules is a lifecycle operation with
  its own state, so it lives in its own tab.

  Each pack bundles rules, decoders and CDB lists behind a manifest. You can open
  a pack to see exactly which files it installs, where they go, which rule IDs it
  claims, and any notes on what it needs to work. Installing is deliberately
  cautious: rule-ID conflicts with already-installed rules are detected and
  refused unless forced, every file that would be overwritten is backed up first,
  the ruleset is validated with `wazuh-analysisd -t` afterwards, and **any failure
  rolls the whole install back** — files, list declarations and all. Nothing is
  left half-applied.

  Removal restores whatever the pack replaced. If you edited an installed file,
  removal stops and tells you which ones rather than silently discarding your work.

  Four packs ship initially: portable-executable detection (Windows/Linux/macOS),
  IP threat intelligence, malware hash matching, and a Zimbra detection suite.

- Pack paths honour `wazuh_path` from `config.yaml` instead of assuming `/var/ossec`.
- `install.sh` now fetches the pack catalogue.

## v1.5.2 (2026-08-29)

- **Node config drift detection.** `ossec.conf` is the one thing a Wazuh cluster
  does *not* synchronise, so a worker can quietly be missing a `<list>`
  declaration and ignore every rule that uses it — with nothing in Wazuh
  surfacing the drift. `GET /api/nodes/config-diff` reads each node's
  configuration through the API and compares the sections that actually change
  detection (`ruleset`, `wodle`, `syscheck`, `rootcheck`, `localfile`,
  `active-response`, `command`) against the master, reporting what is missing on
  a node and what only exists there. A **Config Diff** button was added to the
  Nodes tab.
  The comparison is semantic rather than textual, so comments and formatting do
  not produce noise. Run against a live cluster it immediately found four real
  drifts, including a worker missing every active-response command and running
  FIM without `realtime`.

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
