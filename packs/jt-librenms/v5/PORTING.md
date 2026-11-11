# jt-librenms on Wazuh 5.x (beta) - porting notes

Source: jt-librenms 1.2.2 (4.x), rules 131900-131995. Target: Wazuh 5.0.0-rc2, tested with
`tools/pack5_dev.py all jt-librenms` (logtest, test space): **144/144 cases pass** (the 142 4.x
cases, the 4.x sequence case, and the .env case once more in the legacy 4.x-agent FIM shape).

Count: 4.x 74 rules; 51 ported as Sigma rules, 5 as monitors, 4 dropped for ordered correlation
(131947-131949, 131976), 14 below level 3 not ported (131936 is ported but loses its ignore=).

## Layout

- `integration.yml` - category `applications` (LibreNMS is an application; its own events land in
  `wazuh-events-v5-applications`).
- `decoders/` - only for the two LibreNMS outputs Wazuh has no decoder for:
  - `jt-librenms-log` (librenms.log, 25.1+ shape, under `jt-core`), `jt-librenms-legacy` (the
    unknown-user line of 23.x/24.x, under `jt-core`), `jt-librenms-auth` (child of both: user, address,
    back end), `jt-librenms-service` (dispatcher, under `jt-syslog`, program `librenms-service[.py]`).
- `rules/10-jt-librenms-log.yml` - application log and dispatcher (13 rules).
- `rules/20-jt-librenms-web.yml` - web access log (36 rules) over events decoded by the **standard
  apache-http integration** (it takes nginx and Apache combined lines, whatever the location).
- `rules/30-jt-librenms-fim.yml` - file integrity (2 rules) over events decoded by the **standard
  wazuh-fim integration** (5.0 agents and the legacy 4.x FIM shape both decode the same way).
- `detector.yml` - indices `wazuh-events-v5-applications` and `wazuh-events-v5-system-activity`.
- `monitors/jt-librenms.yml` - 5 bucket monitors (131911, 131916, 131943, 131952, 131982).
- Agent side: the 4.x `agent/agent.conf` (librenms.log multi-line collection, FIM on the web root
  and secrets) is used unchanged.

Access-log cases are replayed with `"decode": "standard"` (standard normalization, then this pack's
rules), FIM cases with `queue: 56`, location `syscheck`.

## WCS field choices

- librenms.log: `log.level` (lower case: error, warning, critical, alert ...), `message` (the text
  after the level, trailing blanks removed), `event.dataset` `librenms.log`, `event.module`
  `librenms`, `service.type` `librenms`.
- Unknown-user login: `user.name` (the typed name, may contain brackets), `source.address` and, when
  it is an address, `source.ip`, both read from the **end** of the line (the last ` from <x>`) as in
  4.x, so a typed name cannot plant an address; `event.provider` = authentication back end (mysql,
  ldap, ...), `event.action` `authentication-failure`, `event.outcome` failure,
  `event.category` authentication, `event.reason` "unknown user name".
- Dispatcher: `process.thread.name` (Poller_0-1 ...), `log.level`, `message`, `event.dataset`
  `librenms.service`, `service.name` `librenms-service`.
- Access log (standard decoder): `http.request.method`, `url.original` (path + query), `url.path`,
  `url.query`, `http.response.status_code`, `http.request.referrer`, `source.ip`.

## How the 4.x semantics were kept

- 4.x `url` patterns anchored with `$` (no query string) -> `url.original` exact, or `url.path` plus
  `not url.query|exists`. `|re` never matches on rc2 (tested on `url.original`, anchored and not,
  with `\d` and `[0-9]`), so "exactly one path segment" is a wildcard pair `'/x/*'` and not `'/x/*/*'`
  (`?*` where the segment must be non-empty). Digit-only segments (`\d+`) cannot be required: the
  rules accept any single segment and exclude the known non-numeric routes (`/users/create`,
  `/api-access/create`, `/2fa/add`, `/2fa/cancel`).
- A negated group that itself contains a negation (`not (a and not b)`) never matched on rc2 (131953
  and 131969 produced no finding at all); those exclusions are written with De Morgan
  (`(not a or b)`), after which all cases pass.
- Case-insensitive SQL injection tokens (4.x `(?i:...)`) -> each token in lower case, upper case
  and, for the common words, capitalised. Mixed-case evasions (`UnIoN`) are missed.
- One finding per event: the 4.x parent/sibling precedence is written out as `not` clauses
  (131953 excludes 131954-131959, 131969 excludes 131970/131975, 131904/131905 exclude their
  children, 131933/131934 theirs; 131983 (SQL injection) is excluded from every API, capture and
  419 rule and itself yields to 131986).
- Internal ranges: as 4.x plus `::1/128` (4.x could not list it because of a 4.14 bug, so an IPv6
  loopback login counted as external; `|cidr` handles it in 5.x).

## Login pairs became single events

4.x 131942 (failed web login) and 131945/131946 (successful login) were pairs: `POST /login` 302,
then within 10 s from the same address `GET /login` 200 (failed) or `GET /` / `GET /2fa` 200
(success). 5.0 has no sequence correlation. The browser loads the page it is redirected to with the
Referer of the form post, i.e. the login page, so:

- 131942 = `GET /login` 200 with `http.request.referrer` ending in `/login`;
- 131946 = `GET /` or `/2fa` 200 with that Referer, from outside the private ranges
  (131945, the private-address success, is level 2 and not ported).

A reload of the login page after a failure counts as another failure; a forged Referer only creates
a finding. All 4.x pair cases are tested on their last line.

## Not ported

- Level below 3: 131900-131903, 131906, 131930-131932, 131940, 131941, 131945, 131950, 131959,
  131980 (131980 also needs the nginx error log, which no standard integration decodes on rc2).
- Ordered correlation, no 5.0 equivalent (neither Sigma nor a bucket monitor can say "A, then B
  from the same address"): 131947 / 131948 / 131949 (login success after failures / after a burst)
  and 131976 (GET /about right after a program path was changed - the exploit trigger). Their
  first halves are still reported (131942 and monitor 131943, 131911; 131975 at high). Candidates for
  the upstream correlation rules (wazuh-indexer-security-analytics#119) once they ship.
- `ignore="3600"` on 131936 (flood control): no equivalent; expect one finding per dispatcher
  restart (every 10 s) during a database or Redis outage. A monitor or a notification throttle
  has to do this.
- Groups `authentication_failed` etc. -> tags `jt.auth.failure` / `jt.auth.success` on the login
  rules (for a future jt-account-guard port), no compliance mapping (4.x had none).

## Monitors

Windows are 5 minutes (4.x: 120 s for 131911, 131952, 131982; 180 s for 131943; 300 s for 131916)
with the 4.x counts, so they are a little more sensitive. 131943 counts 131942 findings.

## Overlap with the standard ruleset

The access-log and FIM rules read standard-decoded events; nothing is decoded twice for them.
The dispatcher's syslog lines are also decoded by the standard syslog integration (a second
document in another index); librenms.log lines are decoded only by this pack (the standard space
leaves them unclassified). Standard apache-http rules (4.x 31101, 31103 ...) keep running in their
own detector; 4.x's demotion of 17,146 harmless API 404s (131950) cannot be expressed in 5.x
because standard rules cannot be changed, only their detector disabled.

## Open questions

- Is the Referer kept on the redirect after `POST /login` by every browser LibreNMS users have
  (it is for Chromium and Firefox with the default referrer policy; LibreNMS sends no
  Referrer-Policy header that strips it)? With `no-referrer` both login rules go silent.
- Does a 5.0 agent deliver journald lines of `librenms-service.py` in the syslog shape
  `jt-syslog` reads (the 4.x cases use it)? Not verified with a real 5.0 agent.
