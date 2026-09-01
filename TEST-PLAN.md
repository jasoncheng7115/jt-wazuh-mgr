# Test Plan

[English](TEST-PLAN.md) | [繁體中文](TEST-PLAN-zh-TW.md)

What gets verified before a release, at which layer, and — as honestly as it can
be stated — what still is not verified at all.

The plan is layered because the layers catch different mistakes. The automated
suite catches a guard that stopped guarding. The mechanical checks catch a
version badge nobody updated. The scan catches a header that went missing. The
browser checklist catches the things that only exist once a person is looking at
the screen. None of them substitutes for another.

---

## Running everything

```bash
python3 -m unittest discover -s tests     # 146 tests, fully offline
python3 tools/preflight.py                # 11 mechanical pre-release checks

# on a host without a system Flask
python3 -m pip install --no-index --find-links=offline_packages \
        --target=/tmp/vendor flask requests pyyaml
PYTHONPATH=/tmp/vendor python3 -m unittest discover -s tests
```

The suite needs no Wazuh manager: the API layer is mocked and the ruleset
directories are synthetic.

---

## Layer 1 — automated suite

`tests/test_web_ui.py` covers the read paths and the security properties.
`tests/test_ui_operations.py` covers the routes that change something.

| Area | What is asserted |
|---|---|
| Authentication | Every route in the app's `url_map` is checked for an anonymous caller. Derived from the map, not a hand-written list, so a route added later is covered without anyone remembering. Session expiry returns `session_expired`. |
| Security headers | CSP, `X-Content-Type-Options`, `X-Frame-Options`, referrer policy, no version in `Server`. |
| Supply chain | Every CDN `<script>` and `<link>` carries an SRI hash. |
| CSRF | The login form issues and requires a token. |
| Reflected XSS | Values echoed into the template are escaped. |
| Input validation | Agent IDs, group names, node names, filenames, active-response commands and arguments. Includes `..` as a name, shell metacharacters, over-length values. |
| Destructive routes | Queue DB cleaning, group membership changes and upgrade-file deletion are exercised **along the rejection path only**. A string where a list belongs must not be iterated per character. |
| Path confinement | Group file reads, node file downloads (keyword, never a path), WPK deletion, and pack manifest destinations. |
| Configuration editing | Empty, oversized and malformed bodies are refused; an XML external entity is not resolved. |
| Rules | Hierarchy, listing, content search, filename search, malformed rule files that ElementTree cannot parse. |
| Decoders, CDB lists | Listing, reading, and the CDB write path. |
| Logtest | Request shape and response parsing. |
| Inventory | Cross-agent package search. |
| Cluster | Ruleset reload across nodes; node config diff. CDB list declaration reaching every node: the declaration text itself, the peer write path, a node that accepts a write without applying it, a redundant declaration writing nothing twice, abort-and-roll-back when a node cannot be reached, and the `local_only` override. |
| Packs | Manifest integrity, SHA-256 of every shipped file, rule ID uniqueness, `dest` paths, `packs/INDEX` consistency, script/cron/agent-group installation, and that no pack contains an internal host or address. |
| Front end | The template's JavaScript parses under `node --check`. The i18n dictionary is embedded and internally consistent. |
| Version comparison | The agent-version comparator, including the pre-release cases. |

**Why the destructive routes are only tested along the rejection path.** Several
of them shell out or delete files once validation passes. A test that drove them
to success would act on whatever machine ran the suite — and on this project that
machine is usually a live Wazuh manager. The guard is the part worth asserting;
the part after the guard is verified by hand, on purpose, in Layer 5.

---

## Layer 2 — mechanical pre-release checks

`tools/preflight.py`, all of which must pass:

1. Version and badges agree with `lib/__init__.py`
2. Both changelogs carry an entry for this version
3. `github/` mirrors the working tree
4. No internal host name, address or mail account appears in anything published
5. Pack manifests: hashes, rule IDs, `dest` paths, descriptions
6. `packs/INDEX` matches the files on disk
7. The i18n dictionary embedded in `web_ui.py` is current
8. The template's JavaScript parses
9. Every screenshot the READMEs reference exists
10. No shipped CDB list is still a placeholder
11. Publishing hygiene — no `wazuh-rules/`, no stray archives, no secrets

Check 10 exists because a level 15 rule once shipped pointing at a list holding a
single fabricated hash. It could never fire, and nothing said so.

---

## Layer 3 — security scan

```bash
PYTHONPATH=/tmp/vendor python3 wazuh_agent_mgr.py --web --host 127.0.0.1 --port 5099 &
docker run --rm --network host -v /tmp/zap:/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://127.0.0.1:5099 -J zap-report.json -I
```

Baseline: **0 FAIL / 8 WARN / 59 PASS**. Compare plugin by plugin, not just the
totals — the same count can hide a swap. Any new finding blocks the release.

The one Medium that remains is `unsafe-inline` in the CSP for scripts and styles,
because the whole front end is inline inside a Python string. Removing it means
restructuring the template, which is not a release-time change.

---

## Layer 4 — browser journeys, automated

```bash
tests/e2e/run.sh          # 17 journeys, 65 checks, needs docker
```

`tests/e2e/mock_api.py` serves the real application against a mocked, stateful
Wazuh API, so a journey can act and then assert on the result of its own action.
It starts the app the way production does — `app.run()` alone skips the header
hardening, and the tests would then be measuring a different program. It never
reads the real ruleset: the rules endpoints have their paths hardcoded to
`/var/ossec`, and the machine running these tests is usually a live manager.

`tests/e2e/journeys.js` drives a real browser: login and refusal of anonymous
callers, every tab rendering, filtering through the custom multi-select,
selecting agents, a confirmation dialog, creating a group and seeing it appear,
both cluster nodes with their daemons, rule search by id and by file name, pack
detail disclosing its scheduled job, logs, statistics, users with no credential
on screen, inventory search, translation to zh-TW leaving names and addresses
alone, security headers on a real response, and a final check that nothing
failed quietly — uncaught errors and failed requests both, with an allowance for
the one documented failure (reading a worker log needs the optional SSH setup)
that must still be present.

One thing the journeys had to work around is worth stating: the interface
refreshes on a timer, and a refresh landing between typing into a dialog and
pressing its button repaints the modal. The dialog checked out a moment earlier
and had no button left by the time it was pressed.

## Layer 4b — browser checklist, by hand

The automated suite drives Flask routes, not the DOM. Everything below needs a
person and a browser. Run against a manager with at least one agent, in both
languages, since the translation layer rewrites text nodes after render.

**Login** — token expiry hint shown; session countdown appears and decrements;
expiry returns to the login form without a stack trace; wrong credentials fail
cleanly.

**Agents** — list loads; filter by status, OS and group; search; select one, many,
all; restart; delete (both confirmations); upgrade to latest, to a chosen version,
and from an uploaded WPK; upgrade result reporting; agent detail; agent key;
runtime config; queue DB size and clean; active-response command.

**Groups** — create; delete; add and remove agents; remove all; move between
groups; exclusive assignment; view, edit, download and import configuration; file
list.

**Nodes** — list and status; daemon statistics; restart services; reconnect;
reload ruleset; view, edit, validate and download configuration; email alert
settings; upgrade files list, upload and delete; sync status and detail; logs.

**Rules** — all five modes: hierarchy, all rules, decoders, CDB lists, log test.
Search by content and by file name, including a partial name and a name with its
extension. View a file; delete a rule; create, edit and delete a CDB list.

**Packs** — list; detail showing files, scripts, scheduled jobs, agent group and
any node the CDB list could not be declared on;
install; install into a rule ID conflict, then force; remove, confirming replaced
files come back; remove a pack whose files were edited after installation, which
must be refused.

**Inventory** — cross-agent package search.

**Statistics** — summary and report.

**API users** — list; create; delete; change roles.

**Logs** — view, filter, download.

**Both languages** — switch to zh-TW on every tab. Watch for English left behind
in JavaScript-generated content, and for over-eager translation of a word that
should have stayed English. `value` and `<option value>` must never change.

**Offline** — with no route to cdnjs, the configuration editor loses syntax
highlighting but must still load, edit and save.

---

## Layer 5 — deployment

1. Deploy, then read the version back **from the target path itself**. A tar
   extracted without `-C` lands somewhere else, and a version check that reads
   the wrong copy reports success twice.
2. Restart the service and confirm it comes up.
3. On a cluster: sync rules to the worker, reload both nodes, and verify on the
   worker as well. The cluster synchronises `etc/rules` and `etc/lists` but not
   `ossec.conf`, and it does not reload a worker's analysisd.
4. `wazuh-analysisd -t` must be clean, with no new warnings.
5. Confirm a rule that should fire still fires. A list rename or a moved file
   stops nothing: the rule loads and simply never matches. Read the reload
   response — analysisd names the list it could not load and the rule it will
   ignore, as a warning on a reload that otherwise reports success.

---

## What is not covered

Stated plainly, because a test plan that implies more coverage than exists is
worse than a short one.

- **No DOM-level automation.** The front end is checked for parse validity and
  translation consistency only. Every interaction in Layer 4 is manual. The
  screenshot harness renders real pages against a mocked API and would be the
  natural place to grow into this.
- **The success paths of destructive routes are not exercised in CI**, for the
  reason given in Layer 1.
- **No load or concurrency testing.** Behaviour with thousands of agents, or with
  two operators editing one configuration, is unmeasured.
- **No upgrade testing across versions.** Installing over an older release is
  verified by hand.
- **The packs' detection rules are not tested against sample logs in CI.** They
  are verified with `wazuh-logtest` on a manager, by hand, per scenario. Sibling
  rules under one parent evaluate in an unpredictable order, so a rule that
  passes in isolation can still be shadowed in place.
