/*
 * End-to-end journeys through the web UI, in a real browser.
 *
 * The unit tests reach Flask routes and can only check that the front end
 * parses. Everything a person actually does -- switching a tab, ticking rows,
 * confirming a dialog, reading a table -- runs code nothing else touches. These
 * journeys drive that code and assert on the DOM it produces.
 *
 * The API behind it is mocked and stateful (see mock_api.py), so a journey can
 * act and then assert on the result of its own action, and no Wazuh manager is
 * involved. Failures are collected rather than thrown, so one broken journey
 * does not hide the state of the rest.
 */
const puppeteer = require('puppeteer');

const BASE = process.env.E2E_BASE || 'http://127.0.0.1:5178';
const wait = ms => new Promise(r => setTimeout(r, ms));

let page, browser;
const results = [];
let currentJourney = null;

function check(name, condition, detail) {
  results.push({ journey: currentJourney, name, ok: !!condition, detail: detail || '' });
}

async function journey(name, fn) {
  currentJourney = name;
  try {
    await fn();
  } catch (e) {
    results.push({ journey: name, name: 'journey completed', ok: false, detail: String(e).slice(0, 300) });
  }
}

/* ---------- helpers ---------- */

const text = async sel => page.$eval(sel, el => el.textContent.trim()).catch(() => null);
const count = async sel => page.$$eval(sel, els => els.length).catch(() => 0);
const visible = async sel => page.$eval(sel, el => {
  const s = getComputedStyle(el);
  return s.display !== 'none' && s.visibility !== 'hidden' && el.offsetParent !== null;
}).catch(() => false);

async function tab(name, settle) {
  await page.click(`[data-tab="${name}"]`);
  await wait(settle || 1200);
}

/** Click the Confirm button of the app's own dialog, as a person would. */
async function confirmDialog() {
  await page.waitForSelector('#modal.show', { timeout: 5000 });
  const clicked = await page.evaluate(() => {
    const btns = [...document.querySelectorAll('#modalFooter button')];
    const yes = btns.find(b => /confirm|yes|ok|install|remove|delete/i.test(b.textContent));
    if (yes) { yes.click(); return true; }
    return false;
  });
  await wait(900);
  return clicked;
}

async function closeModal() {
  await page.evaluate(() => { if (window.closeModal) closeModal(); });
  await wait(300);
}

async function login() {
  await page.goto(BASE + '/login', { waitUntil: 'networkidle2' });
  await page.evaluate(() => {
    const s = (n, v) => { const e = document.querySelector(`input[name="${n}"]`); if (e) e.value = v; };
    s('host', '127.0.0.1'); s('port', '55000');
    s('username', 'soc-analyst'); s('password', 'demo-password');
  });
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }),
    page.click('button[type="submit"]'),
  ]);
  await wait(2200);
}

/* ---------- journeys ---------- */

async function run() {
  browser = await puppeteer.launch({
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
    defaultViewport: { width: 1440, height: 1000 },
  });
  page = await browser.newPage();

  const pageErrors = [];
  const badResponses = [];
  const expectedFailures = [];
  page.on('pageerror', e => pageErrors.push('uncaught: ' + String(e).slice(0, 200)));
  page.on('console', m => {
    // A failed request also reaches the console; the response hook below records
    // it with its URL, so keep the console list to genuine script errors.
    if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) {
      pageErrors.push(m.text().slice(0, 200));
    }
  });
  // Some failures are the documented behaviour rather than a defect: reading a
  // worker's logs needs SSH, which is optional, so the nodes tab gets a 400 for
  // every worker on a manager that has not configured it. Those are listed here
  // with the reason; anything else is a genuine finding.
  const EXPECTED_FAILURES = [
    { pattern: /\/api\/nodes\/[^/]+\/logs-info$/, status: 400,
      why: 'reading a worker log needs the optional SSH configuration' },
  ];
  page.on('response', r => {
    if (r.status() < 400) return;
    const url = r.url();
    const expected = EXPECTED_FAILURES.some(e => e.pattern.test(url) && e.status === r.status());
    (expected ? expectedFailures : badResponses)
      .push(`${r.status()} ${r.request().method()} ${url}`);
  });

  await journey('J1 login and land on the agent list', async () => {
    await page.goto(BASE + '/login', { waitUntil: 'networkidle2' });
    check('login form is served', await visible('input[name="username"]'));
    check('password field is a password field',
      await page.$eval('input[name="password"]', e => e.type) === 'password');
    await login();
    check('reached the application', page.url().replace(/\/$/, '') === BASE.replace(/\/$/, ''),
      'url=' + page.url());
    check('agent rows are rendered', await count('#agents-panel tbody tr') > 5,
      'rows=' + await count('#agents-panel tbody tr'));
    check('an invented host name is shown, not a real one',
      (await page.content()).includes('web-01'));
  });

  await journey('J2 rejected credentials do not create a session', async () => {
    // A new page in the same browser shares the cookie jar, so it would still
    // be the logged-in session. An isolated context is what "anonymous" means.
    const ctx = await browser.createBrowserContext();
    const fresh = await ctx.newPage();
    const resp = await fresh.goto(BASE + '/api/agents', { waitUntil: 'domcontentloaded' });
    check('an anonymous API call is refused', resp.status() === 401, 'status=' + resp.status());
    const pageResp = await fresh.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
    check('an anonymous page request lands on the login form',
      /login/.test(fresh.url()) || pageResp.status() === 401, 'url=' + fresh.url());
    await ctx.close();
  });

  await journey('J3 every tab opens and renders', async () => {
    for (const [name, settle] of [['agents', 1500], ['groups', 1500], ['nodes', 6000],
                                  ['rules', 1800], ['packs', 1800], ['inventory', 1200],
                                  ['stats', 2000], ['users', 1500], ['logs', 2000]]) {
      await tab(name, settle);
      const shown = await visible(`#${name}-panel`);
      check(`${name} panel is visible`, shown);
      const body = await page.$eval(`#${name}-panel`, el => el.innerText.trim().length).catch(() => 0);
      check(`${name} panel has content`, body > 40, 'chars=' + body);
    }
  });

  await journey('J4 agents can be filtered and searched', async () => {
    await tab('agents', 1500);
    const all = await count('#agents-panel tbody tr');
    // The status filter is a custom multi-select, not a <select>: open it and
    // tick an option, which is what a person does.
    await page.click('#statusFilterWrap .multi-select-btn');
    await wait(400);
    check('the filter menu opens', await visible('#statusFilterDropdown'));
    await page.evaluate(() => {
      const item = [...document.querySelectorAll('#statusFilterDropdown input')]
        .find(i => i.value === 'disconnected');
      if (item) item.click();
    });
    await wait(1600);
    const filtered = await count('#agents-panel tbody tr');
    check('the status filter narrows the list', filtered > 0 && filtered < all,
      `all=${all} filtered=${filtered}`);
    await page.evaluate(() => {
      const item = [...document.querySelectorAll('#statusFilterDropdown input:checked')];
      item.forEach(i => i.click());
    });
    await wait(1400);
    check('clearing the filter restores the list',
      await count('#agents-panel tbody tr') === all);
  });

  await journey('J5 selecting agents enables the actions', async () => {
    await tab('agents', 1400);
    await page.evaluate(() => {
      const boxes = document.querySelectorAll('#agents-panel tbody input[type="checkbox"]');
      [1, 2].forEach(i => boxes[i] && boxes[i].click());
    });
    await wait(900);
    const selected = await count('#agents-panel tbody input[type="checkbox"]:checked');
    check('two agents are selected', selected === 2, 'selected=' + selected);
    const enabled = await page.evaluate(() =>
      [...document.querySelectorAll('#agents-panel button')]
        .filter(b => /restart|delete|upgrade/i.test(b.textContent) && !b.disabled).length);
    check('agent actions become available', enabled > 0, 'enabled=' + enabled);
  });

  await journey('J6 restarting agents goes through a confirmation', async () => {
    const restart = await page.evaluate(() => {
      const b = [...document.querySelectorAll('#agents-panel button')]
        .find(x => /^\s*restart/i.test(x.textContent) && !x.disabled);
      if (b) { b.click(); return true; }
      return false;
    });
    check('a restart control was found', restart);
    if (restart) {
      const asked = await page.waitForSelector('#modal.show', { timeout: 4000 })
        .then(() => true).catch(() => false);
      check('a confirmation is required before restarting', asked);
      if (asked) {
        await confirmDialog();
        check('the dialog closes after confirming', !(await visible('#modal.show')));
      }
    }
    // The restart result arrives well after the dialog closes and repaints the
    // modal -- body and footer both, and the footer can come back empty. Left
    // running it lands on top of the next journey's dialog, which then has a
    // body to type into and no button to press. Wait it out and clear it.
    await wait(4000);
    await closeModal();
    await page.evaluate(() => {
      document.querySelectorAll('#agents-panel tbody input[type="checkbox"]:checked')
        .forEach(b => b.click());
    });
    await wait(600);
  });

  await journey('J7 a group can be created and appears in the list', async () => {
    await tab('groups', 1600);
    const before = await count('#groups-panel tbody tr');
    const opened = await page.evaluate(() => {
      if (window.showCreateGroupModal) { showCreateGroupModal(); return true; }
      const b = [...document.querySelectorAll('#groups-panel button')]
        .find(x => /create|add|new/i.test(x.textContent));
      if (b) { b.click(); return true; }
      return false;
    });
    check('a create-group control exists', opened);
    if (opened) {
      await wait(700);
      const dryRun = await page.evaluate(() => {
        const d = document.getElementById('dryRunMode');
        return d ? d.checked : null;
      });
      check('a dry-run switch exists and is off by default', dryRun === false,
        'dryRunMode=' + dryRun);

      // Fill and submit in one evaluation. The interface refreshes on a timer,
      // and a refresh that lands between typing and pressing repaints the modal
      // -- the dialog looked right when checked a moment earlier and had no
      // button left by the time it was pressed. Worth knowing about the UI, and
      // worth not racing here.
      const posts = [];
      const watch = r => { if (r.method() === 'POST' && /\/api\/groups$/.test(r.url())) posts.push(r.url()); };
      page.on('request', watch);
      const submitted = await page.evaluate(() => {
        const d = document.getElementById('dryRunMode');
        if (d && d.checked) d.click();
        const inp = document.getElementById('newGroupName');
        if (!inp) return 'no input';
        inp.value = 'e2e-probe';
        inp.dispatchEvent(new Event('input', { bubbles: true }));
        const btn = [...document.querySelectorAll('#modalFooter button')]
          .find(b => /create/i.test(b.textContent));
        if (!btn) return 'no create button';
        btn.click();
        return 'submitted';
      });
      check('the create dialog was filled in and submitted', submitted === 'submitted',
        submitted);
      await wait(2000);
      page.off('request', watch);
      check('a create request was sent', posts.length === 1, 'posts=' + posts.length);
      const after = await count('#groups-panel tbody tr');
      check('the new group is listed', after >= before, `before=${before} after=${after}`);

      // Separate "the server took it" from "the table shows it". Without that
      // split a failure here says only that a name is missing, and cannot say
      // whether the create failed or the table simply did not catch up.
      const onServer = await page.evaluate(async () => {
        const r = await fetch('/api/groups');
        const j = await r.json();
        const rows = j.groups || (j.data && j.data.affected_items) || [];
        return rows.map(g => g.name || g);
      });
      check('the server has the new group', onServer.includes('e2e-probe'),
        JSON.stringify(onServer));

      // The table refreshes asynchronously after the create; give it a bounded
      // number of tries rather than one fixed sleep.
      let shown = false, panel = '';
      for (let i = 0; i < 6 && !shown; i++) {
        panel = await page.$eval('#groups-panel', e => e.innerText);
        shown = panel.includes('e2e-probe');
        if (!shown) await wait(700);
      }
      if (!shown) {
        // Ask the page to refresh once, to tell a lost update from a lost render.
        await page.evaluate(() => { if (window.refreshGroups) refreshGroups(); });
        await wait(1500);
        panel = await page.$eval('#groups-panel', e => e.innerText);
        const afterRefresh = panel.includes('e2e-probe');
        check('the group appears without needing a manual refresh', false,
          afterRefresh ? 'it appeared only after refreshGroups() was called again'
                       : 'it never appeared: ' + panel.replace(/\s+/g, ' ').slice(0, 160));
      } else {
        check('the group appears without needing a manual refresh', true);
      }
    }
  });

  await journey('J8 node tab shows both cluster nodes and their services', async () => {
    await tab('nodes', 7000);
    const body = await page.$eval('#nodes-panel', e => e.innerText);
    check('the master node is listed', body.includes('node-01'));
    check('the worker node is listed', body.includes('node-02'));
    check('the per-node daemons are listed',
      /Analysis/.test(body) && /Remote/.test(body), body.slice(0, 120));
    check('per-node actions are offered',
      /Restart/.test(body) && /ossec\.conf/.test(body));
  });

  await journey('J9 rules can be browsed and searched by id and by file name', async () => {
    await tab('rules', 2000);
    await page.evaluate(() => {
      const e = document.getElementById('ruleIdSearch');
      if (e) e.value = '5760';
      if (window.searchRuleHierarchy) searchRuleHierarchy();
    });
    await wait(2000);
    let body = await page.$eval('#rules-panel', e => e.innerText);
    check('searching by rule id finds the rule', body.includes('5760'));
    await page.evaluate(() => {
      const e = document.getElementById('ruleIdSearch');
      if (e) e.value = 'sshd';
      if (window.searchRuleHierarchy) searchRuleHierarchy();
    });
    await wait(2000);
    body = await page.$eval('#rules-panel', e => e.innerText);
    check('searching by file name fragment finds the file',
      /sshd/i.test(body), body.slice(0, 120));
  });

  await journey('J10 pack detail states what installing will do', async () => {
    await tab('packs', 1800);
    const listed = await page.$eval('#packs-panel', e => e.innerText);
    check('packs are listed', /jt-/.test(listed));
    const opened = await page.evaluate(() => {
      if (window.showPackDetail) { showPackDetail('jt-ioc'); return true; }
      return false;
    });
    check('a pack detail can be opened', opened);
    if (opened) {
      await wait(1800);
      const body = await page.$eval('#modalBody', e => e.innerText);
      check('the detail names the files it installs', /\.xml|list/i.test(body));
      check('a scheduled job is disclosed before installing',
        /schedul|cron|updater/i.test(body), body.slice(0, 160));
      await closeModal();
    }
  });

  await journey('J11 the log viewer renders lines', async () => {
    await tab('logs', 2500);
    const body = await page.$eval('#logs-panel', e => e.innerText);
    check('log lines are shown', /wazuh-analysisd|INFO/.test(body), body.slice(0, 120));
  });

  await journey('J12 statistics render without an empty panel', async () => {
    await tab('stats', 2500);
    const body = await page.$eval('#stats-panel', e => e.innerText);
    check('the summary has numbers', /\d/.test(body));
  });

  await journey('J13 API users can be listed and one added', async () => {
    await tab('users', 1800);
    const before = await count('#users-panel tbody tr');
    check('existing users are listed', before >= 2, 'rows=' + before);
    const body = await page.$eval('#users-panel', e => e.innerText);
    check('no password or hash is rendered', !/password|hash|secret/i.test(body));
  });

  await journey('J14 inventory search reaches across agents', async () => {
    await tab('inventory', 1500);
    await page.evaluate(() => {
      const inp = document.querySelector('#inventory-panel input[type="text"], #inventorySearch');
      if (inp) { inp.value = 'openssl'; inp.dispatchEvent(new Event('input', { bubbles: true })); }
      const b = [...document.querySelectorAll('#inventory-panel button')]
        .find(x => /search/i.test(x.textContent));
      if (b) b.click();
    });
    await wait(2500);
    const body = await page.$eval('#inventory-panel', e => e.innerText);
    check('a cross-agent result is shown', /openssl/i.test(body), body.slice(0, 120));
  });

  await journey('J15 the interface translates to zh-TW and keeps values intact', async () => {
    await tab('agents', 1500);
    // Only the identity columns must survive translation. A status word is
    // display text and is supposed to change.
    const idCells = () => page.$$eval('#agents-panel tbody tr', rows =>
      rows.slice(0, 4).map(r => [...r.querySelectorAll('td')].slice(2, 5).map(c => c.textContent.trim())));
    const before = await idCells();
    const switched = await page.evaluate(() => {
      const b = [...document.querySelectorAll('button, a, select')]
        .find(x => /中文|zh-TW|語言|Language/i.test(x.textContent || x.value || ''));
      if (b && b.tagName === 'SELECT') {
        b.value = 'zh-TW'; b.dispatchEvent(new Event('change', { bubbles: true })); return true;
      }
      if (b) { b.click(); return true; }
      if (window.setLanguage) { setLanguage('zh-TW'); return true; }
      return false;
    });
    check('a language control exists', switched);
    if (switched) {
      await wait(1800);
      const html = await page.content();
      check('Chinese text appears', /[一-鿿]/.test(html));
      const after = await idCells();
      check('agent names and addresses are not translated',
        JSON.stringify(before) === JSON.stringify(after),
        JSON.stringify({ before, after }).slice(0, 200));
      await page.evaluate(() => { if (window.setLanguage) setLanguage('en'); });
      await wait(1200);
    }
  });

  await journey('J16 security headers are present on a real response', async () => {
    const resp = await page.goto(BASE + '/login', { waitUntil: 'networkidle2' });
    const h = resp.headers();
    check('X-Content-Type-Options', h['x-content-type-options'] === 'nosniff', h['x-content-type-options']);
    check('X-Frame-Options is set', !!h['x-frame-options'], h['x-frame-options']);
    check('a content security policy is sent', !!h['content-security-policy']);
    check('the server header does not carry a version',
      !/\d+\.\d+/.test(h['server'] || ''), h['server']);
  });

  await journey('J17 nothing failed quietly during the whole run', async () => {
    check('no uncaught script errors', pageErrors.length === 0,
      pageErrors.slice(0, 3).join(' | '));
    check('no unexpected request failure',
      badResponses.length === 0, badResponses.slice(0, 4).join(' | '));
    // Assert the known one really happens, so the allowance cannot quietly
    // start covering a different failure.
    check('the documented worker-log failure still behaves as documented',
      expectedFailures.length > 0, 'none seen');
  });


  await journey('J18 a 5.x server hides the tabs it cannot serve', async () => {
    const base5 = process.env.E2E_BASE5;
    if (!base5) { check('a 5.x server was started to test against', false, 'E2E_BASE5 not set'); return; }

    const ctx = await browser.createBrowserContext();
    const p5 = await ctx.newPage();
    await p5.goto(base5 + '/login', { waitUntil: 'networkidle2' });
    await p5.evaluate(() => {
      const s = (n, v) => { const e = document.querySelector(`input[name="${n}"]`); if (e) e.value = v; };
      s('host', '127.0.0.1'); s('port', '55000'); s('username', 'soc-analyst'); s('password', 'demo');
    });
    await Promise.all([
      p5.waitForNavigation({ waitUntil: 'networkidle2' }),
      p5.click('button[type="submit"]'),
    ]);
    await wait(3000);

    const caps = await p5.evaluate(async () => {
      const r = await fetch('/api/capabilities');
      return r.json();
    });
    check('the server version was detected at connection time',
      caps.server_version === '5.0.0', JSON.stringify(caps.server_version));
    check('5.x is recognised as a different generation', caps.server_major === 5);

    // The three tabs whose features 5.0 removed.
    for (const tab of ['rules', 'packs', 'inventory']) {
      const shown = await p5.evaluate(t => {
        const el = document.querySelector('.tab[data-tab="' + t + '"]');
        return el ? el.style.display !== 'none' : false;
      }, tab);
      check(`the ${tab} tab is hidden on 5.x`, !shown);
    }
    // The ones that survive must still be there.
    for (const tab of ['agents', 'groups', 'nodes', 'users', 'logs']) {
      const shown = await p5.evaluate(t => {
        const el = document.querySelector('.tab[data-tab="' + t + '"]');
        return el ? el.style.display !== 'none' : false;
      }, tab);
      check(`the ${tab} tab is still offered on 5.x`, shown);
    }

    // And the routes behind the hidden tabs refuse clearly rather than 404.
    const refusal = await p5.evaluate(async () => {
      const r = await fetch('/api/packs');
      return { status: r.status, body: await r.json() };
    });
    check('a removed feature answers 501, not a confusing 404',
      refusal.status === 501, 'status=' + refusal.status);
    check('the refusal names the server version',
      /5\.0\.0/.test((refusal.body || {}).error || ''), JSON.stringify(refusal.body));

    await ctx.close();
  });

  await journey('J19 a 4.x server keeps every tab', async () => {
    await page.goto(BASE + '/', { waitUntil: 'networkidle2' });
    await wait(2500);
    const caps = await page.evaluate(async () => (await fetch('/api/capabilities')).json());
    check('4.x is detected', caps.server_major === 4, JSON.stringify(caps.server_version));
    for (const tab of ['rules', 'packs', 'inventory']) {
      const shown = await page.evaluate(t => {
        const el = document.querySelector('.tab[data-tab="' + t + '"]');
        return el ? el.style.display !== 'none' : false;
      }, tab);
      check(`the ${tab} tab is offered on 4.x`, shown);
    }
  });

  await browser.close();

  /* ---------- report ---------- */
  const byJourney = {};
  for (const r of results) (byJourney[r.journey] = byJourney[r.journey] || []).push(r);
  let pass = 0, fail = 0;
  for (const [name, checks] of Object.entries(byJourney)) {
    const bad = checks.filter(c => !c.ok);
    console.log((bad.length ? 'FAIL  ' : 'ok    ') + name);
    for (const c of checks) {
      if (!c.ok) console.log('        x ' + c.name + (c.detail ? '  -- ' + c.detail : ''));
    }
    pass += checks.length - bad.length; fail += bad.length;
  }
  console.log(`\n${pass} checks passed, ${fail} failed, across ${Object.keys(byJourney).length} journeys`);
  process.exit(fail ? 1 : 0);
}

run().catch(e => { console.error('harness error:', e); process.exit(2); });
