/* ==========================================================================
 * JT Wazuh Agent Manager - Client-side i18n engine
 * Source language is English (as authored in the templates). When the user
 * selects Traditional Chinese (zh-TW), visible text nodes and selected
 * attributes are translated in place using the I18N dictionary below.
 *
 * Design notes:
 *  - Only TEXT NODES and the placeholder/title attributes are translated.
 *    Element `value` attributes and <option value="..."> are never touched,
 *    so form/logic values stay in English.
 *  - Switching language reloads the page so reverting to English is exact
 *    (the server always emits English; we re-translate on load if needed).
 *  - A MutationObserver re-translates content rendered dynamically by the
 *    app's JavaScript (tables, modals, toasts) while in zh-TW mode.
 *  - Strings with interpolated values are handled by I18N_PATTERNS (regex).
 * ======================================================================== */
(function () {
  'use strict';

  var I18N = {
    'zh-TW': {
      // --- App / header / nav ---
      'JT Wazuh Agent Manager': 'JT Wazuh 代理程式管理工具',
      'JT Wazuh Agent Manager - Login': 'JT Wazuh 代理程式管理工具 - 登入',
      'Login with your Wazuh credentials': '請使用您的 Wazuh 帳號登入',
      'Wazuh API Username': 'Wazuh API 使用者名稱',
      'Username': '使用者名稱',
      'Password': '密碼',
      'Login': '登入',
      'Logout': '登出',
      'Settings': '設定',
      'API Host': 'API 主機',
      'API Port': 'API 連接埠',
      'API Connected': 'API 已連線',
      'Connection Lost': '連線中斷',
      'API: ': 'API：',
      // --- Tabs ---
      'Agents': '代理程式',
      'Groups': '群組',
      'Nodes': '節點',
      'Rules': '規則',
      'Statistics': '統計',
      'API Users': 'API 使用者',
      'Logs': '記錄',
      // --- Stat bar ---
      'Total Agents': '代理程式總數',
      'Active': '在線',
      'Disconnected': '已離線',
      'Pending': '等待中',
      'Never Connected': '從未連線',
      'Show all agents': '顯示所有代理程式',
      'Show active agents': '顯示在線代理程式',
      'Show disconnected agents': '顯示已離線代理程式',
      'Show pending agents': '顯示等待中代理程式',
      // --- Agent toolbar / actions ---
      'Search agents...': '搜尋代理程式…',
      'Search rules...': '搜尋規則…',
      'Search': '搜尋',
      'Clear': '清除',
      'Refresh': '重新整理',
      'Refresh agent list': '重新整理代理程式列表',
      'Refresh content': '重新整理內容',
      'Show/Hide Columns': '顯示/隱藏欄位',
      'Export to file': '匯出為檔案',
      'View upgrade progress': '檢視升級進度',
      'Add to Group': '加入群組',
      'Remove from Group': '從群組移除',
      'Move to Node': '移動到節點',
      'Restart': '重新啟動',
      'Reconnect': '重新連線',
      'Upgrade': '升級',
      'Clean Queue DB': '清除 Queue DB',
      'Delete': '刪除',
      'Agent Actions': '代理程式操作',
      'Group Actions': '群組操作',
      'Dry Run': '模擬執行',
      'Preview changes without executing': '預覽變更但不實際執行',
      'Show Queue DB column (loads from filesystem)': '顯示 Queue DB 欄位（由檔案系統載入）',
      'Queue DB': 'Queue DB',
      // --- Table headers ---
      'Actions': '操作',
      'ID': 'ID',
      'Name': '名稱',
      'IP': 'IP',
      'Status': '狀態',
      'Group': '群組',
      'Node': '節點',
      'OS': '作業系統',
      'Version': '版本',
      'Type': '類型',
      'Description': '說明',
      'Level': '等級',
      'Level:': '等級：',
      'File': '檔案',
      'Roles': '角色',
      'Agent Count': '代理程式數量',
      'Group Name': '群組名稱',
      'Rule ID': '規則 ID',
      'Selected:': '已選取：',
      'Allow Run As': '允許 Run As',
      // --- Pagination ---
      'Per page:': '每頁筆數：',
      'Page': '頁',
      'of': '/',
      'First': '第一頁',
      'Last': '最後一頁',
      '‹ Prev': '‹ 上一頁',
      'Next ›': '下一頁 ›',
      '«': '«',
      '»': '»',
      '50/page': '50 筆/頁',
      '100/page': '100 筆/頁',
      '200/page': '200 筆/頁',
      '500/page': '500 筆/頁',
      'Showing 0 - 0 of 0': '顯示 0 - 0，共 0 筆',
      // --- Filters / selects ---
      'All Types': '所有類型',
      'All Files': '所有檔案',
      'All Rules': '所有規則',
      'Min': '最小',
      'Max': '最大',
      // --- Groups panel ---
      'Create Group': '建立群組',
      'Create User': '建立使用者',
      // --- Rules panel ---
      'Hierarchy': '階層',
      'Expand': '展開',
      'Collapse': '收合',
      'Expand All': '全部展開',
      'Collapse All': '全部收合',
      'Add Rule': '新增規則',
      'Enter Rule ID (e.g., 100001)': '輸入規則 ID（例如 100001）',
      'Click "All Rules" to load all rules.': '點選「所有規則」載入全部規則。',
      'Enter a Rule ID to view its hierarchy and relationships.': '輸入規則 ID 以檢視其階層與關聯。',
      'The tree will show parent rules (if_sid, if_matched_sid) and child rules.': '樹狀圖會顯示父規則（if_sid、if_matched_sid）與子規則。',
      // --- Nodes panel ---
      'Services': '服務',
      'Sync': '同步',
      'Sync Status': '同步狀態',
      // --- Logs panel ---
      'Click Refresh to load logs...': '點選重新整理以載入記錄…',
      'Download Full Log': '下載完整記錄',
      'Last 50 lines': '最後 50 行',
      'Last 100 lines': '最後 100 行',
      'Last 200 lines': '最後 200 行',
      'Last 500 lines': '最後 500 行',
      'Last 1000 lines': '最後 1000 行',
      'Log file:': '記錄檔：',
      // --- Export formats ---
      'CSV': 'CSV',
      'JSON': 'JSON',
      'TSV': 'TSV',
      // --- Misc / footer ---
      'Session expired': 'Session 已過期',
      'Built-in': '內建',
      'Custom': '自訂',
      'by': '製作：',
      // (login "Session expires after N minutes" is handled by I18N_PATTERNS)
      // --- JS messages (dynamic, static text portion) ---
      'Loading...': '載入中…',
      'Loading': '載入中',
      'Loading config...': '載入設定中…',
      'Loading email alerts...': '載入電子郵件警示中…',
      'Restarting': '重新啟動中',
      'Restarting...': '重新啟動中…',
      'Services restarting...': '服務重新啟動中…',
      'Services starting...': '服務啟動中…',
      'Waiting for services...': '等待服務中…',
      'Importing agents...': '匯入代理程式中…',
      'Analyzing CSV data...': '分析 CSV 資料中…',
      'Config cannot be empty': '設定不可為空',
      'Config saved! Remember to restart services.': '設定已儲存！記得重新啟動服務。',
      'Group config saved!': '群組設定已儲存！',
      'Edit cancelled': '已取消編輯',
      'Edit mode enabled': '已啟用編輯模式',
      'Email alert rule deleted': '電子郵件警示規則已刪除',
      'Email alert rule saved! Remember to restart services for changes to take effect.': '電子郵件警示規則已儲存！請重新啟動服務以使變更生效。',
      'Download Failed': '下載失敗',
      'Download failed': '下載失敗',
      'Downloaded': '已下載',
      'Download ossec.conf': '下載 ossec.conf',
      'Exported': '已匯出',
      'Failed': '失敗',
      'Failed to load': '載入失敗',
      'Failed to load config': '載入設定失敗',
      'Failed to load email alerts': '載入電子郵件警示失敗',
      'Failed to delete': '刪除失敗',
      'Failed to analyze CSV': '分析 CSV 失敗',
      'Failed to restart services': '重新啟動服務失敗',
      'Reconnect command sent': '已送出重新連線指令',
      'Restart command sent. Node may still be starting up.': '已送出重新啟動指令，節點可能仍在啟動中。',
      'No agents were added': '未加入任何代理程式',
      'No data to import': '沒有可匯入的資料',
      'No valid data rows found in CSV': 'CSV 中找不到有效的資料列',
      'No worker nodes to sync': '沒有可同步的 Worker 節點',
      'Please select a CSV file': '請選擇一個 CSV 檔案',
      'CSV file is empty or has no data rows': 'CSV 檔案為空或沒有資料列',
      'CSV must have at least one of: ID, Name/Hostname, IP/Address columns': 'CSV 至少需包含其中一欄：ID、Name/Hostname、IP/Address',
      'Sync current email alerts config to all worker nodes': '將目前的電子郵件警示設定同步到所有 Worker 節點',
      'Error': '錯誤',
      'Confirm': '確認',
      'Cancel': '取消',
      'Close': '關閉',
      'Save': '儲存',
      'Edit': '編輯',
      'Yes': '是',
      'No': '否',
      'OK': '確定',
      // --- more dynamic toasts / dialogs ---
      'Connection restored': '連線已恢復',
      'Copied to clipboard': '已複製到剪貼簿',
      'Failed to copy to clipboard': '複製到剪貼簿失敗',
      'Deleting...': '刪除中…',
      'Refreshing...': '重新整理中…',
      'Syncing...': '同步中…',
      'Renaming group...': '重新命名群組中…',
      'Loading agent.conf...': '載入 agent.conf 中…',
      'Loading...': '載入中…',
      'Invalid JSON': 'JSON 格式無效',
      'New name is the same as current name': '新名稱與目前名稱相同',
      'No agents in this group': '此群組沒有代理程式',
      'No data to export': '沒有可匯出的資料',
      'Only .wpk files are allowed': '僅允許 .wpk 檔案',
      'Password is required': '密碼為必填',
      'Username is required': '使用者名稱為必填',
      'Password must contain: uppercase, lowercase, number, special char, min 8 chars': '密碼必須包含：大寫、小寫、數字、特殊字元，且至少 8 個字元',
      'Please enter a group name': '請輸入群組名稱',
      'Please enter a new group name': '請輸入新的群組名稱',
      'Please enter a Rule ID': '請輸入規則 ID',
      'Please enter a version number': '請輸入版本號',
      'Please select a target group': '請選擇目標群組',
      'Template downloaded': '範本已下載',
      'Upgrade history cleared': '升級記錄已清除',
      'Session expired. Redirecting to login...': 'Session 已過期，正在導向登入頁…',
      'This feature is still under development': '此功能仍在開發中',
      'Under Development': '開發中',
      // --- modal titles / section headings ---
      'About': '關於',
      'API Connection': 'API 連線',
      'SSH Configuration': 'SSH 設定',
      'Step 1: Generate SSH Key on Master Node': '步驟 1：在 Master 節點產生 SSH 金鑰',
      'Step 2: Copy Public Key to Worker Node': '步驟 2：複製公鑰到 Worker 節點',
      'Step 3: Test SSH Connection': '步驟 3：測試 SSH 連線',
      'Step 4: Configure This Tool': '步驟 4：設定本工具'
    }
  };

  // Patterns for interpolated strings: [regex, function(match)->translated]
  var I18N_PATTERNS = {
    'zh-TW': [
      [/^Expires:\s*(.+)$/, function (m) { return '到期：' + m[1]; }],
      [/^Session expires after\s+(\d+)\s+minutes?$/, function (m) { return 'Session 將於 ' + m[1] + ' 分鐘後過期'; }],
      [/^Showing\s+(\d+)\s*-\s*(\d+)\s+of\s+(\d+)$/, function (m) { return '顯示 ' + m[1] + ' - ' + m[2] + '，共 ' + m[3] + ' 筆'; }],
      [/^Page\s+(\d+)\s+of\s+(\d+)$/, function (m) { return '第 ' + m[1] + ' 頁，共 ' + m[2] + ' 頁'; }],
      [/^(\d+)\s+agents?\s+selected$/, function (m) { return '已選取 ' + m[1] + ' 個代理程式'; }],
      [/^Found\s+(\d+)\s+agents?$/, function (m) { return '找到 ' + m[1] + ' 個代理程式'; }],
      [/^Error:\s*(.+)$/, function (m) { return '錯誤：' + m[1]; }],
      [/^Error loading agents:\s*(.+)$/, function (m) { return '載入代理程式錯誤：' + m[1]; }],
      [/^Successfully synced to\s+(.+)$/, function (m) { return '已成功同步到 ' + m[1]; }],
      [/^Services restarted successfully on\s+(.+)$/, function (m) { return '已成功在 ' + m[1] + ' 重新啟動服務'; }],
      [/^Successfully added\s+(.+)$/, function (m) { return '已成功新增 ' + m[1]; }],
      [/^Starting upgrade for\s+(.+)$/, function (m) { return '開始升級 ' + m[1]; }],
      [/^Upgrade failed:\s*(.+)$/, function (m) { return '升級失敗：' + m[1]; }],
      [/^Upload failed:\s*(.+)$/, function (m) { return '上傳失敗：' + m[1]; }],
      [/^Delete failed:\s*(.+)$/, function (m) { return '刪除失敗：' + m[1]; }],
      [/^Download failed:\s*(.+)$/, function (m) { return '下載失敗：' + m[1]; }],
      [/^Failed to load agents:\s*(.+)$/, function (m) { return '載入代理程式失敗：' + m[1]; }],
      [/^Content refreshed\s*\((.+)\)$/, function (m) { return '內容已重新整理（' + m[1] + '）'; }],
      [/^Sync completed:\s*(.+)$/, function (m) { return '同步完成：' + m[1]; }],
      [/^Downloaded\s+(.+)$/, function (m) { return '已下載 ' + m[1]; }],
      [/^Exported\s+(.+)$/, function (m) { return '已匯出 ' + m[1]; }]
    ]
  };

  var LANG_KEY = 'jtwz_lang';
  var SUPPORTED = ['en', 'zh-TW'];
  var SKIP_TAGS = { SCRIPT: 1, STYLE: 1, TEXTAREA: 1, CODE: 1, PRE: 1, svg: 1, SVG: 1 };

  function getLang() {
    var l = localStorage.getItem(LANG_KEY);
    return SUPPORTED.indexOf(l) >= 0 ? l : 'en';
  }

  function translate(raw, lang) {
    if (!raw) return null;
    var key = raw.trim();
    if (!key) return null;
    var dict = I18N[lang];
    if (dict && Object.prototype.hasOwnProperty.call(dict, key)) {
      var v = dict[key];
      if (v === '') return null; // intentionally skip (handled by pattern)
      return raw.replace(key, v);
    }
    var pats = I18N_PATTERNS[lang] || [];
    for (var i = 0; i < pats.length; i++) {
      var mm = key.match(pats[i][0]);
      if (mm) return raw.replace(key, pats[i][1](mm));
    }
    return null;
  }

  function shouldSkip(node) {
    var p = node.parentNode;
    while (p && p.nodeType === 1) {
      if (SKIP_TAGS[p.tagName]) return true;
      if (p.hasAttribute && p.hasAttribute('data-noi18n')) return true;
      p = p.parentNode;
    }
    return false;
  }

  function translateTextNodes(root, lang) {
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    var batch = [];
    var n;
    while ((n = walker.nextNode())) batch.push(n);
    for (var i = 0; i < batch.length; i++) {
      var node = batch[i];
      if (shouldSkip(node)) continue;
      var t = translate(node.nodeValue, lang);
      if (t !== null && t !== node.nodeValue) node.nodeValue = t;
    }
  }

  function translateAttrs(root, lang) {
    var els = root.nodeType === 1 ? [root] : [];
    var found = (root.querySelectorAll ? root.querySelectorAll('[placeholder],[title]') : []);
    for (var i = 0; i < found.length; i++) els.push(found[i]);
    for (var j = 0; j < els.length; j++) {
      var el = els[j];
      if (!el.getAttribute) continue;
      ['placeholder', 'title'].forEach(function (a) {
        if (el.hasAttribute(a)) {
          var t = translate(el.getAttribute(a), lang);
          if (t !== null) el.setAttribute(a, t);
        }
      });
    }
  }

  function translateTree(root, lang) {
    if (lang === 'en') return;
    translateTextNodes(root, lang);
    translateAttrs(root, lang);
  }

  function setLang(lang) {
    if (SUPPORTED.indexOf(lang) < 0) lang = 'en';
    localStorage.setItem(LANG_KEY, lang);
    location.reload();
  }
  window.jtwzSetLang = setLang;

  function buildToggle() {
    var lang = getLang();
    var btn = document.createElement('button');
    btn.className = 'btn-settings';
    btn.id = 'langToggle';
    btn.type = 'button';
    btn.style.cssText = 'margin-right:6px;';
    btn.textContent = (lang === 'zh-TW') ? 'EN' : '中文';
    btn.title = (lang === 'zh-TW') ? 'Switch to English' : '切換為繁體中文';
    btn.onclick = function () { setLang(lang === 'zh-TW' ? 'en' : 'zh-TW'); };
    var hb = document.querySelector('.header-buttons');
    if (hb) hb.insertBefore(btn, hb.firstChild);
    else { btn.style.cssText += 'position:fixed;top:10px;right:10px;z-index:9999;'; document.body.appendChild(btn); }
  }

  function init() {
    var lang = getLang();
    document.documentElement.setAttribute('lang', lang === 'zh-TW' ? 'zh-TW' : 'en');
    buildToggle();
    if (lang !== 'en') {
      translateTree(document.body, lang);
      var obs = new MutationObserver(function (muts) {
        for (var i = 0; i < muts.length; i++) {
          var added = muts[i].addedNodes;
          for (var j = 0; j < added.length; j++) {
            var node = added[j];
            if (node.nodeType === 1) translateTree(node, lang);
            else if (node.nodeType === 3) {
              if (!shouldSkip(node)) {
                var t = translate(node.nodeValue, lang);
                if (t !== null && t !== node.nodeValue) node.nodeValue = t;
              }
            }
          }
        }
      });
      obs.observe(document.body, { childList: true, subtree: true });
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
