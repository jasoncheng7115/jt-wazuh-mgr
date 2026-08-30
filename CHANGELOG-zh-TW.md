# 更新記錄

本檔案記錄 **JT Wazuh Manager** 的所有重要變更。

[English](CHANGELOG.md) | [繁體中文](CHANGELOG-zh-TW.md)

## v1.6.4（2026-08-30）

- **套件現在會說明自己需要什麼前提才會運作。** 有幾條隨附規則其實永遠不會觸發，
  卻沒有任何地方寫明：906121 / 906122 需要 Sysmon 事件 ID 15，
  906142 與 100990 比對的 CDB 清單隨附時只有一行佔位符，906120 需要 syscheck 監控 `C:\Users`。
  儀表板上顯示這些規則已安裝，看起來像有防護，實際上是空的。各 manifest 現在都標明了前提條件。

- **套件說明會依讀者語言顯示。** 詳細面板原本只讀 `notes_zh`，英文使用者看到的是中文或空白。
  現在每個 manifest 都另外帶有英文 `notes`，面板會依目前介面語言選擇。

- **Zenarmor：寄放網域降為 level 0。** 這個分類實測誤判極為嚴重 ——
  單一用戶端一天產生約 2,900 筆，佔本套件全部告警量的 88%，
  全部指向一個 CDN 前置的 App 後端，只因為它的 apex 網域沒有 A 記錄。
  真正的 DGA 活動已由 Zenarmor 自己的 Botnet DGA Domains 標籤涵蓋，不會漏掉。

## v1.6.3（2026-08-30）

- **所有套件的規則描述改為英文。** 隨附的 179 條規則中有 128 條以繁體中文描述自己，
  這讓告警文字在作者自己的主控台之外難以閱讀 —— 而這些套件是公開發佈供一般使用的。
  現在描述全為英文，`$(欄位)` 變數與 `[CRITICAL]` / `[HIGH]` / `[WARN]` 前綴維持不變，
  既有的儀表板與下游解析程式不受影響。

  標點一律改為半形，先前混入的全形冒號與破折號已清除。

- 套件版本隨之更新：jt-zimbra 2.1、jt-portable-detect 1.3、jt-zenarmor 1.2。
  各 manifest 的 `name_zh` / `summary_zh` / `notes_zh` 不受影響 ——
  那些是刻意保留的雙語欄位，介面上仍會顯示中文的套件名稱與注意事項。

## v1.6.2（2026-08-30）

- **Zenarmor 套件依實際流量重做。** 第一版所有分類都靠 `security_tags`，
  實測發現這樣會漏掉真正的訊號：Zenarmor 的 `security_tags` 與 `category`
  是**互斥出現**的（有其一時另一個為 null），因此有一半的風險事件掉進
  level 0、完全不告警。現在兩個欄位都會比對。

  內容分類被明確定位成弱訊號：Proxy 為 level 5、Parked Domains 為 level 3，
  因為 `is_blocked` 多半只代表上網政策封鎖而非威脅。真正的威脅標籤維持原本分級，
  並新增一條關聯規則，用來抓「連線一直被擋、卻仍持續重試」的主機。

- 標籤比對的短詞一律加上 `\b` 邊界。少了它，`Tor` 在不分大小寫的情況下會誤中
  `Torrent`，把一般 P2P 流量報成使用匿名代理。

## v1.6.1（2026-08-30）

- **新增套件：Zenarmor（OPNsense）。** 針對以 syslog 轉送進來的 Zenarmor NGFW 事件，
  提供解碼器與分級規則，使用規則 ID 130800-130899。

  告警等級同時依「威脅分類」與「防火牆是否真的擋下」決定，並刻意讓
  **未被阻擋的惡意連線比已阻擋的更嚴重** —— 沒擋下代表連線已經成立，
  該主機可能已經被入侵。惡意程式、Botnet、C2、勒索軟體若未被阻擋為 level 12，
  已阻擋則為 level 7；釣魚、挖礦、DGA 分別為 10 與 5；駭客工具、代理、Tor
  與已遭入侵主機為 7。同一台內部主機五分鐘內出現六次未被阻擋的惡意連線，
  升為 level 13。

  本套件刻意**不提供 catch-all 規則**：無安全分類的一般連線停在 level 0 不告警，
  正常上網不會灌爆主控台。例行的政策阻擋記錄建議直接看 Zenarmor 自己的報表，
  不必重複灌進 Wazuh。

- 套件現在可以包含解碼器，與規則、清單享有相同的備份、驗證與回滾流程，
  安裝至 `etc/decoders/`。
- 隨附的套件目錄納入測試：manifest 雜湊、安裝路徑、XML 合法性、
  跨套件規則 ID 不重複、`INDEX` 一致性都會驗證。改了規則卻忘記更新 manifest 雜湊，
  會在測試階段就失敗，而不是等到移除套件時才發現。

## v1.6.0（2026-08-30）

- **新增「規則套件」分頁。** Jason Tools 維護的偵測規則系列目錄。它被設計成**套件管理員**
  而非「規則」分頁的另一個唯讀檢視 —— 安裝與移除是有狀態的生命週期操作，
  與規則檢視的用途不同，因此獨立成一個分頁。

  每個套件以 manifest 打包規則、解碼器與 CDB 清單。點入可看到它會安裝哪些檔案、
  裝到哪裡、佔用哪些規則 ID，以及生效所需的注意事項。安裝流程刻意保守：
  會偵測與既有規則的 ID 衝突並拒絕安裝（除非強制），所有將被覆蓋的檔案先備份，
  安裝後以 `wazuh-analysisd -t` 驗證規則集，**任何一步失敗就整包回滾** ——
  檔案與清單宣告一併還原，不會留下半套狀態。

  移除時會還原被該套件覆蓋的原檔。若你安裝後修改過其中的檔案，移除會先停下來
  告訴你是哪些，而不是默默刪掉你的修改。

  首批四個套件：可攜式程式偵測（Windows/Linux/macOS）、IP 威脅情資、
  惡意程式雜湊比對、Zimbra 偵測套組。

- 套件路徑改為讀取 `config.yaml` 的 `wazuh_path`，不再假設 `/var/ossec`。
- `install.sh` 會一併下載套件目錄。

## v1.5.2（2026-08-29）

- **節點設定漂移偵測。** `ossec.conf` 正好是 Wazuh 叢集**不會**同步的東西，
  因此 worker 可能悄悄少了某個 `<list>` 宣告，於是所有用到該清單的規則全被忽略 ——
  而 Wazuh 本身沒有任何機制會提醒這件事。新增 `GET /api/nodes/config-diff`，
  透過 API 讀取各節點設定，就「真正影響偵測」的區段
  （`ruleset`、`wodle`、`syscheck`、`rootcheck`、`localfile`、`active-response`、`command`）
  與 master 比對，列出節點上缺少的項目與僅該節點才有的項目。
  「節點」分頁新增 **設定差異** 按鈕。
  比對是語意層級而非純文字，因此註解與排版差異不會造成雜訊。
  在正式叢集上實測，立刻找出四處真實落差，包括 worker 完全缺少主動回應指令、
  以及 FIM 未啟用 `realtime`。

## v1.5.1（2026-08-29）

- **在「規則」分頁一鍵重新載入整個叢集的規則集。** 在 master 改規則後，worker 並不會
  自動生效：叢集只同步檔案，每個節點的 `analysisd` 仍使用自己記憶體中的舊規則，
  直到被明確要求重載。因此修好的規則可能看起來已生效，實際上真正處理那些 agent 的
  節點還在跑舊規則 —— 這正是正式環境發生過的事：一條已修正的規則因為只有 master
  重載過，在 worker 上又持續誤報了四個小時。
  新增 `POST /api/cluster/reload-ruleset`，一次重載所有節點
  （`PUT /cluster/analysisd/reload` 不帶 `nodes_list`），單機環境則自動改用
  `PUT /manager/analysisd/reload`，並逐節點回報結果與規則集警告。
  已直接對 `analysisd` 驗證：這是熱重載，程序不會重新啟動。

## v1.5.0（2026-08-26）

盤點 Wazuh 4.14.7 API 全部 150 個 endpoint 後，補上 11 項 Dashboard 缺少或藏太深的能力。

**新增「資產清單」分頁**
- `GET /api/inventory/search` 會平行查詢所有代理程式的同一個 syscollector 類別，
  彙整成單一表格：套件、開放連接埠、處理程序、服務、本機使用者、修補程式、
  網路介面、作業系統、瀏覽器擴充功能。可直接回答「哪些機器裝了這個套件 /
  開著這個連接埠」——這是 Dashboard 逐台檢視做不到的。結果可匯出 CSV。

**「規則」分頁升級為規則集工作台**
- **記錄測試** —— 貼上一行 log，看到命中的規則與解碼器、擷取到的欄位，
  以及 analysisd 的訊息（`PUT /logtest`）。
- **解碼器** —— 瀏覽、搜尋解碼器並檢視其 XML。
- **CDB 清單** —— 列出、新增、編輯、刪除 CDB 清單。

**更安全的設定變更**
- **驗證** —— 重新啟動節點前先檢查 `ossec.conf` 是否有效。
- **重新載入規則集** —— 套用規則變更而不必重新啟動 Manager。

**代理程式**
- **自訂 WPK 升級** —— 使用 Manager 上既有的 WPK 檔升級，這是離線環境唯一可行的方式。
- **主動回應** —— 對選取的代理程式下達指令。
- **註冊代理程式** —— 依名稱預先註冊並取回 ID 與金鑰。
- **生效中的設定** —— 代理程式實際套用的設定，可確認群組 `agent.conf` 是否真的生效。
- **代理程式金鑰** —— 取回註冊金鑰，用於重新註冊故障的代理程式。

**節點 / 群組**
- **健康狀態** —— 各節點的 analysisd / remoted / wazuh-db 計數。
- **檔案** —— 瀏覽並檢視群組目錄下的所有檔案，不再侷限於 agent.conf。

**其他**
- 新增 127 個繁體中文字典項目與 57 條規則式，涵蓋以上所有功能。
- 測試套件擴充至 85 項。
- OWASP ZAP baseline 與 1.4.3 相同：0 failure、8 warning、59 pass。

## v1.4.3（2026-08-26）

**資安強化**（已用 OWASP ZAP baseline 掃描驗證：警告從 12 降至 8、0 個 failure；
剩下的 Medium 是架構上無法避免的 CSP `unsafe-inline`）：

- 所有回應都加上**安全標頭**：`Content-Security-Policy`、`X-Content-Type-Options`、
  `X-Frame-Options: DENY`、`Referrer-Policy`、`Permissions-Policy`、
  `Cross-Origin-Opener-Policy`、`Cross-Origin-Resource-Policy`、
  `Cache-Control: no-store`，以及 HTTPS 模式下的 HSTS。
- 為 cdnjs 載入的 CodeMirror 資源加上 **Subresource Integrity**。原本沒有任何完整性
  驗證，若 CDN 回應遭竄改，就會在持有 Wazuh API token 的管理介面中執行任意 JavaScript。
- **登入表單加上 CSRF token**。JSON API 有 `SameSite=Lax` 保護，但登入表單原本沒有。
- **WSGI 伺服器不再於 `Server` 標頭洩漏版本資訊**。

**規則分頁**

- **新增：對所有規則的完整 XML 做關鍵字搜尋**（`GET /api/rules/search`），
  支援以空白分隔的多個關鍵字，並可選擇全部符合或任一符合。原本的表格篩選只看得到
  id/level/description/file/groups，因此 `<field>`、`<regex>`、`<decoded_as>`、
  `<options>` 裡的字串完全搜不到。由於改用原始文字比對，連 XML 解析失敗的檔案裡的
  規則也找得到。
- **修正：階層檢視無法捲動。** 該區塊本身沒有任何尺寸樣式，導致
  `.rules-content` 的 `flex:1; overflow:auto` 完全失效，較長的規則樹會被面板切掉
  且沒有捲軸。

**代理程式分頁**

- **新增：「離開選取」按鈕**，位於已選取數量旁，可一次清除批次選取，
  不必逐列取消勾選。

**翻譯**

- 大幅補齊繁體中文：以全模板掃描比對所有使用者可見字串與字典後補上缺口，
  包含完整的代理程式升級流程（對話框、選項、進度表格、狀態值、統計數字）、
  各種確認對話框，以及帶有變數的視窗標題。新增 40 多個字典項目與 38 條規則式，
  也包含你回報的「Found N related rules」。
- 調整「升級至 Manager 版本」標籤結構，讓其文字節點不再夾帶結尾的 `(`
  ——原本因此無法翻譯。

**測試**

- **專案現在有測試套件了**（`tests/test_web_ui.py`，46 項測試）：
  以 `python3 -m unittest discover -s tests` 執行。完全離線運作
  （Wazuh API 以 mock 取代、ruleset 為模擬資料），涵蓋認證、請求驗證、
  規則相關端點、安全標頭、CSRF、反射型 XSS 的轉義、SRI、版本比較器與翻譯一致性。

## v1.4.2（2026-08-24）

- **「規則」分頁會回報無法解析的規則檔。** `parse_rule_file()` 原本會吞掉 XML 錯誤，
  導致格式有誤的檔案中的規則在分頁裡直接消失，而且完全沒有任何提示。
  `GET /api/rules` 現在會回傳 `parse_errors` 清單，分頁上會顯示警告，
  點擊後可看到每個檔案與解析器的錯誤原因。
  （Wazuh 4.14.7 本身就有一個這樣的檔案：`0910-ms-exchange-proxylogon_rules.xml`，
  其 `pcre2` 正規表示式含有 `\<` 與 `\>`，ElementTree 在第 57 行拒絕解析，
  使該檔的規則被隱藏。）解析失敗的記錄層級也從 DEBUG 提升為 WARNING。

## v1.4.1（2026-08-24）

維護版本。已對 **Wazuh 4.14.7** 完整驗證 —— 不需要任何 API 或 CLI 的配合修改，
本工具用到的每個 endpoint 與路徑在該版本都存在且未被標記為 deprecated。

- **修正：規則階層會讓「規則」分頁當機。** `find_children()` 遞迴時沒有深度限制，
  遇到較長的 `if_group` / `if_sid` 鏈會拋出
  `RecursionError: maximum recursion depth exceeded`，請求以 500 失敗。
  現已限制遞迴深度（截斷時會寫入記錄）。
- **修正：沒有 JSON body 的請求會回 500。** 當呼叫端未帶 body 或 `Content-Type`
  不是 JSON 時，`request.get_json()` 會拋出 werkzeug 的 `BadRequest`，
  而各路由的通用例外處理把它回報成伺服器錯誤。20 個路由改用
  `get_json(silent=True)`。
- **新增：代理程式批次操作的輸入驗證。** `restart`、`reconnect`、`delete`、
  `upgrade` 現在會拒絕缺少或空的 `agent_ids`，並驗證每個 ID，
  不再帶著空清單去呼叫 Wazuh API。
- **新增：`POST /api/groups` 會驗證群組名稱**（`DELETE` 路由原本就有），
  名稱格式錯誤或缺少時回 400，而不是真的建出一個叫 `None` 的群組。
- **修正：版本比較函式被定義了三次**，而且實際生效的版本與最先寫的那個行為不同。
  已整併為單一的數值比較器，`4.14.7` 會正確排在 `4.9.0` 之上。
- **移除無效程式碼：** 取得角色清單時的 `wazuh-user` CLI 備援
  （Wazuh 並沒有這支執行檔，RBAC 僅能透過 API 管理），以及五個未使用的 import。
- 為新增的驗證訊息補上繁體中文翻譯。

## v1.4.0（2026-06-11）
- **雙語介面（English / 繁體中文）**：標題列一鍵切換語言，偏好依瀏覽器記住。翻譯完全在前端套用（文字節點 + `placeholder`／`title`），並以 `MutationObserver` 讓動態產生的內容也持續翻譯。UI 字串集中於 `lib/i18n_engine.js`，由 `tools/build_i18n.py` 內嵌進 `lib/web_ui.py`。
- **獨立倉庫**：專案由 `jt_wazuh_agent_mgr` 更名為 **`jt-wazuh-mgr`**，並獨立為 `jasoncheng7115/jt-wazuh-mgr`。安裝路徑改為 `/opt/jt-wazuh-mgr`，systemd 服務改為 `jt-wazuh-mgr`。
- **一行安裝／升級／移除**：強化 `install.sh`（可重複執行的更新模式），並新增 `uninstall.sh` 以完整移除。
- **授權**：改採 **Apache-2.0**。

## v1.3.136（2026-03-18）
- **瀏覽所有規則**：規則分頁新增「All Rules」模式
  - 可排序、分頁的規則表格（內建 + 自訂）
  - 可搜尋規則 ID、等級、說明、檔案與群組
  - 篩選：等級範圍（最小／最大）、檔案、類型（自訂／內建）
  - 點選任一規則 ID 跳至階層檢視
  - 新增 API 端點 `GET /api/rules`

## v1.3.135（2026-02-25）
- **電子郵件警示儲存驗證**：儲存前先驗證規則 ID、群組與等級確實存在於 Wazuh ruleset
- **多組 ossec_config 支援**：修正含多個 `<ossec_config>` 區段（Worker 節點常見）時的警示同步

## v1.3.134（2026-02-24）
- **電子郵件警示視覺化管理**：以表單管理 Master 節點 ossec.conf 中的 `<email_alerts>` 規則
- **同步到所有 Worker**：一鍵將電子郵件警示設定同步到所有 Worker 節點（自動備份）
- 僅修改 `<email_alerts>` 區塊，其餘設定內容、註解與格式皆保留

## v1.3.133（2026-02-23）
- **延長 Web Session**：Session 逾時預設改為 2 小時（可由 `web.session_timeout` 設定）
- **JWT Token 自動續期**：到期前自動重新認證，Session 期間免重新登入
- **設定頁 SSH 設定指南**：快速存取 SSH 設定教學

## v1.3.131（2026-02-22）
- **批次清除 Queue DB**：選取 Agent 後批次刪除 queue DB 檔並自動重啟 Agent
- **精準節點定位**：僅連線到實際擁有 queue DB 檔的節點
- **詳細結果顯示**：以對話框顯示各 Agent、各節點的刪除結果與重啟狀態
- **安裝腳本改進**：安裝時自動建立並啟動 systemd 服務、更新時自動重啟、`install.sh` 自我更新

## v1.3.10x（2026-01-04）
- **分布圖**：Agent 列表上方新增視覺化統計長條（狀態／作業系統／版本／群組／節點／同步狀態），可點選區段快速篩選，含左至右與滑入動畫
- **統計自動重新整理**：上方統計每 10 秒自動更新
- 多項分布圖樣式、對齊與動畫修正

## v1.3.3x（2026-01-02）
- **新增規則分頁**：規則階層檢視器 — 可搜尋規則 ID、父子關係（`if_sid`、`if_matched_sid`）、可收合樹狀圖、XML 語法上色、全部展開／收合
- 支援內建（`/var/ossec/ruleset/rules/`）與自訂規則（`/var/ossec/etc/rules/`）

## v1.3.2x（2025-01-01）
- **安全強化**：輸入驗證器（`validate_node_name`、`validate_agent_id`、`validate_group_name`、`validate_username`）、路徑白名單（`validate_path`、`ALLOWED_PATHS`）、Shell 參數跳脫（`safe_shell_arg` / `shlex.quote`）、記錄淨化、上傳採用 `secure_filename()`、以 `ALLOWED_SYNC_ITEMS` 白名單防範路徑穿越
- **統計欄位可排序**與語意化版本排序
- **同步狀態**樣式與載入指示；**Favicon** 與 `/images/` 靜態路由

## v1.2.x
- Agent 升級功能、升級檔案管理與升級進度追蹤

## v1.1.x（2024-12-31）
- **Agent 表格欄位自訂**（顯示／隱藏欄位，儲存於 localStorage）
- **Queue DB 多節點支援**（透過 SSH）；節點下載／重啟透過 SSH
- **響應式寬度**；統一 24 小時制時間格式；同步篩選修正

## v1.0.8x – v1.0.9x（2024-12-31）
- Worker 節點 SSH 遠端管理（讀寫 ossec.conf、重啟服務、下載 cluster.key）
- SSH 設定指南含一鍵複製；設定對話框（API 連線、SSH 狀態、關於）
- 多項節點偵測、版本解析與 JavaScript regex 跳脫修正

> 1.4.0 之前更完整、細項的歷程，請參考專案早期的發行說明。
