# 更新記錄

本檔案記錄 **JT Wazuh Agent Manager** 的所有重要變更。

[English](CHANGELOG.md) | [繁體中文](CHANGELOG-zh-TW.md)

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
