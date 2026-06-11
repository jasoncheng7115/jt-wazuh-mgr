# JT Wazuh Manager v1.4.0

[English](README.md) | [繁體中文](README-zh-TW.md)

強大的 Wazuh Agent 網頁管理工具，專為叢集環境設計。

> **定位**：本工具用來「補強」Wazuh Dashboard，提供其缺少或操作不便的管理功能，**並非**取代 Wazuh Dashboard，而是與其互補。

> **建議**：以 Web UI 作為主要操作介面，這是本工具功能最完整的核心。

![Version](https://img.shields.io/badge/version-1.4.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Apache--2.0-orange)
![Languages](https://img.shields.io/badge/UI-English%20%7C%20%E7%B9%81%E9%AB%94%E4%B8%AD%E6%96%87-blueviolet)

🌐 **專案網站：** https://jasoncheng7115.github.io/jt-wazuh-mgr/

---

## ⚡ 一行安裝 / 升級 / 移除

請以 **root** 在 Wazuh Manager（叢集模式為 Master 節點）執行：

```bash
# 安裝
curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/install.sh | sudo bash

# 升級（重新執行安裝腳本，會保留你的 config.yaml）
curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/install.sh | sudo bash

# 移除
curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/uninstall.sh | sudo bash
```

安裝腳本會把程式安裝到 `/opt/jt-wazuh-mgr`、安裝 Python 相依套件，並註冊與啟動 `systemd` 服務（`jt-wazuh-mgr`）。安裝完成後，開啟 **https://你的WazuhManager_IP:5000**，使用 Wazuh API 帳號登入即可。

> 已安裝過？也可以在本機直接升級／移除：
> ```bash
> curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/install.sh | sudo bash   # 升級
> sudo bash /opt/jt-wazuh-mgr/uninstall.sh                                                                # 移除
> ```

---

## ✨ 1.4.0 新功能

- **雙語介面（English / 繁體中文）**，標題列一鍵切換語言，瀏覽器會記住你的選擇。
- 專案更名並獨立為單一倉庫：**`jasoncheng7115/jt-wazuh-mgr`**。
- 提供一行 **安裝 / 升級 / 移除** 流程。
- 改採 **Apache-2.0** 授權。

完整內容請見 [CHANGELOG](CHANGELOG-zh-TW.md)。

## 功能特色

### 語言
- 標題列可切換 **英文 / 繁體中文**（EN ⇄ 中文），偏好設定依瀏覽器記住。

### Agent 管理
- 即時檢視所有 Agent 狀態
- 進階篩選（狀態、群組、節點、作業系統、版本、IP、名稱、同步狀態）
- **便利的多選**批次操作
- **分布圖**：以視覺化長條呈現 Agent 依狀態／作業系統／版本／群組／節點／同步狀態的分布
  - 點選區段即可篩選 Agent
  - 切換檢視時有動畫過場
- **統計自動重新整理**：上方統計每 10 秒自動更新並帶滑入動畫
- **群組操作**：加入／移出群組、合併到其他群組、僅保留於特定群組、重新命名群組、**從 CSV 匯入**（含預覽）、**匯出為 CSV**
- 批次操作：重新啟動、重新連線、刪除、升級
- **移動到節點**（規劃中）：透過 HAProxy 整合將 Agent 遷移到指定節點（開發中）
- 健康檢查與重複 Agent 偵測
- **Queue DB 容量檢查**：監控 Agent queue 資料庫使用量，支援批次清除
- Agent 升級並即時追蹤進度

### 叢集支援
- 完整的 Master/Worker 叢集支援
- 節點服務狀態監控
- **編輯 ossec.conf**：編輯 Master 與 Worker 節點的設定檔
- **重新啟動服務**：在任一節點重新啟動 Wazuh 服務
- **下載 cluster.key**：從 Master 節點下載叢集金鑰
- **WPK 檔案管理**：上傳與刪除 WPK 升級檔
- **同步狀態檢查**：監控 Master 與 Worker 間的檔案同步（Rules、Decoders、Groups、Keys、Lists、SCA），並可檢視節點間差異的檔案
- Worker 節點 SSH 遠端管理
- **電子郵件警示管理**：以表單方式管理 `ossec.conf` 中的 `<email_alerts>` 規則 — 免手動編輯 XML 即可新增／編輯／刪除，一鍵同步到所有 Worker 節點，每次變更前自動備份

### 統計與報表
- 依狀態、群組、節點、作業系統、版本、網段統計
- 所有統計表格欄位可排序
- 匯出為 JSON/CSV

### 規則檢視器
- **瀏覽所有規則**：可排序、可搜尋、分頁的規則表格；可依等級範圍、檔案、類型（自訂／內建）篩選
- **規則階層視覺化**：以可收合的樹狀圖呈現父子關係（`if_sid`、`if_matched_sid`）
- 點選任一規則 ID 跳至其階層檢視；展開可檢視完整規則 XML 並語法上色

### 安全性
- 所有參數皆做輸入驗證；防範指令注入與路徑穿越
- 安全的檔案上傳處理
- 完整的操作**記錄與稽核**
- **API 使用者管理**：建立、修改與管理 Wazuh API 使用者與角色
- 暴力破解防護（IP 鎖定：登入失敗 3 次 = 鎖定 30 分鐘）
- 安全政策與強化說明請見 [SECURITY.md](SECURITY.md)

## 螢幕截圖

| | |
|---|---|
| 登入頁面 | ![Login](screenshots/1_login.png) |
| Agent 列表 | ![Agents](screenshots/2_agents.png) |
| Agent 操作與 Queue DB | ![Agent Actions](screenshots/3_selected_action_queuedb.png) |
| 群組管理 | ![Groups](screenshots/4_groups.png) |
| 節點管理 | ![Nodes](screenshots/5_nodes.png) |
| WPK 檔案管理 | ![WPK Files](screenshots/6_nodes_wpkfiles.png) |
| 規則檢視器 | ![Rules](screenshots/7_rule.png) |
| API 使用者 | ![API Users](screenshots/8_apiusers.png) |
| 記錄檢視器 | ![Logs](screenshots/9_logs.png) |
| 編輯 ossec.conf | ![Edit Config](screenshots/10_node_editconfig.png) |
| Agent 升級 | ![Upgrade 1](screenshots/11_upgrade_agent_1.png) ![Upgrade 2](screenshots/11.5_upgrade_agent_2.png) ![Upgrade 3](screenshots/12_upgrade_agent_3.png) |
| Agent 詳細資訊 | ![Agent Detail](screenshots/13_agent_detail.png) |

## 快速開始

### 系統需求
- Python 3.8+
- Wazuh Manager 4.x
- **必須安裝在 Wazuh Manager 上**（叢集模式安裝在 Master 節點）

### 安裝

使用上方的[一行安裝指令](#-一行安裝--升級--移除)，或手動執行：

```bash
./wazuh_agent_mgr.py --web --ssl-auto
```

開啟 **https://你的WazuhManager_IP:5000**，使用 Wazuh API 帳號登入。

> **提示**：使用 `wazuh` 或 `wazuh-wui` 帳號。密碼可於 `wazuh-install-files.tar`（安裝時產生）或你的安裝記錄中找到。

### 其他選項

```bash
# 自訂連接埠
./wazuh_agent_mgr.py --web --port 8443 --ssl-auto

# 自訂 SSL 憑證
./wazuh_agent_mgr.py --web --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem
```

### systemd 服務

安裝腳本會自動註冊並啟動 systemd 服務，管理指令：

```bash
systemctl status jt-wazuh-mgr       # 檢視狀態
systemctl restart jt-wazuh-mgr      # 重新啟動服務
journalctl -u jt-wazuh-mgr -f       # 檢視記錄
```

## CLI 使用方式

```bash
# 列出所有 Agent
./wazuh_agent_mgr.py agent list

# 篩選 Agent
./wazuh_agent_mgr.py agent list --status=Active --group=production

# 快速狀態查詢
./wazuh_agent_mgr.py agent disconnected
./wazuh_agent_mgr.py agent pending

# 群組管理
./wazuh_agent_mgr.py group list
./wazuh_agent_mgr.py group add-agent webservers 001 002 003

# 節點管理
./wazuh_agent_mgr.py node list
./wazuh_agent_mgr.py node reconnect 001 002

# 統計
./wazuh_agent_mgr.py stats report
```

### 輸出格式

支援三種輸出格式：`table`（預設）、`json`、`csv`。

```bash
./wazuh_agent_mgr.py agent list --format=json
./wazuh_agent_mgr.py agent list --format=csv > agents.csv
./wazuh_agent_mgr.py stats report --format=json > report.json
```

### 模擬執行（Dry-Run）

所有寫入操作皆支援 `--dry-run`，可預覽動作而不實際執行：

```bash
./wazuh_agent_mgr.py agent delete 001 --dry-run
# 輸出：[DRY-RUN] Would execute: /var/ossec/bin/manage_agents -r 001
```

## 設定

`config.yaml`（已附範本，**Web UI 模式不需設定帳密**）：

```yaml
wazuh_path: /var/ossec

# API 設定
# Web UI 模式：不需要設定 username/password（使用者透過瀏覽器登入）
# CLI 模式：需要設定 username/password（執行 ./wazuh_agent_mgr.py agent list 等指令）
api:
  enabled: false           # CLI 模式請設為 true
  host: localhost
  port: 55000
  username: wazuh          # 僅 CLI 模式需要
  password: ""             # 僅 CLI 模式需要，密碼請查看 wazuh-install-files.tar
  verify_ssl: false

# Web UI 設定
web:
  session_timeout: 120     # 分鐘

# 選用：Worker 節點 SSH 遠端管理
# ssh:
#   enabled: true
#   key_file: /root/.ssh/wazuh_cluster_key
#   nodes:
#     worker01:
#       host: 192.168.1.100
#       port: 22
#       user: root
```

### Web UI 與 CLI 設定差異

| 設定 | Web UI | CLI |
|------|--------|-----|
| `api.enabled` | 不需要 | `true` |
| `api.username` | 不需要（瀏覽器登入） | 需要 |
| `api.password` | 不需要（瀏覽器登入） | 需要 |
| `ssh.*` | 選用（遠端節點管理） | 選用 |

## 多語系（i18n）

介面以英文撰寫，並在前端完整翻譯為繁體中文。UI 字串集中於
`lib/i18n_engine.js`，再由 `tools/build_i18n.py` 內嵌進 `lib/web_ui.py`。
要擴充或修改翻譯：

```bash
# 編輯 lib/i18n_engine.js 後，重新內嵌進 web_ui.py
python3 tools/build_i18n.py
```

## 技術架構

- **後端**：Python、Flask
- **前端**：原生 JavaScript、CSS（無框架）
- **Wazuh 整合**：CLI 指令 + REST API

## 免責聲明

本軟體以「現狀」提供，不附帶任何明示或暗示的擔保。作者對使用本軟體所造成的任何損害或損失概不負責，請自行承擔使用風險。

在進行任何操作（尤其是刪除、重新啟動或升級）前，強烈建議：
- 先以 `--dry-run` 模式預覽動作
- 備份重要設定
- 先在非正式環境測試

## 授權

採用 [Apache License 2.0](LICENSE) 授權。

## 作者

Jason Cheng (Jason Tools)
