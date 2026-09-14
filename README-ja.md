# jt-wazuh-mgr v1.8.0

[English](README.md) | [繁體中文](README-zh-TW.md) | [日本語](README-ja.md)

クラスタ環境の Wazuh エージェントを管理するための、強力な Web ベース管理ツールです。

> **目的**: このツールは、Wazuh Dashboard に不足している、あるいは使いにくい管理機能を**補う**ために作られています。Wazuh Dashboard を**置き換えるものではなく**、補完するものです。

> **推奨**: Web UI を主なインターフェースとしてお使いください。本ツールの中心となる機能であり、すべての機能が利用できます。

![Version](https://img.shields.io/badge/version-1.8.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-AGPL--3.0-orange)
![Languages](https://img.shields.io/badge/UI-English%20%7C%20%E7%B9%81%E9%AB%94%E4%B8%AD%E6%96%87%20%7C%20%E6%97%A5%E6%9C%AC%E8%AA%9E-blueviolet)

🌐 **プロジェクトサイト:** https://jasoncheng7115.github.io/jt-wazuh-mgr/

---

## ⚡ ワンライナーでのインストール / アップグレード / アンインストール

Wazuh Manager 上（クラスタ構成ではマスターノード）で **root** として実行します:

```bash
# インストール
curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/install.sh | sudo bash

# アップグレード（インストーラーを再実行するだけ。config.yaml は保持されます）
curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/install.sh | sudo bash

# アンインストール
curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/uninstall.sh | sudo bash
```

インストーラーは `/opt/jt-wazuh-mgr` にアプリケーションを配置し、Python の依存パッケージをインストールしたうえで、`systemd` サービス（`jt-wazuh-mgr`）を登録・起動します。完了後、**https://お使いの_WAZUH_MANAGER_の_IP:5000** を開き、Wazuh API の認証情報でログインしてください。

> インストール失敗やアップグレードがうまくいかない場合は、**[インストール／アップグレードのトラブルシューティング](https://jasoncheng7115.github.io/jt-wazuh-mgr/troubleshooting.html)**（検索可能）をご覧ください。

> すでにインストール済みの場合、ローカルでもアップグレード／アンインストールできます:
> ```bash
> curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-wazuh-mgr/main/install.sh | sudo bash   # アップグレード
> sudo bash /opt/jt-wazuh-mgr/uninstall.sh                                                                # アンインストール
> ```

---

## 機能

### 表示言語
- **English / 繁體中文 / 日本語** をヘッダーから切り替えられます（EN ⇄ 中文 ⇄ 日本語）。選択した言語はブラウザーごとに保存されます。

### エージェント管理
- すべてのエージェントの状態をリアルタイムで表示
- 高度な絞り込み（状態、グループ、ノード、OS、バージョン、IP、名前、同期状態）
- 一括操作のための**便利な複数選択**
- **分布バー**: 状態・OS・バージョン・グループ・ノード・同期状態ごとのエージェント分布を視覚的に表示
  - セグメントをクリックするとエージェントを絞り込み
  - 表示切り替え時のアニメーション
- **統計の自動更新**: 上部の統計が 10 秒ごとにスライドアニメーション付きで更新
- **グループ操作**: グループへの追加／削除、別グループへの統合、特定グループのみに限定、グループ名の変更、**CSV からのインポート**（プレビュー付き）、**CSV へのエクスポート**
- 一括操作: 再起動、再接続、削除、アップグレード
- **ノードへ移動**（予定）: HAProxy 連携により特定ノードへエージェントを移行（開発中）
- ヘルスチェックと重複検出
- **Queue DB サイズの確認**: エージェントのキューデータベース使用量を監視し、一括クリアにも対応
- リアルタイムな進捗表示付きのエージェントアップグレード

### クラスタ対応
- マスター／ワーカー構成に完全対応
- ノードのサービス状態の監視
- マスター・ワーカー両ノードの **ossec.conf の編集**
- 任意のノードでの**サービス再起動**
- マスターノードからの **cluster.key のダウンロード**
- **WPK ファイル管理**: アップグレード用 WPK ファイルのアップロードと削除
- マスターとワーカー間の**同期状態の確認**（ルール、デコーダー、グループ、キー、リスト、SCA）。ノード間で差異のあるファイルの表示も含みます
- ワーカーノードの SSH によるリモート管理
- **メール通知の管理**: `ossec.conf` の `<email_alerts>` ルールをフォームで管理。XML を手で編集せずに追加・編集・削除でき、すべてのワーカーノードへワンクリックで同期、変更前には自動バックアップ

### 統計とレポート
- 状態、グループ、ノード、OS、バージョン、ネットワークセグメント別の統計
- すべての統計表で列のソートが可能
- JSON／CSV へのエクスポート

### ルールビューアー
- **すべてのルールの一覧**（ソート・検索・ページ送り対応）。レベル範囲、ファイル、種類（カスタム／組み込み）で絞り込み
- **ルール階層の可視化**（`if_sid`、`if_matched_sid` による親子関係を折りたたみ可能なツリーで表示）
- ルール ID をクリックすると階層表示へ移動。展開するとシンタックスハイライト付きでルールの XML 全体を確認できます

### ルールパック
- Jason Tools が保守する**検知ルール群のカタログ**。UI からインストールできます
- 各パックはマニフェストのもとにルール・デコーダー・CDB リストをまとめています。開くとインストールされるファイル、その配置先、使用するルール ID を確認できます
- インストールは保護されています: **ルール ID の重複検出**、上書きされるファイルのバックアップ、`wazuh-analysisd -t` による検証、そして**いずれかの手順が失敗した場合の完全なロールバック**
- 削除時は置き換えられたファイルを復元し、**インストール後に編集されたファイルは破棄を拒否**します
- 同梱パック: 可搬実行ファイルの検知（Windows／Linux／macOS）、IP 脅威インテリジェンス、マルウェアのハッシュ照合、Zimbra 検知、Zenarmor（OPNsense）、AdGuard Home、fail2ban

### セキュリティ
- すべてのパラメーターに対する入力検証。コマンドインジェクションとパストラバーサルへの対策
- 安全なファイルアップロード処理
- 操作の**完全なログ記録と監査**
- **API ユーザー管理**: Wazuh API のユーザーとロールの作成・変更・管理
- 総当たり攻撃への対策（IP ロックアウト: ログイン 3 回失敗で 30 分間ロック）
- セキュリティ方針と堅牢化については [SECURITY.md](SECURITY.md) を参照してください
- リリース前に何を検証しているか（および何を検証していないか）は [TEST-PLAN.md](TEST-PLAN.md) を参照してください

## スクリーンショット

| | |
|---|---|
| ログイン | ![Login](screenshots/1_login.png) |
| エージェント一覧 | ![Agents](screenshots/2_agents.png) |
| エージェント操作と Queue DB | ![Agent Actions](screenshots/3_selected_action_queuedb.png) |
| グループ | ![Groups](screenshots/4_groups.png) |
| ノード | ![Nodes](screenshots/5_nodes.png) |
| WPK ファイル管理 | ![WPK Files](screenshots/6_nodes_wpkfiles.png) |
| ルールビューアー | ![Rules](screenshots/7_rule.png) |
| API ユーザー | ![API Users](screenshots/8_apiusers.png) |
| ログビューアー | ![Logs](screenshots/9_logs.png) |
| ossec.conf の編集 | ![Edit Config](screenshots/10_node_editconfig.png) |
| エージェントのアップグレード | ![Upgrade 1](screenshots/11_upgrade_agent_1.png) ![Upgrade 2](screenshots/11.5_upgrade_agent_2.png) ![Upgrade 3](screenshots/12_upgrade_agent_3.png) |
| エージェントの詳細 | ![Agent Detail](screenshots/13_agent_detail.png) |
| インベントリ（全エージェント横断検索） | ![Inventory](screenshots/14_inventory.png) |
| ルールパック | ![Rule Packs](screenshots/15_rule_packs.png) |
| ルールパックの詳細 | ![Rule Pack Detail](screenshots/16_rule_pack_detail.png) |
| ファイル名別のルール | ![Rules by file](screenshots/17_rules_by_file.png) |
| 統計 | ![Statistics](screenshots/18_statistics.png) |

## クイックスタート

### 動作要件
- Python 3.8 以上
- Wazuh Manager 4.x
- **Wazuh Manager 上にインストールすること**（クラスタ構成ではマスターノード）

### インストール

上記の[ワンライナーインストーラー](#-ワンライナーでのインストール--アップグレード--アンインストール)を使うか、クローン後に手動で実行します:

```bash
./wazuh_agent_mgr.py --web --ssl-auto
```

**https://お使いの_WAZUH_MANAGER_の_IP:5000** を開き、Wazuh API の認証情報でログインします。

> **補足**: `wazuh` または `wazuh-wui` アカウントを使用します。パスワードはインストール時に生成される `wazuh-install-files.tar` の中、またはインストール記録に記載されています。

### その他のオプション

```bash
# ポートを変更する
./wazuh_agent_mgr.py --web --port 8443 --ssl-auto

# 独自の SSL 証明書を使う
./wazuh_agent_mgr.py --web --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem
```

### systemd サービス

インストーラーが systemd サービスを自動的に登録・起動します。管理用コマンド:

```bash
systemctl status jt-wazuh-mgr       # 状態を確認
systemctl restart jt-wazuh-mgr      # サービスを再起動
journalctl -u jt-wazuh-mgr -f       # ログを表示
```

## CLI の使い方

```bash
# すべてのエージェントを一覧表示
./wazuh_agent_mgr.py agent list

# エージェントを絞り込む
./wazuh_agent_mgr.py agent list --status=Active --group=production

# 状態のクイック照会
./wazuh_agent_mgr.py agent disconnected
./wazuh_agent_mgr.py agent pending

# グループ管理
./wazuh_agent_mgr.py group list
./wazuh_agent_mgr.py group add-agent webservers 001 002 003

# ノード管理
./wazuh_agent_mgr.py node list
./wazuh_agent_mgr.py node reconnect 001 002

# 統計
./wazuh_agent_mgr.py stats report
```

### 出力形式

`table`（既定）、`json`、`csv` の 3 種類に対応しています。

```bash
./wazuh_agent_mgr.py agent list --format=json
./wazuh_agent_mgr.py agent list --format=csv > agents.csv
./wazuh_agent_mgr.py stats report --format=json > report.json
```

### ドライランモード

すべての書き込み操作は `--dry-run` に対応しており、実行せずに内容を確認できます:

```bash
./wazuh_agent_mgr.py agent delete 001 --dry-run
# 出力: [DRY-RUN] Would execute: /var/ossec/bin/manage_agents -r 001
```

## 設定

`config.yaml`（テンプレートが同梱されています。**Web UI モードでは認証情報の設定は不要です**）:

```yaml
wazuh_path: /var/ossec

# API 設定
# Web UI モード: username／password は不要（ブラウザーからログインします）
# CLI モード:    ./wazuh_agent_mgr.py agent list のようなコマンドには username／password が必要です
api:
  enabled: false           # CLI モードで使う場合は true
  host: localhost
  port: 55000
  username: wazuh          # CLI モードのみ
  password: ""             # CLI モードのみ。wazuh-install-files.tar を参照
  verify_ssl: false

# Web UI の設定
web:
  session_timeout: 120     # 分

# 任意: ワーカーノードをリモート管理するための SSH 設定
# ssh:
#   enabled: true
#   key_file: /root/.ssh/wazuh_cluster_key
#   nodes:
#     worker01:
#       host: 192.168.1.100
#       port: 22
#       user: root
```

### Web UI と CLI の設定の違い

| 設定項目 | Web UI | CLI |
|---------|--------|-----|
| `api.enabled` | 不要 | `true` |
| `api.username` | 不要（ブラウザーからログイン） | 必要 |
| `api.password` | 不要（ブラウザーからログイン） | 必要 |
| `ssh.*` | 任意（リモートノード管理用） | 任意 |

## 国際化（i18n）

UI は英語で書かれており、繁體中文と日本語へはすべてクライアント側で翻訳されます。
UI の文字列は `lib/i18n_engine.js` にあり、`tools/build_i18n.py` によって
`lib/web_ui.py` に埋め込まれます。翻訳を追加・修正する手順:

```bash
# lib/i18n_engine.js を編集してから、web_ui.py に埋め込み直す
python3 tools/build_i18n.py
```

言語を増やす場合は、`I18N` と `I18N_PATTERNS` にその言語のキーを追加し、
`SUPPORTED` に言語コードを加えるだけです。それ以外に言語固有の箇所はありません。

## 技術スタック

- **バックエンド**: Python、Flask
- **フロントエンド**: 素の JavaScript と CSS（フレームワークなし）
- **Wazuh 連携**: CLI コマンド ＋ REST API

## 免責事項

本ソフトウェアは明示・黙示を問わずいかなる保証もなく「現状のまま」提供されます。本ソフトウェアの使用によって生じたいかなる損害・損失についても、作者は責任を負いません。ご自身の責任においてご使用ください。

操作（特に削除・再起動・アップグレード）を行う前に、次のことを強く推奨します:
- `--dry-run` モードで実行内容を事前に確認する
- 重要な設定をバックアップする
- まず本番以外の環境で試す

## ライセンス

[GNU Affero General Public License v3.0](LICENSE) のもとで提供されています。

## 作者

Jason Cheng (Jason Tools)
