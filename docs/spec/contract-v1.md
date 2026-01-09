# Repo Contract Specification v1.0

> AI・人間の双方が守るべき「リポジトリの契約」を機械可読形式で定義する仕様

## 1. 概要

### 1.1 目的

Repo Contract は以下を実現するための設定ファイル仕様です：

- **AIが安全に開発できる基盤**: 禁止操作・必須ルールを明示的に定義
- **品質・セキュリティの強制**: CIレベルでの自動検証
- **レビューの契約化**: 「好み」ではなく「契約」ベースの判断基準

### 1.2 設計原則

| 原則 | 説明 |
|------|------|
| **機械可読** | YAML/JSON形式でCI・GitHub Appが検証可能 |
| **言語非依存** | Core（共通ルール）とProfile（言語別）の分離 |
| **段階的適用** | severity（error/warning/info）による柔軟な運用 |
| **宣言的定義** | 「望ましい状態」を記述、差分検出・自動修正が可能 |

### 1.3 ファイル配置

```
/
├── contract.yml              # メインContract（Core設定）
├── contract.<lang>.yml       # 言語Profile（オプション）
└── contract.<name>.yml       # カスタムProfile（オプション）
```

- ファイルはリポジトリルートに配置
- Profile ファイルは `contract.` プレフィックスで統一

---

## 2. 設定ファイル構造

### 2.1 トップレベル構造

```yaml
# contract.yml
$schema: "https://pirakansa.github.io/RepoContract/schemas/v1.json"
version: "1.0"

profile: "<language>"          # オプション: 言語Profile指定

branch_protection:             # ブランチ保護ルール
  # ...

required_files:                # 必須ファイル定義
  # ...

metadata:                      # メタデータ（オプション）
  # ...
```

### 2.2 フィールド定義

| フィールド | 型 | 必須 | 説明 |
|------------|------|------|------|
| `$schema` | string | No | JSON Schema URI |
| `version` | string | **Yes** | 仕様バージョン（`"1.0"`） |
| `profile` | string | No | 読み込む言語Profile名 |
| `branch_protection` | object | No | ブランチ保護ルール |
| `required_files` | array | No | 必須ファイル定義 |
| `metadata` | object | No | リポジトリメタデータ |

---

## 3. branch_protection

GitHub のブランチ保護設定を宣言的に定義します。

### 3.1 構造

```yaml
branch_protection:
  branches:
    - "main"
    - "release/*"
  
  rules:
    required_pull_request_reviews:
      enabled: true
      required_approving_review_count: 1
      dismiss_stale_reviews: true
      require_code_owner_reviews: false
      require_last_push_approval: false
    
    required_status_checks:
      enabled: true
      strict: true
      checks:
        - context: "ci"
        - context: "lint"
    
    enforce_admins: false
    required_linear_history: false
    allow_force_pushes: false
    allow_deletions: false
    required_conversation_resolution: true
    required_signatures: false
```

### 3.2 branches

| フィールド | 型 | デフォルト | 説明 |
|------------|------|------------|------|
| `branches` | string[] | `["main"]` | 保護対象ブランチ（glob対応） |

glob パターン例：
- `main` - 完全一致
- `release/*` - `release/` 直下のブランチ
- `feature/**` - `feature/` 以下すべて

### 3.3 rules.required_pull_request_reviews

| フィールド | 型 | デフォルト | 説明 |
|------------|------|------------|------|
| `enabled` | boolean | `true` | PRレビュー必須を有効化 |
| `required_approving_review_count` | integer (0-6) | `1` | 必須承認数 |
| `dismiss_stale_reviews` | boolean | `true` | 新コミットで古いレビューを却下 |
| `require_code_owner_reviews` | boolean | `false` | CODEOWNERSレビュー必須 |
| `require_last_push_approval` | boolean | `false` | 最終プッシュ者以外の承認必須 |

### 3.4 rules.required_status_checks

| フィールド | 型 | デフォルト | 説明 |
|------------|------|------------|------|
| `enabled` | boolean | `true` | ステータスチェック必須を有効化 |
| `strict` | boolean | `true` | ブランチを最新に保つ |
| `checks` | array | `[]` | 必須チェックのリスト |
| `checks[].context` | string | - | チェック名（必須） |
| `checks[].app_id` | integer | - | GitHub App ID（オプション） |

### 3.5 rules（その他）

| フィールド | 型 | デフォルト | 説明 |
|------------|------|------------|------|
| `enforce_admins` | boolean | `false` | 管理者にも制限を適用 |
| `required_linear_history` | boolean | `false` | リニアコミット履歴必須 |
| `allow_force_pushes` | boolean | `false` | force push許可 |
| `allow_deletions` | boolean | `false` | ブランチ削除許可 |
| `required_conversation_resolution` | boolean | `false` | PR会話解決必須 |
| `required_signatures` | boolean | `false` | 署名済みコミット必須 |

---

## 4. required_files

リポジトリに存在すべきファイルを定義します。

### 4.1 構造

```yaml
required_files:
  - path: "README.md"
    description: "プロジェクト説明"
  
  - path: "LICENSE"
    description: "ライセンスファイル"
    alternatives:
      - "LICENSE.md"
      - "COPYING"
  
  - path: "CONTRIBUTING.md"
    description: "貢献ガイドライン"
    severity: "warning"
  
  - path: "docs/**/*.md"
    description: "ドキュメント"
    severity: "info"
```

### 4.2 フィールド定義

| フィールド | 型 | 必須 | デフォルト | 説明 |
|------------|------|------|------------|------|
| `path` | string | **Yes** | - | ファイルパス（glob対応） |
| `description` | string | No | - | 人間可読な説明 |
| `alternatives` | string[] | No | `[]` | 代替ファイルパス（いずれか存在でOK） |
| `severity` | string | No | `"error"` | 検証失敗時の重大度 |
| `pattern` | string | No | - | 正規表現パターン（`path`の代わりに使用） |
| `case_insensitive` | boolean | No | `false` | 大文字小文字を区別しない |

### 4.3 severity

| 値 | CI終了コード | 挙動 |
|-----|-------------|------|
| `error` | 1（失敗） | CI失敗、PRマージブロック |
| `warning` | 0（成功） | 警告コメント、Annotation表示 |
| `info` | 0（成功） | ログ出力のみ |

`--strict` オプション使用時は `warning` も終了コード 1 となります。

### 4.4 パスマッチング

- `README.md` - 完全一致
- `LICENSE*` - ワイルドカード（`LICENSE`, `LICENSE.md` など）
- `src/**/*.rs` - 再帰glob（`src/` 以下のすべての `.rs` ファイル）
- `pattern: "^README\\.(md|rst|txt)$"` - 正規表現

---

## 5. metadata

リポジトリのメタ情報を定義します（ドキュメント目的）。

### 5.1 構造

```yaml
metadata:
  description: "Repo Contract 検証ツール"
  maintainers:
    - "@pirakansa"
    - "@platform-team"
  tier: "critical"
  last_updated: "2026-01-08"
```

### 5.2 フィールド定義

| フィールド | 型 | 説明 |
|------------|------|------|
| `description` | string | リポジトリの説明 |
| `maintainers` | string[] | メンテナー（@username または @org/team） |
| `tier` | string | 重要度（`critical` / `standard` / `experimental`） |
| `last_updated` | string (date) | 最終更新日（YYYY-MM-DD） |

---

## 6. Profile システム

### 6.1 概要

Profile は言語・フレームワーク固有のルールを分離するための仕組みです。

```yaml
# contract.yml (Core)
version: "1.0"
profile: "rust"  # → contract.rust.yml を読み込む
```

### 6.2 Profile 読み込み

1. `profile: "<name>"` が指定された場合、`contract.<name>.yml` を検索
2. 見つかった場合、Core設定とマージ
3. 見つからない場合、**警告を出力して続行**（エラーにしない）

### 6.3 マージ戦略

| データ型 | 戦略 | 例 |
|----------|------|-----|
| **配列** | 結合（append） | `required_files` は Core + Profile の両方を適用 |
| **オブジェクト** | Profile優先で上書き | `branch_protection.rules` は Profile が優先 |
| **スカラー** | Profile優先 | `version` は常に Core の値を使用（例外） |

#### マージ例

```yaml
# contract.yml (Core)
required_files:
  - path: "README.md"
  - path: "LICENSE"

branch_protection:
  rules:
    required_approving_review_count: 1

# contract.rust.yml (Profile)
required_files:
  - path: "Cargo.toml"
  - path: "src/lib.rs"

branch_protection:
  rules:
    required_approving_review_count: 2  # 上書き
    required_status_checks:
      checks:
        - context: "rust-ci"
```

```yaml
# マージ結果
required_files:
  - path: "README.md"      # Core
  - path: "LICENSE"        # Core
  - path: "Cargo.toml"     # Profile
  - path: "src/lib.rs"     # Profile

branch_protection:
  rules:
    required_approving_review_count: 2  # Profile優先
    required_status_checks:             # Profile追加
      checks:
        - context: "rust-ci"
```

### 6.4 Profile ファイル構造

```yaml
# contract.rust.yml
version: "1.0"
language: "rust"  # Profile識別子

required_files:
  - path: "Cargo.toml"
    description: "Rustプロジェクトマニフェスト"
  # ...

branch_protection:
  # Profile固有のオーバーライド
```

---

## 7. 検証ルール

### 7.1 構文検証（validate）

JSON Schema に基づく検証：

- 必須フィールドの存在確認
- 型チェック（string, integer, boolean, array, object）
- enum値の検証（severity等）
- パターンマッチ（version形式等）

### 7.2 状態検証（check）

リポジトリの実際の状態との照合：

| 対象 | 検証内容 |
|------|----------|
| `branch_protection` | GitHub API経由でブランチ保護設定を取得・比較 |
| `required_files` | ファイルシステムまたはGitHub API経由で存在確認 |

### 7.3 検証結果

```json
{
  "valid": false,
  "errors": [
    {
      "rule": "required_files",
      "path": "CONTRIBUTING.md",
      "severity": "warning",
      "message": "File not found: CONTRIBUTING.md"
    },
    {
      "rule": "branch_protection",
      "path": "main",
      "severity": "error",
      "message": "required_approving_review_count: expected 2, got 1"
    }
  ],
  "summary": {
    "error": 1,
    "warning": 1,
    "info": 0
  }
}
```

---

## 8. スキーマ

JSON Schema は以下のURLで公開されます：

```
https://pirakansa.github.io/RepoContract/schemas/v1.json
```

YAML/JSON ファイルで `$schema` を指定することで、エディタ補完・検証が有効になります：

```yaml
$schema: "https://pirakansa.github.io/RepoContract/schemas/v1.json"
version: "1.0"
# ...
```

---

## 9. バージョニング

### 9.1 仕様バージョン

- `version: "1.0"` - 現行バージョン（MVP）
- 破壊的変更時はメジャーバージョンを上げる（`"2.0"`）
- 後方互換な追加はマイナーバージョンを上げる（`"1.1"`）

### 9.2 スキーマバージョン

スキーマURLにはバージョンを含める：

- `https://pirakansa.github.io/RepoContract/schemas/v1.json` - v1.x系
- `https://pirakansa.github.io/RepoContract/schemas/v2.json` - v2.x系（将来）

---

## 10. 将来拡張（Phase 2以降）

以下の機能はMVP後に追加予定：

| 機能 | 説明 |
|------|------|
| `extends` | Renovate風の継承システム |
| `labels` | Issue/PRラベル定義 |
| `codeowners` | CODEOWNERS生成・検証 |
| `dependencies` | 許可/禁止ライブラリ |
| `ai_restrictions` | AI向け禁止操作の定義 |
