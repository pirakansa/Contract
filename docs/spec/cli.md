# Repo Contract CLI Specification

> `contract` コマンドラインツールの仕様定義

## 1. 概要

`contract` CLI は Repo Contract の検証・差分検出・適用を行うツールです。

### 1.1 設計原則

| 原則 | 説明 |
|------|------|
| **ローカル/CI両対応** | 開発者のローカル環境とCI環境で同じコマンドが動作 |
| **明確な終了コード** | severity に応じた終了コードで CI 判定が容易 |
| **機械可読出力** | JSON出力オプションでスクリプト連携が可能 |
| **段階的検証** | validate → check → diff → apply の順で詳細化 |

---

## 2. インストール

### 2.1 バイナリ配布

```bash
# GitHub Releases からダウンロード
curl -L https://github.com/pirakansa/Contract/releases/latest/download/contract-$(uname -s)-$(uname -m) -o contract
chmod +x contract
sudo mv contract /usr/local/bin/
```

### 2.2 Cargo インストール

```bash
cargo install contract
```

### 2.3 GitHub Actions

```yaml
- uses: pirakansa/contract-action@v1
  with:
    command: check
```

---

## 3. コマンド一覧

| コマンド | 説明 |
|----------|------|
| `contract validate` | Contract ファイルの構文検証 |
| `contract check` | リポジトリ状態との照合 |
| `contract diff` | 期待値と現状の差分表示 |
| `contract apply` | Contract に基づく設定適用（Phase 2） |
| `contract init` | Contract ファイルの雛形生成 |
| `contract schema` | JSON Schema の出力 |

---

## 4. contract validate

Contract ファイルの構文を JSON Schema に基づいて検証します。

### 4.1 使用方法

```bash
# デフォルト: contract.yml を検証
contract validate

# 指定ファイルを検証
contract validate contract.yml
contract validate path/to/contract.yml

# Profile も含めて検証
contract validate --with-profile
```

### 4.2 オプション

| オプション | 短縮形 | デフォルト | 説明 |
|------------|--------|------------|------|
| `--config <PATH>` | `-c` | `contract.yml` | Contract ファイルパス |
| `--with-profile` | `-p` | `false` | Profile ファイルも検証 |
| `--format <FORMAT>` | `-f` | `human` | 出力形式（`human` / `json`） |
| `--quiet` | `-q` | `false` | エラー時のみ出力 |

### 4.3 出力例

```
$ contract validate

✓ contract.yml: Valid
✓ contract.rust.yml: Valid (profile)

Validated 2 files, 0 errors
```

```
$ contract validate --format json
{
  "valid": true,
  "files": [
    { "path": "contract.yml", "valid": true, "errors": [] },
    { "path": "contract.rust.yml", "valid": true, "errors": [] }
  ]
}
```

### 4.4 終了コード

| コード | 意味 |
|--------|------|
| `0` | 検証成功 |
| `1` | 検証エラー（構文エラー、スキーマ違反） |
| `2` | 実行エラー（ファイル未発見等） |

---

## 5. contract check

リポジトリの実際の状態が Contract に準拠しているか検証します。

### 5.1 使用方法

```bash
# ローカルリポジトリを検証
contract check

# リモートリポジトリを検証（GitHub API使用）
contract check --remote owner/repo

# 特定ルールのみ検証
contract check --rules required_files
contract check --rules branch_protection
```

### 5.2 オプション

| オプション | 短縮形 | デフォルト | 説明 |
|------------|--------|------------|------|
| `--config <PATH>` | `-c` | `contract.yml` | Contract ファイルパス |
| `--remote <REPO>` | `-r` | - | リモートリポジトリ（`owner/repo`） |
| `--rules <RULES>` | | すべて | 検証するルール（カンマ区切り） |
| `--format <FORMAT>` | `-f` | `human` | 出力形式（`human` / `json`） |
| `--strict` | `-s` | `false` | warning も終了コード 1 にする |
| `--quiet` | `-q` | `false` | エラー/警告時のみ出力 |

branch_protection の検証は GitHub API を利用するため、`GITHUB_TOKEN`（または `.contract.toml` の `github.token`）が必要です。
`--remote` を省略した場合は `GITHUB_REPOSITORY` か `git remote origin` からリポジトリを推測します。
`required_files` は `--remote` 未対応です。

### 5.3 出力例

```
$ contract check

Checking repository against contract.yml...

Branch Protection [main]
  ✓ required_pull_request_reviews.enabled: true
  ✓ required_pull_request_reviews.required_approving_review_count: 1
  ✗ required_status_checks.checks: missing "lint"
  
Required Files
  ✓ README.md: Found
  ✓ LICENSE: Found
  ⚠ CONTRIBUTING.md: Not found (warning)
  ✓ .gitignore: Found
  ℹ AGENTS.md: Found (info)

Summary: 1 error, 1 warning, 1 info
```

```
$ contract check --format json
{
  "valid": false,
  "results": [
    {
      "rule": "branch_protection",
      "target": "main",
      "checks": [
        {
          "path": "required_status_checks.checks",
          "expected": ["ci", "lint", "test"],
          "actual": ["ci", "test"],
          "severity": "error",
          "message": "Missing required status check: lint"
        }
      ]
    },
    {
      "rule": "required_files",
      "checks": [
        { "path": "README.md", "exists": true, "severity": "error" },
        { "path": "CONTRIBUTING.md", "exists": false, "severity": "warning" }
      ]
    }
  ],
  "summary": {
    "error": 1,
    "warning": 1,
    "info": 1
  }
}
```

### 5.4 終了コード

| コード | 条件 |
|--------|------|
| `0` | すべて成功、または warning/info のみ |
| `1` | error が 1 つ以上、または `--strict` 時に warning が 1 つ以上 |
| `2` | 実行エラー（ファイル未発見、API エラー等） |

### 5.5 環境変数

| 変数 | 説明 |
|------|------|
| `GITHUB_TOKEN` | GitHub API アクセス用トークン（branch_protection の check/diff に必須） |
| `CONTRACT_STRICT` | `true` の場合 `--strict` と同等 |

---

## 6. contract diff

Contract の期待値と現状の差分を表示します。

### 6.1 使用方法

```bash
# ローカルリポジトリとの差分
contract diff

# リモートリポジトリとの差分
contract diff --remote owner/repo

# 特定ルールのみ
contract diff --rules branch_protection
```

### 6.2 オプション

| オプション | 短縮形 | デフォルト | 説明 |
|------------|--------|------------|------|
| `--config <PATH>` | `-c` | `contract.yml` | Contract ファイルパス |
| `--remote <REPO>` | `-r` | - | リモートリポジトリ |
| `--rules <RULES>` | | すべて | 差分を取るルール |
| `--format <FORMAT>` | `-f` | `human` | 出力形式（`human` / `json` / `yaml`） |

branch_protection の差分取得は GitHub API を利用するため、`GITHUB_TOKEN`（または `.contract.toml` の `github.token`）が必要です。
`--remote` を省略した場合は `GITHUB_REPOSITORY` か `git remote origin` からリポジトリを推測します。
`required_files` は `--remote` 未対応です。

### 6.3 出力例

```
$ contract diff

Branch Protection [main]
  required_status_checks.checks:
    - ci      (exists)
    + lint    (missing)
    - test    (exists)

Required Files:
    + CONTRIBUTING.md  (missing, severity: warning)
```

```
$ contract diff --format json
{
  "diffs": [
    {
      "rule": "branch_protection",
      "target": "main",
      "path": "required_status_checks.checks",
      "type": "array_diff",
      "expected": ["ci", "lint", "test"],
      "actual": ["ci", "test"],
      "missing": ["lint"],
      "extra": []
    },
    {
      "rule": "required_files",
      "path": "CONTRIBUTING.md",
      "type": "missing_file",
      "severity": "warning"
    }
  ]
}
```

### 6.4 終了コード

| コード | 条件 |
|--------|------|
| `0` | 差分なし |
| `1` | 差分あり |
| `2` | 実行エラー |

---

## 7. contract init

Contract ファイルの雛形を生成します。

### 7.1 使用方法

```bash
# 基本的な contract.yml を生成
contract init

# 言語 Profile も生成
contract init --profile rust

# 既存設定から逆生成（リポジトリの現状を Contract 化）
contract init --from-repo
contract init --from-repo --remote owner/repo
```

### 7.2 オプション

| オプション | 短縮形 | デフォルト | 説明 |
|------------|--------|------------|------|
| `--output <PATH>` | `-o` | `contract.yml` | 出力ファイルパス |
| `--profile <LANG>` | `-p` | - | 生成する言語 Profile |
| `--from-repo` | | `false` | リポジトリの現状から生成 |
| `--remote <REPO>` | `-r` | - | リモートリポジトリ |
| `--force` | `-f` | `false` | 既存ファイルを上書き |

### 7.3 出力例

```
$ contract init --profile rust

Created: contract.yml
Created: contract.rust.yml

Edit these files to customize your repository contract.
Run `contract validate` to verify the configuration.
```

### 7.4 終了コード

| コード | 条件 |
|--------|------|
| `0` | 生成成功 |
| `1` | 既存ファイルあり（`--force` なし） |
| `2` | 実行エラー |

---

## 8. contract schema

JSON Schema を標準出力に出力します。

### 8.1 使用方法

```bash
# JSON Schema を出力
contract schema

# ファイルに保存
contract schema > contract.schema.json
```

### 8.2 終了コード

常に `0`（エラー時のみ `2`）

---

## 9. グローバルオプション

すべてのコマンドで使用可能なオプション：

| オプション | 短縮形 | 説明 |
|------------|--------|------|
| `--help` | `-h` | ヘルプを表示 |
| `--version` | `-V` | バージョンを表示 |
| `--verbose` | `-v` | 詳細ログを出力（複数指定で増加） |
| `--no-color` | | カラー出力を無効化 |

---

## 10. 設定ファイル

### 10.1 設定の優先順位

1. コマンドラインオプション
2. 環境変数
3. 設定ファイル（`.contract.toml`）
4. デフォルト値

### 10.2 .contract.toml

```toml
# .contract.toml - CLI設定ファイル（オプション）

[default]
config = "contract.yml"
format = "human"
strict = false

[check]
rules = ["required_files", "branch_protection"]

[github]
# GITHUB_TOKEN 環境変数の代わりに設定可能
# token = "ghp_xxxx"  # 非推奨: 環境変数を使用すること
```

branch_protection の check/diff では `github.token` を利用できます。

---

## 11. CI/CD 統合

### 11.1 GitHub Actions

```yaml
name: Contract Check

on:
  pull_request:
    branches: [main]

jobs:
  contract:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install contract CLI
        run: |
          curl -L https://github.com/pirakansa/Contract/releases/latest/download/contract-linux-amd64 -o contract
          chmod +x contract
          sudo mv contract /usr/local/bin/
      
      - name: Validate contract
        run: contract validate
      
      - name: Check repository
        run: contract check --format json > result.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: contract-results
          path: result.json
```

### 11.2 Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pirakansa/Contract
    rev: v1.0.0
    hooks:
      - id: contract-validate
      - id: contract-check
        args: [--rules, required_files]
```

---

## 12. エラーメッセージ形式

### 12.1 Human-readable

```
error[E001]: Missing required file
  --> contract.yml:15:3
   |
15 |   - path: "CONTRIBUTING.md"
   |     ^^^^^^^^^^^^^^^^^^^^^^^ file not found in repository
   |
   = help: Create CONTRIBUTING.md or change severity to "warning"

warning[W001]: Branch protection drift detected
  --> contract.yml:8:5
   |
 8 |     required_approving_review_count: 2
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ expected 2, got 1
   |
   = help: Update branch protection settings or adjust contract
```

### 12.2 JSON

```json
{
  "errors": [
    {
      "code": "E001",
      "level": "error",
      "message": "Missing required file",
      "location": {
        "file": "contract.yml",
        "line": 15,
        "column": 3
      },
      "context": {
        "path": "CONTRIBUTING.md",
        "severity": "error"
      },
      "help": "Create CONTRIBUTING.md or change severity to \"warning\""
    }
  ]
}
```

---

## 13. エラーコード一覧

| コード | カテゴリ | 説明 |
|--------|----------|------|
| `E001` | required_files | 必須ファイルが見つからない |
| `E002` | required_files | ファイルパターンにマッチするファイルがない |
| `E010` | branch_protection | ブランチ保護が設定されていない |
| `E011` | branch_protection | 必須レビュー数が不足 |
| `E012` | branch_protection | 必須ステータスチェックが不足 |
| `E020` | schema | Contract ファイルの構文エラー |
| `E021` | schema | Profile ファイルが見つからない |
| `W001` | drift | 設定値の不一致（warning） |
| `W002` | drift | 推奨ファイルが見つからない |
