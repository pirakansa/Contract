# Repo Contract - GitHub Actions Integration

> GitHub Actions での Repo Contract 検証フローと連携仕様

## 1. 概要

Repo Contract は GitHub Actions と連携して、以下を実現します：

- **PR 時の自動検証**: Contract 違反を検出し、マージをブロック
- **視覚的フィードバック**: コメント・ラベル・Annotation で違反を通知
- **段階的適用**: severity に応じた柔軟な運用

---

## 2. 検証フロー

```
┌─────────────────────────────────────────────────────────────────┐
│                        Pull Request                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. repo-contract validate                                       │
│     - contract.yml の構文検証                                    │
│     - Profile ファイルの構文検証                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │ 失敗                          │ 成功
              ▼                               ▼
┌─────────────────────────┐   ┌─────────────────────────────────┐
│  CI Failed              │   │  2. repo-contract check          │
│  - PR コメント投稿      │   │     - required_files 検証        │
│  - ラベル付与           │   │     - branch_protection 検証     │
│    contract:invalid     │   └─────────────────────────────────┘
└─────────────────────────┘                   │
                              ┌───────────────┴───────────────┐
                              │ 違反あり                      │ 違反なし
                              ▼                               ▼
              ┌─────────────────────────────┐ ┌─────────────────────┐
              │  Severity に応じた処理      │ │  CI Passed          │
              │  - error: CI Failed         │ │  - ラベル削除       │
              │  - warning: Annotation      │ │    contract:*       │
              │  - info: ログのみ           │ └─────────────────────┘
              └─────────────────────────────┘
```

---

## 3. GitHub Action

### 3.1 基本的な使用方法

```yaml
# .github/workflows/contract.yml
name: Contract Check

on:
  pull_request:
    branches: [main]
    paths:
      - 'contract.yml'
      - 'contract.*.yml'
      - '**/*'  # または特定のパスのみ

jobs:
  contract:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write  # コメント・ラベル用
      checks: write         # Annotation用
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Contract Check
        uses: pirakansa/contract-action@v1
        with:
          command: check
          strict: false
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 3.2 Action 入力パラメータ

| パラメータ | 必須 | デフォルト | 説明 |
|------------|------|------------|------|
| `command` | No | `check` | 実行コマンド（`validate` / `check` / `diff`） |
| `config` | No | `contract.yml` | Contract ファイルパス |
| `strict` | No | `false` | warning も失敗扱いにする |
| `rules` | No | すべて | 検証ルール（カンマ区切り） |
| `fail-on-warning` | No | `false` | `strict` の別名 |
| `comment` | No | `true` | PR にコメントを投稿する |
| `label` | No | `true` | 違反時にラベルを付与する |
| `annotation` | No | `true` | Annotation を追加する |

### 3.3 Action 出力

| 出力 | 説明 |
|------|------|
| `valid` | 検証結果（`true` / `false`） |
| `error-count` | error 数 |
| `warning-count` | warning 数 |
| `info-count` | info 数 |
| `result-json` | 検証結果の JSON |

```yaml
- name: Contract Check
  id: contract
  uses: pirakansa/contract-action@v1

- name: Handle result
  if: steps.contract.outputs.valid == 'false'
  run: |
    echo "Contract violations found:"
    echo "Errors: ${{ steps.contract.outputs.error-count }}"
    echo "Warnings: ${{ steps.contract.outputs.warning-count }}"
```

---

## 4. Severity 別挙動

### 4.1 挙動マトリクス

| Severity | CI 終了コード | Required Check | コメント | ラベル | Annotation |
|----------|---------------|----------------|----------|--------|------------|
| `error` | 1（失敗） | ❌ Failed | ✅ 投稿 | ✅ `contract:violation` | ✅ Error |
| `warning` | 0（成功） | ✅ Passed | ✅ 投稿 | ✅ `contract:warning` | ✅ Warning |
| `info` | 0（成功） | ✅ Passed | ❌ なし | ❌ なし | ✅ Notice |

### 4.2 --strict モード

`strict: true` 時の挙動：

| Severity | CI 終了コード | Required Check |
|----------|---------------|----------------|
| `error` | 1（失敗） | ❌ Failed |
| `warning` | 1（失敗） | ❌ Failed |
| `info` | 0（成功） | ✅ Passed |

---

## 5. PR コメント

### 5.1 コメント形式

違反検出時、PR に以下のコメントが投稿されます：

```markdown
## 🔴 Contract Violation Detected

The repository does not comply with the defined contract.

### Errors (1)

| Rule | Target | Message |
|------|--------|---------|
| `required_files` | `CONTRIBUTING.md` | File not found |

### Warnings (2)

| Rule | Target | Message |
|------|--------|---------|
| `required_files` | `SECURITY.md` | File not found |
| `branch_protection` | `main` | `required_approving_review_count`: expected 2, got 1 |

---

<details>
<summary>📋 Full Report (JSON)</summary>

```json
{
  "valid": false,
  "summary": { "error": 1, "warning": 2, "info": 0 }
}
```

</details>

---

> 🤖 This comment was generated by [Repo Contract](https://github.com/pirakansa/RepoContract)
```

### 5.2 コメント更新

- 同一 PR で再実行時、既存コメントを**更新**（重複投稿しない）
- 違反解消時、コメントを**成功メッセージに更新**

```markdown
## ✅ Contract Check Passed

All contract rules are satisfied.

| Category | Count |
|----------|-------|
| Errors | 0 |
| Warnings | 0 |
| Info | 2 |
```

---

## 6. ラベル

### 6.1 自動付与ラベル

| ラベル | 条件 | 色 |
|--------|------|-----|
| `contract:violation` | error が 1 つ以上 | `#d73a49` (赤) |
| `contract:warning` | warning が 1 つ以上（error なし） | `#f9c513` (黄) |
| `contract:valid` | すべて成功 | `#28a745` (緑) |

### 6.2 ラベル管理

```yaml
# ラベルの自動作成が必要な場合
- name: Ensure labels exist
  run: |
    gh label create "contract:violation" --color "d73a49" --force || true
    gh label create "contract:warning" --color "f9c513" --force || true
    gh label create "contract:valid" --color "28a745" --force || true
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 6.3 ラベル遷移

```
PR作成 → contract:violation（エラー検出）
       ↓ 修正
       → contract:warning（警告のみ）
       ↓ 修正
       → contract:valid（すべて成功）
```

- 状態変化時、古いラベルは**自動削除**

---

## 7. Annotation

### 7.1 Annotation 形式

GitHub Actions の Annotation 機能を使用して、違反箇所をコード上に表示します。

```
::error file=contract.yml,line=15,col=3::Missing required file: CONTRIBUTING.md
::warning file=contract.yml,line=20,col=3::File not found: SECURITY.md (severity: warning)
::notice file=contract.yml,line=25,col=3::File found: AGENTS.md (info)
```

### 7.2 Files Changed での表示

PR の "Files changed" タブで、該当行に Annotation が表示されます。

---

## 8. Branch Protection 連携

### 8.1 Required Status Check として設定

1. リポジトリ設定 → Branches → Branch protection rules
2. "Require status checks to pass before merging" を有効化
3. "contract" を Required check に追加

```yaml
# contract.yml での定義
branch_protection:
  branches:
    - "main"
  rules:
    required_status_checks:
      enabled: true
      strict: true
      checks:
        - context: "contract"  # このワークフローのジョブ名
```

### 8.2 ステータスチェック名

ワークフロー設定に応じたステータスチェック名：

| ワークフロー設定 | ステータスチェック名 |
|------------------|----------------------|
| `jobs.contract:` | `contract` |
| `jobs.contract-check:` | `contract-check` |
| `name: Contract / Check` | `Contract / Check` |

---

## 9. 高度な設定例

### 9.1 マトリクスビルドとの組み合わせ

```yaml
jobs:
  contract:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        rule: [required_files, branch_protection]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Check ${{ matrix.rule }}
        uses: pirakansa/contract-action@v1
        with:
          rules: ${{ matrix.rule }}
```

### 9.2 条件付き実行

```yaml
jobs:
  contract:
    runs-on: ubuntu-latest
    # contract.yml が変更された場合のみ厳格チェック
    steps:
      - uses: actions/checkout@v4
      
      - name: Check if contract changed
        id: changes
        uses: dorny/paths-filter@v3
        with:
          filters: |
            contract:
              - 'contract.yml'
              - 'contract.*.yml'
      
      - name: Strict check (contract changed)
        if: steps.changes.outputs.contract == 'true'
        uses: pirakansa/contract-action@v1
        with:
          strict: true
      
      - name: Normal check
        if: steps.changes.outputs.contract != 'true'
        uses: pirakansa/contract-action@v1
```

### 9.3 自作 GitHub App との連携

```yaml
jobs:
  contract:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Contract Check
        id: contract
        uses: pirakansa/contract-action@v1
        with:
          comment: false  # 自作 App でコメントする場合は無効化
          label: false
      
      - name: Notify custom app
        if: always()
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.CUSTOM_APP_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d '${{ steps.contract.outputs.result-json }}' \
            https://your-app.example.com/webhook/contract
```

---

## 10. トラブルシューティング

### 10.1 よくある問題

| 問題 | 原因 | 解決策 |
|------|------|--------|
| コメントが投稿されない | `pull-requests: write` 権限不足 | permissions を確認 |
| Annotation が表示されない | `checks: write` 権限不足 | permissions を確認 |
| branch_protection チェックが失敗 | GITHUB_TOKEN 権限不足 | PAT または GitHub App token を使用 |
| ラベルが作成されない | ラベルが存在しない | 事前にラベルを作成 |

### 10.2 デバッグモード

```yaml
- name: Contract Check (debug)
  uses: pirakansa/contract-action@v1
  with:
    command: check
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    ACTIONS_STEP_DEBUG: true  # 詳細ログ有効化
```

---

## 11. Workflow 完全例

```yaml
# .github/workflows/contract.yml
name: Contract

on:
  pull_request:
    branches: [main, 'release/*']
  push:
    branches: [main]
    paths:
      - 'contract.yml'
      - 'contract.*.yml'

concurrency:
  group: contract-${{ github.ref }}
  cancel-in-progress: true

jobs:
  validate:
    name: Validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Validate contract files
        uses: pirakansa/contract-action@v1
        with:
          command: validate

  check:
    name: Check
    needs: validate
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Check repository compliance
        uses: pirakansa/contract-action@v1
        with:
          command: check
          comment: ${{ github.event_name == 'pull_request' }}
          label: ${{ github.event_name == 'pull_request' }}
          annotation: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
