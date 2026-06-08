# CI/CD Integration

> [Documentation](../index.md) → [Platform](README.md)

MCTS is designed for **local-first pipeline gates** — no cloud API required for core scans. Use JSON for artifacts, SARIF for GitHub Advanced Security, HTML for human review, and score thresholds to fail builds deterministically.

---

## Integration patterns

| Pattern | When to use | Outputs |
|---------|-------------|---------|
| **Static gate** | Every PR touching MCP server code | JSON + exit code |
| **SARIF upload** | GitHub/GitLab/Azure code scanning | `.sarif` file |
| **HTML artifact** | Security review, executives | `security-report.html` |
| **Live probe** | Staging fixture validation | JSON with merged discovery |
| **Fuzz + scan** | Protocol hardening regression | `fuzz.json` → `--runtime-events` |
| **Inventory audit** | Self-hosted / developer machine | `inventory.json` |

---

## GitHub Actions (published action)

```yaml
name: MCP Security

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  mcts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: MCP-Audit/MCTS@v1
        with:
          target: ./examples/vulnerable-mcp-server/server.py
          fail-on-critical: true
          min-score: "70"

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcts-report.sarif
```

### What the action does

1. Installs MCTS with dependencies
2. Runs `mcts scan` on `target`
3. Writes `mcts-report.json` and `mcts-report.sarif`
4. Runs `mcts report` → `mcts-report.html`
5. Uploads JSON/HTML as workflow artifacts
6. Respects `fail-on-critical` and `min-score` inputs

Monorepo: `uses: ./action`
Full reference: [action/README.md](../../action/README.md)

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `target` | `./server.py` | Scan target path |
| `fail-on-critical` | `true` | Fail workflow on critical findings |
| `min-score` | — | Fail if score below threshold |

---

## Manual CI commands

### Fail on critical findings

```bash
mcts scan ./server.py --fail-on-critical -o report.json
```

### Score threshold

```bash
mcts scan ./repo/ --min-score 70 --max-critical 0 -o report.json
```

Recommended for MCP server repos: start with `--max-critical 0` and `--min-score 70`, tighten over time.

### Category gates

```bash
mcts scan ./repo/ \
  --min-score 70 \
  --fail-on-category permissions:10 \
  --fail-on-category injection:15 \
  --fail-on-category execution:10
```

Category semantics: [Scoring Specification](../reporting/scoring-spec.md).

### SARIF for code scanning

```bash
mcts scan ./server.py --format sarif -o report.sarif
```

Upload with platform-specific actions:

| Platform | Upload step |
|----------|-------------|
| GitHub | `github/codeql-action/upload-sarif@v3` |
| GitLab | Ultimate SAST API or generic artifact |
| Azure DevOps | SARIF upload task |

**Note:** One `mcts scan` invocation writes one format to one `-o` path. For both JSON and SARIF in manual CI, run scan twice or use the GitHub Action.

### HTML artifact for reviewers

```bash
mcts scan ./server.py -o report.json
mcts report report.json -o security-report.html
```

Upload `security-report.html` as a workflow artifact for security team review without cloning the repo.

---

## Recommended workflow (manual install)

```yaml
jobs:
  mcts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v4
      - run: uv sync --all-extras

      - name: Static security scan
        run: |
          uv run mcts scan ./mcp-server/ \
            --no-progress \
            --min-score 75 \
            --max-critical 0 \
            --fail-on-critical \
            -o mcts-report.json

      - name: SARIF export
        if: always()
        run: |
          uv run mcts scan ./mcp-server/ \
            --no-progress \
            --format sarif \
            -o mcts-report.sarif

      - name: HTML dashboard
        if: always()
        run: uv run mcts report mcts-report.json -o mcts-report.html

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcts-report.sarif

      - name: Upload reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: mcts-reports
          path: |
            mcts-report.json
            mcts-report.sarif
            mcts-report.html
```

---

## Live probing in CI

Live scans start a real MCP subprocess. **Only use on trusted fixtures or staging servers you control.**

```bash
export MCTS_LIVE_OK=1
uv sync --extra mcp

uv run mcts scan ./examples/live-mcp-server/server.py \
  --live \
  --no-progress \
  -o report.json \
  --min-score 70
```

Alternative: pass `--i-understand-live-risk` instead of env var.

### Fuzz in CI (safe level)

```bash
MCTS_LIVE_OK=1 uv run mcts fuzz ./server.py \
  --fuzz-level safe \
  --i-understand-live-risk \
  -o fuzz.json

MCTS_LIVE_OK=1 uv run mcts scan ./server.py \
  --runtime-events fuzz.json \
  --no-progress \
  --min-score 70
```

Never run **aggressive** fuzz in CI against shared infrastructure.

---

## Exit codes

| Code | Meaning | Typical CI action |
|------|---------|-------------------|
| **0** | Success; gates passed | Continue pipeline |
| **1** | Gate failure or high/critical fuzz/inventory | Fail job |
| **2** | Usage error, missing consent, probe failure | Fail job (misconfiguration) |

Configure CI to fail on codes 1 and 2.

---

## Inventory in CI

```bash
mcts inventory --scan -o inventory.json
```

Best on **self-hosted runners** or developer machines with MCP client configs installed. Ephemeral GitHub-hosted runners typically have no `~/.cursor/mcp.json` — inventory will return empty.

Use cases:

- Scheduled audit of engineering laptops
- Pre-release config hygiene check
- Detect cross-server tool shadowing before agent deployment

---

## Branch protection

Pair MCTS gates with required CI checks on `main`. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for ruleset setup.

---

## Security considerations

| Topic | Guidance |
|-------|----------|
| Live/fuzz in CI | Trusted targets only; set `MCTS_LIVE_OK` explicitly |
| SARIF contents | May include file paths and finding snippets — treat as security data |
| HTML artifacts | Self-contained; no exfiltration, but contains full scan |
| Secrets in repos | MCTS may flag secrets in scanned source — rotate if leaked in CI logs |

---

## Related

- [CLI Reference](cli.md)
- [Scoring Spec](../reporting/scoring-spec.md)
- [Live Scanning](../scanning/live-scanning.md)
- [Roadmap — GitHub Action](../more/roadmap.md#2-github-action)
