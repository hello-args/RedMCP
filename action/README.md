# MCTS GitHub Action

Run MCTS security scans in your GitHub Actions workflow. The action scans your MCP server, generates JSON + SARIF + HTML reports, and can fail the build on security thresholds.

> **New to MCTS?** See [Getting Started](../docs/get-started/getting-started.md) first.
> **Full CI guide:** [CI Integration](../docs/platform/ci-integration.md)

---

## Quick start

Add this to your workflow file (`.github/workflows/mcp-security.yml`):

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
          target: ./server.py
          fail-on-critical: true
          min-score: "70"

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcts-report.sarif
```

---

## What the action does

1. Installs MCTS from the pinned action ref (`pip install` from the checked-out `MCTS` repo — not PyPI), so the action version always matches the scanner
2. Runs `mcts scan` on your target
3. Writes `mcts-report.json` and `mcts-report.sarif`
4. Generates `mcts-report.html` via `mcts report`
5. Uploads JSON and HTML as workflow artifacts
6. Fails the workflow if `fail-on-critical` or `min-score` thresholds are not met

You upload SARIF separately (step 2 above) to show findings in GitHub's Security tab.

---

## Usage (monorepo / local action)

If the action lives in your repo under `action/`:

```yaml
- uses: ./action
  with:
    target: ./server.py
    fail-on-critical: true
    min-score: "70"
```

---

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `target` | `./server.py` | Path to MCP server entrypoint or repo directory |
| `fail-on-critical` | `true` | Fail workflow if any critical finding is detected |
| `min-score` | — | Fail if overall score is below this threshold (0–100) |

---

## Outputs

| File | Format | Use |
|------|--------|-----|
| `mcts-report.json` | JSON | Full scan report — automation, archiving |
| `mcts-report.sarif` | SARIF | Upload to GitHub Code Scanning |
| `mcts-report.html` | HTML | Human review — download from workflow artifacts |

---

## Related

- [CI Integration](../docs/platform/ci-integration.md) — full CI patterns and gate examples
- [CLI Reference](../docs/platform/cli.md) — all scan flags available locally
- [Scoring Specification](../docs/reporting/scoring-spec.md) — how scores are calculated
- [Documentation index](../docs/index.md)
