# Getting Started

> [Documentation](../index.md) → **Get Started**

This guide walks you through installing MCTS, running your first scan, and understanding the results. No prior MCP security experience required.

**Time needed:** ~15 minutes for install, first scan, and HTML report.

> Unfamiliar with a term? See the [Glossary](../glossary.md).

---

## What you'll do

By the end of this guide you will:

1. Install MCTS on your machine
2. Scan the included vulnerable example server
3. Read the terminal security report
4. Export JSON and generate an HTML dashboard
5. Know where to go next for CI, live scanning, and advanced features

---

## What is MCTS?

**MCTS** (Model Context Threat Scanner) analyzes MCP servers for security issues. An MCP server is a program that exposes **tools** — callable actions an AI assistant can use (read files, query databases, send messages, etc.).

MCTS reads your server code (or connects to a running server), runs automated security checks, and produces:

- A **security score** from 0 to 100 (100 = no issues found)
- A list of **findings** ranked by severity (Critical → Low)
- Exportable reports in JSON, SARIF, and HTML formats

For the full pipeline design, see [Architecture](../analysis/architecture.md).

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | Required |
| [uv](https://docs.astral.sh/uv/) | Latest recommended | Fast dependency manager used by this repo |
| Git | Any recent | To clone from `MCP-Audit/MCTS` |

### Optional extras

Install these only when you need the corresponding feature:

| Feature | Install command | What it enables |
|---------|-----------------|-----------------|
| Live probing + fuzzing | `uv sync --extra mcp` | Connect to running MCP servers |
| REST API | `uv sync --extra api` | `mcts serve` (FastAPI) |
| YARA rules | `uv sync --extra yara` | `--yara` metadata pattern matching |
| LLM-as-judge | `uv sync --extra llm` | `--llm-judge` (opt-in semantic review) |
| Dependency CVE scan | `uv sync --extra supplychain` | `--pip-audit` |
| Deep TypeScript SAST | `uv sync --extra sast` | Tree-sitter taint analysis |

For your first scan, the base install is enough.

---

## Install

### From PyPI (recommended)

> PyPI distribution: **`mcp-mcts`** (import package and CLI: `mcts`). The shorter name `mcts` is already used by another project on PyPI.

```bash
pip install mcp-mcts
mcts --version
mcts scan --help
```

Add extras when you need them:

```bash
pip install "mcp-mcts[mcp]"          # live probing + fuzzing
pip install "mcp-mcts[api]"          # REST API (`mcts serve`)
pip install "mcp-mcts[supplychain]"    # `--pip-audit` / `--npm-audit`
pip install "mcp-mcts[all]"            # every optional extra
```

### From source (contributors)

```bash
git clone https://github.com/MCP-Audit/MCTS.git
cd MCTS
uv sync --all-extras
```

Verify the CLI works:

```bash
uv run mcts --version
uv run mcts scan --help
```

### Minimal install (static scan only)

If you only want to scan source code without live probing:

```bash
# PyPI
pip install mcp-mcts

# Source
uv sync
uv run mcts scan examples/vulnerable-mcp-server/server.py
```

---

## Example servers

The repo includes demo servers you can scan immediately:

| Path | What it demonstrates | Expected score |
|------|---------------------|----------------|
| `examples/vulnerable-mcp-server/server.py` | Destructive tools, injection, attack chains | ~5/100 (CRITICAL) |
| `examples/safe-mcp-server/server.py` | Minimal, safe tool surface | ~100/100 |
| `examples/medium-risk-mcp-server/server.py` | Moderate findings | ~67/100 |
| `examples/live-mcp-server/server.py` | Live probe + fuzz tests | Varies |
| `examples/prompt-only-server/` | Prompt-surface scanning | Multi-surface demo |

**Start with the vulnerable server** to see a full report with real findings.

---

## Scan your first server

Run this command:

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py
```

### What happens under the hood

1. **Discovery** — MCTS parses the Python file and finds all `@tool` handlers, their descriptions, input schemas, and handler source code
2. **Analysis** — 20 security analyzers check for permissions, injection, secrets, command execution, attack chains, and more
3. **Scoring** — Findings are weighted by severity and converted to a 0–100 score
4. **Report** — Results appear in your terminal

### Reading the output

```text
[✓] Discovering tools...
[✓] Mapping permissions...
[✓] Detecting attack chains...
[✓] Generating report...

==================== MCTS Security Report ====================
Overall Score:   5/100 (CRITICAL)
Risk Index:      100/100
Scoring basis:   3 Critical, 7 High, 2 Medium, 0 Low (12 scorable findings)

● Critical    4
● High        7
● Medium      2
● Low         0
```

| Field | Meaning |
|-------|---------|
| **Overall Score** | 0–100, higher is better. Below 50 is serious. |
| **Risk Index** | 0–100, higher is worse. Linear measure of total risk. |
| **Scoring basis** | How many findings at each severity level contributed to the score |
| **Severity counts** | Total findings including non-scoring compliance items |

Scores are never hardcoded — the scanner verifies its math on every run. Details: [Scoring Specification](../reporting/scoring-spec.md).

### Scan a whole repository

```bash
uv run mcts scan examples/bench/multi-file-server/
```

Directory scans walk the tree, discover Python and TypeScript MCP servers, merge tools by name, and skip test directories and dependencies automatically.

### Terminal themes

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py --theme cyber    # default
uv run mcts scan examples/vulnerable-mcp-server/server.py --theme minimal
uv run mcts scan examples/vulnerable-mcp-server/server.py --no-progress    # CI-friendly
```

---

## Save JSON and SARIF

### JSON (full report)

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
```

The JSON contains everything: server metadata, all findings, score breakdown, and attack chain graph. Use this as input for `mcts report` or CI automation.

### SARIF (GitHub Code Scanning)

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py \
  -o report.sarif --format sarif
```

Upload to GitHub with `github/codeql-action/upload-sarif`. See [CI Integration](../platform/ci-integration.md).

---

## HTML security dashboard

Generate a shareable report for security teams or leadership:

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcts report report.json -o security-report.html
open security-report.html   # macOS
```

The dashboard is a single self-contained HTML file with:

- Score gauge and letter grade (A–F)
- Severity breakdown and category radar chart
- Searchable findings table with remediation advice
- Attack chain visualization
- OWASP LLM Top 10 mapping
- In-browser export (JSON, HTML, PDF)

Full layout reference: [HTML Security Dashboard](../reporting/html-report.md).

---

## Optional: live probing

By default, MCTS reads source code only. **Live mode** starts your server as a subprocess and asks it what tools it actually exposes at runtime.

```bash
uv sync --extra mcp

uv run mcts scan examples/live-mcp-server/server.py \
  --live --i-understand-live-risk
```

Live mode requires explicit consent because it starts a real server process. Add `--i-understand-live-risk` or set `MCTS_LIVE_OK=1` in CI.

Deep dive: [Live Scanning](../scanning/live-scanning.md).

---

## Optional: remote HTTP scanning

Scan a hosted MCP server without local source code:

```bash
uv run mcts scan . \
  --url https://mcp.example.com/mcp \
  --bearer-token "$TOKEN" \
  --i-understand-live-risk
```

See [Remote Scanning](../scanning/remote-scanning.md).

---

## Optional: other scan modes

| Mode | Command | When to use |
|------|---------|-------------|
| Static JSON snapshot | `mcts scan . --snapshot ./tools-list.json` | Air-gapped CI, no network |
| Multi-surface | `mcts scan ./repo/ --surfaces tool,prompt,resource,instruction` | Check prompts and resources too |
| Supply chain | `mcts scan ./repo/ --pip-audit --npm-audit` | Check dependency CVEs |
| Config inventory | `mcts inventory --scan` | Audit MCP servers on your machine |
| Protocol fuzzing | `mcts fuzz ./server.py --i-understand-live-risk` | Test server error handling |
| Readiness | `mcts readiness ./repo/` | Production readiness (non-security) |

Each mode has a dedicated guide in [Scanning](../scanning/README.md).

---

## CI gate

Fail your build when security thresholds aren't met:

```bash
uv run mcts scan ./server.py \
  --fail-on-critical \
  --min-score 70 \
  -o report.json
```

GitHub Action: [CI Integration](../platform/ci-integration.md) · [action/README.md](../../action/README.md)

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Exit code 2, "Live probing requires consent" | Missing consent flag | Add `--i-understand-live-risk` or `MCTS_LIVE_OK=1` |
| Exit code 2, "Unknown format" | Invalid `--format` | Use `json` or `sarif` |
| No tools discovered | Wrong target or empty repo | Point at server entrypoint; check `--languages` |
| Score seems wrong | Compliance findings in report | Only scorable analyzers affect score; check `score.basis` |
| `mcp` import error | Missing extra | `uv sync --extra mcp` |
| Remote scan fails | Missing consent or auth | `--i-understand-live-risk` + `--bearer-token` |
| TS tools missing | Language filter | Use `--languages typescript` |

---

## Next steps

| I want to… | Guide |
|------------|-------|
| See every CLI flag | [CLI Reference](../platform/cli.md) |
| Understand the pipeline | [Architecture](../analysis/architecture.md) |
| Learn what each check does | [Security Checks](../analysis/security-checks.md) |
| Set up CI/CD | [CI Integration](../platform/ci-integration.md) |
| Understand technique IDs | [Threat Taxonomy](../reporting/taxonomy.md) |
| Understand the score formula | [Scoring Specification](../reporting/scoring-spec.md) |
| Look up a term | [Glossary](../glossary.md) |
