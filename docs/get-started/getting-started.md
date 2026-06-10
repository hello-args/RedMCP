# Getting Started

> [Documentation](../index.md) → **Get Started**

This guide walks you through installing MCTS, running your first scan, and understanding the results. No prior MCP security experience required.

**Time needed:** ~15 minutes.

| Where to go next | Link |
|------------------|------|
| Pick a scan mode (live, remote, snapshot…) | [Which scan mode should I use?](../scanning/README.md#which-scan-mode-should-i-use) |
| Set up CI | [CI integration](../platform/ci-integration.md) |
| Every flag and command | [CLI reference](../platform/cli.md) |
| Full doc index | [Documentation map](../index.md#documentation-map) |

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
| LLM-as-judge / triage | `uv sync --extra llm` | `--llm-judge`, `--llm-triage` (opt-in semantic review) |
| Semgrep SAST | `uv sync --extra semgrep` | `--semgrep` (also requires `semgrep` CLI on PATH) |
| Dependency CVE scan | `uv sync --extra supplychain` | `--pip-audit` |
| Deep TypeScript SAST | `uv sync --extra sast` | Tree-sitter taint analysis |
| MCP server mode | `uv sync --extra mcp` | `mcts-mcp` for IDE agent integration |

For your first scan, the base install is enough.

If `mcts doctor .` reports `Extra [mcp]` as missing, install that optional extra before using `mcts-mcp`, `mcts scan --live`, or `mcts fuzz`.

---

## Install

### Recommended (isolated)

> PyPI distribution: **`mcp-mcts`** (import package and CLI: `mcts`). The shorter name `mcts` is already used by another project on PyPI.

```bash
# Scan without installing
uvx mcp-mcts scan examples/vulnerable-mcp-server/server.py

# One-off live scan with MCP extra (no global install)
uvx --from 'mcp-mcts[mcp]' mcts scan ./server.py --live --i-understand-live-risk

# Or install in an isolated tool environment
pipx install 'mcp-mcts[mcp]'
uv tool install mcp-mcts
mcts --version
```

| Install | Use case |
|---------|----------|
| `uvx mcp-mcts` | One-off static scan |
| `pipx install mcp-mcts` | Global isolated CLI |
| `pip install mcp-mcts[mcp]` | Live probing in a dedicated venv |
| `pip install mcp-mcts[all]` | All extras except LLM (no `litellm`) |
| `pip install 'mcp-mcts[all,llm]'` | Full analyzer set including `--llm-judge` |

### From PyPI (dedicated environment)

Use a **separate** virtualenv — not your application's dev `.venv`:

```bash
pip install mcp-mcts
mcts scan --help
```

Add extras when you need them (avoid `[all]` in app venvs):

```bash
pip install "mcp-mcts[mcp]"          # live probing + fuzzing
pip install "mcp-mcts[api]"          # REST API (`mcts serve`)
pip install "mcp-mcts[supplychain]"  # `--pip-audit` / `--npm-audit`
pip install "mcp-mcts[llm]"          # `--llm-judge` / `--llm-triage`
pip install "mcp-mcts[semgrep]"      # `--semgrep` SAST adapter
pip install "mcp-mcts[mcp]"          # live probing + fuzzing + `mcts-mcp`
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
| `examples/baseline-mcp-server/server.py` | Minimal, safe tool surface | ~100/100 |
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
2. **Analysis** — 25+ security analyzers check for permissions, injection, secrets, command execution, attack chains, and more
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

### Scan prompts and instructions in a repo

Agent projects often store prompts in markdown (`system_prompt.md`, `skills/*/SKILL.md`) rather than MCP `prompts/list`. MCTS discovers these files by default on static scans:

```bash
# Prompt/instruction surfaces only (skips supply-chain noise on pyproject.toml)
uv run mcts scan . --surfaces prompt,instruction

# Skills tree only
uv run mcts scan ./skills --surfaces prompt,instruction

# Explicit files or globs
uv run mcts scan . --instruction-file src/agent/system_prompt.md
uv run mcts inventory --skills --skills-dir ./skills
```

Disable repo markdown discovery with `--no-discover-instructions` when you only want MCP tool metadata from source code. See [Security checks — metadata poisoning](../analysis/security-checks.md#2-metadata-poisoning-and-injection).

### Terminal themes

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py --theme cyber    # default
uv run mcts scan examples/vulnerable-mcp-server/server.py --theme minimal
uv run mcts scan examples/vulnerable-mcp-server/server.py --no-progress    # CI-friendly
```

---

## Save JSON and SARIF

By default, every scan writes artifacts to **`mcts_analysis/`** in your project folder:

| File | Purpose |
|------|---------|
| `scan-report.json` | Full machine-readable report |
| `scan-report.html` | Executive HTML dashboard (open directly) |
| `scan-report.sarif` | GitHub Code Scanning upload |
| `history.json` | Score trend across runs |

Relative `-o` paths use the **basename only** under `mcts_analysis/` — e.g. `-o report.json` → `mcts_analysis/report.json`, not `./report.json`.

### JSON (full report)

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
# → writes mcts_analysis/report.json (+ HTML + SARIF)
```

The JSON contains everything: server metadata, all findings, score breakdown, and attack chain graph. Use this for CI automation or `mcts report` (paths auto-resolve under `mcts_analysis/`).

### SARIF (GitHub Code Scanning)

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py \
  -o report.sarif --format sarif
# → writes mcts_analysis/report.sarif
```

Upload to GitHub with `github/codeql-action/upload-sarif`. See [CI Integration](../platform/ci-integration.md).

---

## HTML security dashboard

Every scan already writes **`mcts_analysis/scan-report.html`**. Open it directly after scanning — no extra step required.

To regenerate HTML from an existing JSON file:

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
open mcts_analysis/scan-report.html   # macOS — written automatically on scan
# optional:
uv run mcts report report.json        # resolves to mcts_analysis/report.json
```

The dashboard is a single self-contained HTML file with:

- Score gauge, letter grade, and partitioned area scores
- Severity breakdown and category radar chart
- Searchable findings table (location, CWE, technique links, expandable evidence)
- Full **MCTS-T technique grid** (79 techniques) with Detected / Clear filters
- **Tool capability matrix** and attack chain visualization
- **OWASP LLM + MCP Top 10** mapping with coverage gap cards
- Scan history trend chart
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

## Other scan modes

Most users start with a **static scan** (`mcts scan ./server.py`). When you need something else:

| If you… | Read |
|---------|------|
| Have source code on disk (default) | You're in the right place — keep reading below |
| Need to probe a running server | [Live scanning](../scanning/live-scanning.md) |
| Have a hosted URL, no source | [Remote scanning](../scanning/remote-scanning.md) |
| Have exported JSON, no network | [Static snapshot](../scanning/static-snapshot.md) |
| Aren't sure which applies | [Which scan mode should I use?](../scanning/README.md#which-scan-mode-should-i-use) |

**Also useful:** `mcts inventory --scan` (audit local configs) · `mcts scan --machine-wide` (all configs) · `mcts doctor .` (preflight) · [full task list](../index.md#i-want-to)

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

## Optional: one-command auto scan

When you are unsure which entrypoint or MCP config to use:

```bash
mcts scan . --auto
mcts scan . --auto --auto-server my-server -o report.json --html report.html
```

`--auto` picks a single entrypoint, a lone config server, or falls back to repo scan. It never enables live probing.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `externally-managed-environment` / PEP 668 | `pip install` into system Python | Use `uvx mcp-mcts`, `pipx install mcp-mcts`, or a dedicated venv |
| `mcts: command not found` | Tool not on PATH | `pipx ensurepath`, `uv tool update-shell`, or use `uvx mcp-mcts` |
| Dependency conflicts after install | MCTS installed in app `.venv` | Use isolated install; avoid `pip install mcp-mcts[all]` in app venv |
| Exit code 2, "Live probing requires consent" | Missing consent flag | Add `--i-understand-live-risk` or `MCTS_LIVE_OK=1` |
| Exit code 2, "Unknown format" | Invalid `--format` | Use `json` or `sarif` |
| No tools discovered | Wrong target or empty repo | Point at server entrypoint; check `--languages` |
| Score seems wrong | Compliance findings in report | Only scorable analyzers affect score; check `score.basis` |
| `mcp` import error | Missing extra | `uv sync --extra mcp` or `uvx --from 'mcp-mcts[mcp]' mcts …` |
| Remote scan fails | Missing consent or auth | `--i-understand-live-risk` + `--bearer-token` |
| TS tools missing | Language filter | Use `--languages typescript` |

---

## Next steps

| I want to… | Guide |
|------------|-------|
| Pick live vs remote vs snapshot | [Which scan mode?](../scanning/README.md#which-scan-mode-should-i-use) |
| See every CLI flag | [CLI reference](../platform/cli.md) |
| Understand a finding | [Security checks](../analysis/security-checks.md) |
| Set up CI/CD | [CI integration](../platform/ci-integration.md) |
| Full doc map | [Documentation index](../index.md) |
