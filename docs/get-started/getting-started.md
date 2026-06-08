# Getting Started

> [Documentation](../index.md) → **Get Started**

**MCTS** (Model Context Threat Scanner) is a local-first security analyzer for Model Context Protocol (MCP) servers. It discovers tools from Python and TypeScript source (or optional live stdio/HTTP/SSE probes), runs 20 security analyzers by default (25+ with optional flags), computes an auditable risk score, and emits terminal dashboards, JSON, SARIF, and shareable HTML reports.

This guide walks through installation, your first scan, export formats, optional live modes, and CI gates. For the full pipeline design, see [Architecture](../analysis/architecture.md).

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | Required |
| [uv](https://docs.astral.sh/uv/) | Latest recommended | Fast dependency management used by this repo |
| Git | Any recent | Clone from `MCP-Audit/MCTS` |

Optional capabilities:

| Capability | Extra | Purpose |
|------------|-------|---------|
| Live stdio + remote HTTP/SSE | `mcp` | Connect to MCP servers via official SDK |
| Protocol fuzzing | `mcp` | Same subprocess transport as live probe |
| REST API | `api` | `mcts serve` (FastAPI + uvicorn) |
| YARA metadata rules | `yara` | `--yara` analyzer |
| LLM-as-judge | `llm` | `--llm-judge` (opt-in) |
| pip-audit | `supplychain` | `--pip-audit` CVE scanning |
| Tree-sitter SAST | `sast` | Deeper TypeScript taint; optional Go/Rust parsers |
| HTML dashboard | Included | `mcts report` (Jinja2 + Chart.js CDN) |

---

## Install

### From source (development)

```bash
git clone https://github.com/MCP-Audit/MCTS.git
cd MCTS
uv sync --all-extras
```

Verify the CLI:

```bash
uv run mcts --version
uv run mcts scan --help
```

### Minimal install (static scan only)

Static repository scanning works without the MCP SDK:

```bash
uv sync
uv run mcts scan examples/vulnerable-mcp-server/server.py
```

### With live probe and fuzz

```bash
uv sync --extra mcp
```

The `mcp` extra installs `mcp>=1.27` for stdio sessions in `probe/session.py` and `fuzz/runner.py`.

---

## Example servers

The repository ships benchmark and demo servers under `examples/`:

| Path | Purpose | Expected score band |
|------|---------|---------------------|
| `examples/vulnerable-mcp-server/server.py` | Demo with destructive tools, injection, chains | ~5/100 (CRITICAL) |
| `examples/safe-mcp-server/server.py` | Minimal safe surface | ~100/100 |
| `examples/medium-risk-mcp-server/server.py` | Moderate findings | ~67/100 |
| `examples/live-mcp-server/server.py` | Live probe + fuzz integration tests | Varies |
| `examples/bench/multi-file-server/` | Multi-file Python discovery | Test fixture |
| `examples/bench/multi-file-ts-server/` | TypeScript `registerTool` discovery | Test fixture |
| `examples/behavioral-fixtures/python_mismatch/` | Description vs handler mismatch demo | Behavioral findings |
| `examples/prompt-only-server/` | Prompt-surface scanning | Multi-surface demo |

Start with the vulnerable server to see a full terminal dashboard and HTML report.

---

## Scan your first server

### Single Python file

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py
```

MCTS will:

1. Parse the entrypoint and walk related Python files (when scanning a directory)
2. Discover `@tool` handlers, `input_schema`, docstrings, and handler source snippets
3. Run all enabled analyzers (permissions, injection, command execution, attack chains, etc.)
4. Enrich findings with `MCTS-T-*` technique IDs
5. Compute score via `RiskScoringEngine` with integrity verification
6. Render the Rich terminal dashboard

### Repository (Python + TypeScript)

```bash
uv run mcts scan examples/bench/multi-file-server/
```

Directory scans default to `--languages python,typescript`. MCTS walks the tree, skips `tests/`, `node_modules`, `.venv`, and other excluded dirs (see `ScanConfig.exclude_dirs` in `core/config.py`), merges tools by name, and prefers the richest schema when duplicates exist.

### Terminal output

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

Scores are **never hardcoded**. The scanner raises if recomputed score does not match findings. Compliance meta-findings (OWASP mapping) are excluded from scoring. Details: [Scoring Specification](../reporting/scoring-spec.md).

### Themes and progress

```bash
# Cyberpunk-style dashboard (default)
uv run mcts scan examples/vulnerable-mcp-server/server.py --theme cyber

# Minimal / GitHub-style palettes
uv run mcts scan examples/vulnerable-mcp-server/server.py --theme minimal
uv run mcts scan examples/vulnerable-mcp-server/server.py --theme github

# Skip pre-scan animation (CI-friendly)
uv run mcts scan examples/vulnerable-mcp-server/server.py --no-progress
```

---

## Save JSON and SARIF

### JSON (full ScanReport)

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
```

The JSON includes `server` (`MCPServerInfo`), `findings`, `summary`, `score` (with `basis`), `attack_graph`, and metadata (`version`, `target`, `scanned_at`).

### SARIF (GitHub Code Scanning)

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py \
  -o report.sarif --format sarif
```

Upload SARIF via `github/codeql-action/upload-sarif` or compatible tools. See [CI Integration](../platform/ci-integration.md).

---

## HTML security dashboard

Share results with security and leadership stakeholders:

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcts report report.json -o security-report.html
open security-report.html   # macOS
```

The dashboard is a **single self-contained HTML file** with:

- Score gauge, letter grade (A–F), severity cards, executive posture summary
- Category breakdown with progress bars and radar chart (vs industry benchmark)
- Searchable findings table, analyzer breakdown, attack chain SVG graph
- OWASP LLM Top 10 mapping, prioritized recommendations
- In-browser export: JSON, HTML save, PDF via print

Full layout reference: [HTML Security Dashboard](../reporting/html-report.md).

---

## Live probing (optional)

Live mode starts a **real stdio MCP subprocess**, calls `list_tools` / `list_prompts` / `list_resources`, and merges results with static analysis when source is available.

```bash
uv sync --extra mcp

uv run mcts scan examples/live-mcp-server/server.py \
  --live --i-understand-live-risk
```

**Consent is mandatory.** Without `--i-understand-live-risk` or `MCTS_LIVE_OK=1`, the CLI exits with code 2.

Common patterns:

```bash
# Custom launch command
uv run mcts scan ./server.py --live --i-understand-live-risk \
  --command uv --args run,server.py

# From Cursor / Claude config (no local source)
uv run mcts scan . --config ~/.cursor/mcp.json --server my-server \
  --live --i-understand-live-risk
```

Deep dive: [Live Scanning](../scanning/live-scanning.md).

---

## Remote HTTP / SSE scanning

Scan hosted MCP servers without local source:

```bash
uv sync --extra mcp

uv run mcts scan . \
  --url https://mcp.example.com/mcp \
  --bearer-token "$TOKEN" \
  --i-understand-live-risk
```

Add `--protocol-probe` for active HTTP security checks. See [Remote Scanning](../scanning/remote-scanning.md).

---

## Static JSON snapshot (air-gapped)

Scan exported tool metadata with no network or subprocess:

```bash
uv run mcts scan . --snapshot ./artifacts/tools-list.json -o report.json
```

See [Static Snapshot](../scanning/static-snapshot.md).

---

## Multi-surface and supply chain

Analyze prompts, resources, and instructions — not only tools:

```bash
uv run mcts scan ./repo/ \
  --surfaces tool,prompt,resource,instruction \
  --pip-audit --npm-audit
```

Surface-focused subcommands (tools still use `mcts scan`):

```bash
uv run mcts scan-prompts examples/prompt-only-server/server.py
uv run mcts scan-resources ./repo/ --live --i-understand-live-risk
uv run mcts scan-instructions ./repo/
```

Export the raw `ScanReport` envelope (no terminal rendering):

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py --format raw -o report.json
```

---

## Behavioral SAST eval

MCTS ships a multi-language behavioral corpus under `eval/behavioral/` for description/code mismatch and taint-flow detection (Python, TypeScript, Go, Rust):

```bash
uv run python scripts/run_behavioral_eval.py
uv run python scripts/run_behavioral_eval.py --json
```

For deeper TypeScript parsing, install the optional SAST extra:

```bash
uv sync --extra sast
```

See `examples/behavioral-fixtures/README.md` for fixture scanning examples.

---

## Readiness checks

Separate from security scoring:

```bash
uv run mcts readiness examples/vulnerable-mcp-server/server.py
uv run mcts readiness examples/vulnerable-mcp-server/server.py --llm-judge  # requires --extra llm
```

Start the REST API (requires `--extra api`):

```bash
uv run mcts serve --host 127.0.0.1 --port 8080
```

See [Readiness Scanning](../scanning/readiness.md) and [REST API](../platform/rest-api.md).

---

## Discover local MCP configs

Audit which MCP servers are configured on this machine:

```bash
uv run mcts inventory
uv run mcts inventory --scan -o inventory.json
```

Supported clients: Cursor, Claude Desktop, VS Code, Windsurf. With `--scan`, MCTS static-scans each entrypoint and lists tool names. Cross-server **tool shadowing** (same tool name on different servers) maps to **MCTS-T-1008**.

Deep dive: [Config Inventory](../scanning/inventory.md).

---

## Protocol fuzzing

Fuzzing sends deterministic JSON-RPC probes to a live stdio server. Default level is **safe** (read-only, no `tools/call`).

```bash
uv run mcts fuzz examples/live-mcp-server/server.py \
  --fuzz-level safe --i-understand-live-risk -o fuzz.json

# Feed fuzz telemetry into full scan
uv run mcts scan examples/live-mcp-server/server.py \
  --runtime-events fuzz.json -o report.json
```

Aggressive fuzz may invoke `tools/call` and requires `--i-understand-fuzz-risk` in addition to live consent.

Deep dive: [Protocol Fuzzing](../scanning/fuzzing.md).

---

## CI gate

Fail builds when security thresholds are not met:

```bash
uv run mcts scan ./server.py \
  --fail-on-critical \
  --min-score 70 \
  --max-critical 0 \
  -o report.json
```

Category gates (repeatable):

```bash
uv run mcts scan ./repo/ \
  --fail-on-category permissions:10 \
  --fail-on-category injection:15
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
| Remote scan fails | Missing consent or auth | `--i-understand-live-risk` + `--bearer-token` or `--header` |
| TS tools missing | Language filter | Default includes `typescript`; use `--languages typescript` |
| Config vars not expanded | Literal `$HOME` in command | `--expand-vars auto` (default) |

---

## Next steps

| Topic | Guide |
|-------|-------|
| All CLI flags and exit codes | [CLI Reference](../platform/cli.md) |
| Pipeline and analyzers | [Architecture](../analysis/architecture.md) |
| TypeScript discovery patterns | [TypeScript Discovery](../scanning/typescript-discovery.md) |
| Technique IDs on findings | [Threat Taxonomy](../reporting/taxonomy.md) |
| Score formula and gates | [Scoring Specification](../reporting/scoring-spec.md) |
| Implementation roadmap | [Feature Expansion Plan](../more/feature-expansion-plan.md) · [Product Roadmap](../more/roadmap.md) |
