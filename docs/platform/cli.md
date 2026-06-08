# CLI Reference

> [Documentation](../index.md) → [Platform](README.md)

Complete reference for the MCTS command-line interface (`src/mcts/cli/main.py`). All commands use [Typer](https://typer.tiangolo.com/) with Rich terminal output.

**Global options**

| Option | Description |
|--------|-------------|
| `--version` | Print `mcts` version and exit |
| `--help` | Command-specific help |

---

## `mcts scan`

Run a full security scan against an MCP server entrypoint or repository.

```bash
mcts scan <target> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `target` | Path to server file, repository directory, or `.` when using `--config` |

### Output flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | — | Write report to file |
| `--format`, `-f` | `json` | `json`, `sarif`, or `raw` (envelope with `target` + `scan_results`) |

When `-o` is set, format determines serialization. SARIF uses `reporting/sarif.py` for GitHub Code Scanning compatibility.

### CI gate flags

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-on-critical` | false | Exit **1** if any critical finding |
| `--min-score` | — | Exit **1** if `score.overall` < N (0–100) |
| `--max-critical` | — | Exit **1** if critical count > N |
| `--fail-on-category` | — | Repeatable. Format: `category:limit`. Exit **1** when category score ≥ limit |

Valid category keys: `permissions`, `injection`, `execution`, `data_leakage`, `attack_chains`, `shadowing`, `jailbreak`. See [Scoring Specification](../reporting/scoring-spec.md).

### Terminal UI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--theme` | `cyber` | `cyber`, `minimal`, or `github` |
| `--no-progress` | false | Skip pre-report progress animation (CI-friendly) |

### Discovery flags

| Flag | Default | Description |
|------|---------|-------------|
| `--languages` | `python,typescript` | Comma-separated static discovery backends |
| `--live` | false | Connect to live stdio MCP server |
| `--url` | — | Remote MCP URL (streamable HTTP or SSE); implies live |
| `--transport` | `streamable-http` | Remote transport: `streamable-http` or `sse` |
| `--command` | — | Custom launch binary for live mode |
| `--args` | — | Comma-separated args for `--command` |
| `--config` | — | MCP client config JSON path (JSON5/comments supported) |
| `--server` | — | Server name inside `mcpServers` (requires `--config`) |
| `--expand-vars` | `auto` | Expand `$VAR` / `%VAR%` in config commands: `auto`, `linux`, `mac`, `windows`, `off` |
| `--snapshot` | — | Static JSON snapshot (`tools/list` export); no live connection |
| `--surfaces` | all four | Comma-separated: `tool`, `prompt`, `resource`, `instruction` |
| `--resource-mime` | — | Comma-separated MIME allowlist for resource scanning (e.g. `text/plain`) |
| `--i-understand-live-risk` | false | Consent for live/remote probe (or `MCTS_LIVE_OK=1`) |
| `--stderr-file` | — | Capture live server stderr to file |

### Remote auth flags

| Flag | Description |
|------|-------------|
| `--bearer-token` | Bearer token for remote MCP |
| `--header` | Repeatable. `Name: Value` custom HTTP headers |

OAuth client credentials: set via config JSON or env (`oauth_token_url`, `oauth_client_id`, etc.). See [Remote Scanning](../scanning/remote-scanning.md).

### Advanced analysis flags

| Flag | Default | Description |
|------|---------|-------------|
| `--baseline` | — | Compare tool metadata against saved baseline JSON (rug-pull) |
| `--save-baseline` | — | Write current tool metadata snapshot to JSON |
| `--sigma-rules-path` | — | Directory with extra `MCTS-T-*/detection-rule.yml` Sigma rules |
| `--semantic-secrets` | false | Enable semantic credential detection (MCTS-T-1022 / MCTS-M-025) |
| `--runtime-events` | — | JSON file with probe/runtime telemetry rows |
| `--behavioral-probe` | false | Multi-turn MCTS-T-1026 events (auto-enabled with `--live` / `--url`) |
| `--pip-audit` | false | Run pip-audit on `requirements.txt` / `pyproject.toml` |
| `--npm-audit` | false | Run `npm audit` when `package.json` present |
| `--protocol-probe` | false | Active MCPS HTTP checks on `--url` |
| `--yara` | false | Enable YARA metadata analyzer (`uv sync --extra yara`) |
| `--llm-judge` | false | Opt-in LLM-as-judge (`MCTS_LLM_API_KEY`, `--extra llm`) |
| `--cloud-inspect` | false | Opt-in cloud ML API (`MCTS_CLOUD_API_KEY`) |
| `--virustotal` | false | VirusTotal hash lookup (`MCTS_VT_API_KEY`) |

### Filter and output flags

| Flag | Description |
|------|-------------|
| `--terminal-format` | `table`, `by_tool`, `by_analyzer`, `by_severity`, `summary` (instead of Rich dashboard) |
| `--tool-filter` | Comma-separated tool names |
| `--analyzer-filter` | Comma-separated analyzer keys |
| `--severity-filter` | Comma-separated severities |
| `--analyzers` | Run only listed analyzers (subset mode) |
| `--hide-safe` | Hide low-severity informational findings in terminal output |

### Planned flags (not yet implemented)

| Flag | Purpose |
|------|---------|
| `--profile` | Policy profile: `strict`, `balanced`, `dev` |

### Scoring output

Each scan prints:

- **Overall Score** — 0–100, higher is better (`100 × e^(-raw_risk/50)`)
- **Risk Index** — 0–100, higher is worse (`min(100, raw_risk)`)
- **Scoring basis** — severity counts; compliance excluded
- **Category breakdown** — per-dimension risk bars

### Examples

```bash
# Repo scan (Python + TypeScript)
mcts scan ./my-mcp-repo/ -o report.json

# Single file
mcts scan examples/vulnerable-mcp-server/server.py

# Live stdio probe
mcts scan ./server.py --live --i-understand-live-risk

# From Cursor config
mcts scan . --config ~/.cursor/mcp.json --server my-server \
  --live --i-understand-live-risk

# SARIF + CI gates
mcts scan ./server.py -o report.sarif --format sarif \
  --min-score 70 --max-critical 0 --fail-on-critical

# Category gates
mcts scan ./repo/ \
  --fail-on-category permissions:10 \
  --fail-on-category injection:15

# Fuzz telemetry replay
mcts scan ./server.py --runtime-events fuzz.json

# Rug-pull baseline workflow
mcts scan ./server.py --save-baseline baseline.json
mcts scan ./server.py --baseline baseline.json

# TypeScript-only discovery
mcts scan ./node-server/ --languages typescript

# Sigma + semantic secrets
mcts scan ./repo/ \
  --sigma-rules-path ./custom-rules/ \
  --semantic-secrets

# Remote HTTP MCP server
mcts scan . --url https://mcp.example.com/mcp \
  --bearer-token "$TOKEN" --i-understand-live-risk

# Static JSON snapshot (air-gapped CI)
mcts scan . --snapshot ./artifacts/tools-list.json -o report.json

# All MCP surfaces + supply chain
mcts scan ./repo/ \
  --surfaces tool,prompt,resource,instruction \
  --pip-audit --npm-audit

# Table output with filters
mcts scan ./server.py --terminal-format by_severity \
  --severity-filter critical,high
```

---

## Surface subcommands

Targeted scans without passing `--surfaces`:

```bash
mcts scan-prompts <target> [--snapshot path.json]
mcts scan-resources <target> [--snapshot path.json] [--resource-mime text/plain]
mcts scan-instructions <target> [--snapshot path.json]
```

---

## `mcts readiness`

Production readiness checks (separate from security score).

```bash
mcts readiness <target> [--output, -o] [--opa] [--llm-judge]
```

See [Readiness Scanning](../scanning/readiness.md).

---

## `mcts serve`

Start the REST API server (requires `uv sync --extra api`).

```bash
mcts serve [--host 127.0.0.1] [--port 8080] [--reload]
```

See [REST API](rest-api.md).

---

## `mcts report`

Generate an HTML security dashboard from a JSON scan report.

```bash
mcts report <input.json> [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | `security-report.html` | Output HTML path |
| `--theme` | `cyber` | Terminal theme for save notice only |

Input must be valid `ScanReport` JSON from `mcts scan -o`.

See [HTML Security Dashboard](../reporting/html-report.md).

---

## `mcts inventory`

Discover MCP servers configured on this machine.

```bash
mcts inventory [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--scan` | false | Static-scan each entrypoint for tool names |
| `--output`, `-o` | — | Write inventory JSON |
| `--theme` | `cyber` | Terminal theme |

Clients: Cursor, Claude Desktop, VS Code, Windsurf. Exit **1** on critical/high cross-server shadow findings.

See [Config Inventory](../scanning/inventory.md).

---

## `mcts fuzz`

Protocol-level probing against a live stdio MCP server.

```bash
mcts fuzz <target> [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--fuzz-level` | `safe` | `safe`, `standard`, or `aggressive` |
| `--command` | — | Custom server launch command |
| `--args` | — | Comma-separated launch args |
| `--config` | — | MCP client config JSON |
| `--server` | — | Server name in config |
| `--output`, `-o` | — | Write findings + `runtime_events` JSON |
| `--i-understand-live-risk` | false | Live subprocess consent |
| `--i-understand-fuzz-risk` | false | Required for **aggressive** level |
| `--theme` | `cyber` | Terminal theme |

Pipe to scan:

```bash
mcts fuzz ./server.py --i-understand-live-risk -o fuzz.json
mcts scan ./server.py --runtime-events fuzz.json
```

See [Protocol Fuzzing](../scanning/fuzzing.md).

---

## Planned commands

| Command | Status | Description |
|---------|--------|-------------|
| `mcts audit-config` | Planned | Static review of `mcpServers` JSON |
| `mcts simulate` | Planned | Active attack-path simulation |
| `mcts pentest` | Stub | Prints "not yet implemented" |
| `mcts vet` | Planned | Pre-install package vetting |
| `mcts trend` | Planned | Score history from `.mcts/history/` |
| `mcts badge` | Planned | README certification SVG |

See [Roadmap](../more/roadmap.md).

---

## Exit codes

| Code | When |
|------|------|
| **0** | Success; all gates passed |
| **1** | Gate failure; or critical/high fuzz/inventory findings |
| **2** | Usage error, missing consent, probe/fuzz failure, invalid theme/format |

Gate failures (`scan` only): `--fail-on-critical`, `--min-score`, `--max-critical`, `--fail-on-category`.

---

## Environment variables

| Variable | Effect |
|----------|--------|
| `MCTS_LIVE_OK=1` | Grants live/fuzz/remote probe consent in CI |
| `MCTS_BEARER_TOKEN` | Default bearer token for `--url` scans |
| `MCTS_LLM_API_KEY` | LiteLLM provider key for `--llm-judge` |
| `MCTS_LLM_MODEL` | LLM model ID (default `gpt-4o-mini`) |
| `MCTS_CLOUD_API_KEY` | Cloud inspect API key for `--cloud-inspect` |
| `MCTS_CLOUD_ENDPOINT` | Cloud inspect API URL |
| `MCTS_VT_API_KEY` / `VIRUSTOTAL_API_KEY` | VirusTotal API key for `--virustotal` |
| `MCTS_API_KEY` | When set, REST API (`mcts serve`) requires matching `X-API-Key` header |

---

## CI examples

```bash
# Static gate
mcts scan ./server.py --fail-on-critical --min-score 70 -o report.json

# SARIF upload pipeline
mcts scan ./server.py --format sarif -o report.sarif --max-critical 0

# Live on fixture (trusted only)
MCTS_LIVE_OK=1 mcts scan ./fixture/server.py --live --no-progress

# Full artifact chain
mcts scan ./server.py -o report.json
mcts report report.json -o security-report.html
```

GitHub Action: [CI Integration](ci-integration.md) · [`action/action.yml`](../../action/action.yml)

---

## Related

- [Architecture](../analysis/architecture.md)
- [Live Scanning](../scanning/live-scanning.md)
- [Remote Scanning](../scanning/remote-scanning.md)
- [Static Snapshot](../scanning/static-snapshot.md)
- [REST API](rest-api.md)
- [Scoring Specification](../reporting/scoring-spec.md)
- [Getting Started](../get-started/getting-started.md)
