# CLI Reference

Commands and flags reflect the current Typer CLI in `src/mcts/cli/main.py`. Planned commands are marked as planned.

---

## `mcts scan`

Run a full security scan against an MCP server entrypoint or repository.

```bash
mcts scan <target> [options]
```

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Write report to file (JSON or SARIF) |
| `--format`, `-f` | `json` (default) or `sarif` |
| `--fail-on-critical` | Exit 1 if critical findings exist |
| `--min-score` | Exit 1 if overall score below threshold (0–100) |
| `--max-critical` | Exit 1 if critical count exceeds limit |
| `--fail-on-category` | Exit 1 when category risk ≥ threshold (e.g. `permissions:10`). Repeatable. |
| `--theme` | Terminal theme: `cyber`, `minimal`, `github` |
| `--no-progress` | Skip pre-report progress animation |
| `--live` | Connect to live stdio MCP server (requires consent) |
| `--command`, `--args` | Custom launch command for live mode |
| `--config`, `--server` | Scan server from client MCP config JSON |
| `--i-understand-live-risk` | Consent for live probing (or `MCTS_LIVE_OK=1` in CI) |
| `--languages` | Discovery languages: `python`, `typescript` (default: both) |
| `--baseline` | Compare tool metadata against saved baseline JSON (rug-pull) |
| `--save-baseline` | Write current tool metadata snapshot to JSON |
| `--sigma-rules-path` | Extra directory with `MCTS-T-*/detection-rule.yml` Sigma rules |
| `--semantic-secrets` | Opt-in semantic credential detection (MCTS-T-1022) |
| `--runtime-events` | JSON file with probe/runtime telemetry for analyzers |
| `--behavioral-probe` | Multi-turn MCTS-T-1026 probe events (auto-enabled with `--live`) |
| `--profile` | Policy profile: `strict`, `balanced`, `dev` (planned) |
| `--llm-review` | Opt-in LLM finding review; requires API key (planned) |

**Target:** path to MCP server file, repository directory, or `.` with `--config` + `--server`.

### Scoring output

Each scan prints:

- **Overall Score** — security score (higher is better), exponential decay on weighted findings
- **Risk Index** — raw risk capped at 100 (higher is worse)
- **Scoring basis** — severity counts (compliance meta-findings excluded)
- **Category breakdown** — per-category risk bars in the terminal dashboard

Details: [Scoring Specification](scoring-spec.md).

### Examples

```bash
# Repo scan (Python + TypeScript)
mcts scan ./my-mcp-repo/ -o report.json

# Live stdio probe
mcts scan ./server.py --live --i-understand-live-risk

# From Cursor config
mcts scan . --config ~/.cursor/mcp.json --server my-server --live --i-understand-live-risk

# SARIF + CI gates
mcts scan ./server.py -o report.sarif --format sarif --min-score 70 --max-critical 0

# Fuzz telemetry replay
mcts scan ./server.py --runtime-events fuzz.json

# Rug-pull baseline
mcts scan ./server.py --save-baseline baseline.json
mcts scan ./server.py --baseline baseline.json
```

---

## `mcts report`

Generate an HTML security dashboard from JSON scan output.

```bash
mcts report report.json [--output security-report.html] [--theme cyber]
```

| Flag | Description |
|------|-------------|
| `--output`, `-o` | HTML report path (default: `security-report.html`) |
| `--theme` | Terminal theme for the success message only |

See [HTML Security Dashboard](html-report.md).

---

## `mcts inventory`

Discover MCP servers configured on this machine.

```bash
mcts inventory
mcts inventory --scan -o inventory.json
```

| Flag | Description |
|------|-------------|
| `--scan` | Static-scan each discovered server entrypoint for tool names |
| `--output`, `-o` | Write inventory JSON report |
| `--theme` | Terminal theme |

Clients: Cursor, Claude Desktop, VS Code, Windsurf. Cross-server shadowing findings may fail the command (exit 1).

See [Config Inventory](inventory.md).

---

## `mcts fuzz`

Protocol-level probing against a live stdio MCP server.

```bash
mcts fuzz <target> --i-understand-live-risk [options]
```

| Flag | Description |
|------|-------------|
| `--fuzz-level` | `safe` (default), `standard`, or `aggressive` |
| `--command`, `--args` | Custom server launch |
| `--config`, `--server` | Launch from client MCP config |
| `--output`, `-o` | Write findings + `runtime_events` JSON |
| `--i-understand-live-risk` | Consent to start subprocess (or `MCTS_LIVE_OK=1`) |
| `--i-understand-fuzz-risk` | Required for **aggressive** (may invoke `tools/call`) |
| `--theme` | Terminal theme |

Pipe output into scan:

```bash
mcts fuzz ./server.py --i-understand-live-risk -o fuzz.json
mcts scan ./server.py --runtime-events fuzz.json
```

See [Protocol Fuzzing](fuzzing.md).

---

## `mcts audit-config` (Planned)

Static review of `mcpServers` JSON without LLM agent tool invocation.

```bash
mcts audit-config ~/.cursor/mcp.json
mcts audit-config ./claude_desktop_config.json --probe
```

---

## `mcts simulate` (Planned)

Active attack-path simulation. See [Roadmap](roadmap.md).

---

## `mcts pentest` (Planned)

AI-assisted penetration testing agent. Stub today — prints "not yet implemented".

---

## `mcts vet` (Planned)

Pre-install package vetting (`pypi:…`, `npm:…`).

---

## `mcts trend` (Planned)

Score history from `.mcts/history/`.

---

## `mcts badge` (Planned)

README certification SVG from scan JSON.

---

## `mcts serve` (Planned)

Local REST API for pipeline integration.

---

## `mcts --version`

Print the installed version.

---

## Exit codes

| Code | When |
|------|------|
| 0 | Success; gates passed |
| 1 | Gate failure or high/critical fuzz/inventory findings |
| 2 | Usage error, missing consent, probe failure |

---

## CI examples

```bash
# Static gate
mcts scan ./server.py --fail-on-critical --min-score 70 -o report.json

# SARIF for GitHub Code Scanning
mcts scan ./server.py --format sarif -o report.sarif --max-critical 0

# Category gates
mcts scan ./repo/ --fail-on-category permissions:10 --fail-on-category injection:15
```

GitHub Action: [CI Integration](ci-integration.md) · [`action/action.yml`](../action/action.yml)

---

## Related

- [Architecture](architecture.md)
- [Live Scanning](live-scanning.md)
- [Scoring Specification](scoring-spec.md)
