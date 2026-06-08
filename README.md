# MCTS

**Model Context Threat Scanner**

![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Status](https://img.shields.io/badge/status-alpha-orange)
![Security](https://img.shields.io/badge/focus-MCP%20Security-red)

Security analysis purpose-built for Model Context Protocol (MCP) servers — permissions, injection, attack chains, and risk scoring.

Make MCP threat scanning as easy as running a linter.

```bash
mcts scan ./server.py
```

## Demo

Scan the included vulnerable MCP server:

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py
```

```
$ mcts scan examples/vulnerable-mcp-server/server.py
[✓] Discovering tools...
[✓] Mapping permissions...
[✓] Detecting attack chains...
[✓] Generating report...

==================== MCTS Security Report ====================
Overall Score:   5/100 (CRITICAL)
Risk Index:      100/100
Scoring basis:   3 Critical, 7 High, 2 Medium (12 scorable findings)

Severity Summary          Top Findings
● Critical    4           [1] CRITICAL Destructive tool: delete_all_users
● High        7           [2] CRITICAL Read → exfiltration attack chain possible
● Medium      2           ...
```

> **Tip:** Record a terminal GIF of the scan above and add it here as `docs/assets/scan-demo.gif` for maximum README impact.

## Problem

MCP servers expose databases, APIs, file systems, cloud resources, and SaaS tools to AI agents — often without rigorous security review. MCTS helps teams find issues before attackers do.

## Features

| Module | Status | Description |
|--------|--------|-------------|
| Repository scanning | Alpha | `mcts scan ./repo/` — Python + TypeScript discovery |
| Multi-surface scanning | Alpha | Tools, prompts, resources, instructions (`--surfaces`) |
| Remote HTTP/SSE probing | Alpha | `--url` with Bearer/OAuth; streamable HTTP + SSE |
| Static JSON snapshot | Alpha | `--snapshot` for air-gapped CI from `tools/list` JSON |
| Permission & metadata analyzers | Alpha | Destructive tools, poisoning, schema surface (FSP) |
| Source-aware SAST | Alpha | Secrets, command execution, path validation, behavioral static |
| Supply chain CVE scan | Alpha | `--pip-audit`, `--npm-audit` |
| Runtime telemetry analyzers | Alpha | OAuth, rug-pull, injection — via `--runtime-events` / `--live` |
| Multi-step attack chains | Alpha | Capability-graph chain detection |
| Live stdio probing | Alpha | `--live` merges MCP protocol schemas with static analysis |
| Config inventory | Alpha | `mcts inventory` — Cursor, Claude, VS Code, Windsurf |
| Protocol fuzzing | Alpha | `mcts fuzz` — safe read-only probes by default |
| Readiness scanning | Alpha | `mcts readiness` — HEUR-001–020 + OPA + LLM judge (opt-in) |
| Surface subcommands | Alpha | `mcts scan-prompts`, `scan-resources`, `scan-instructions` |
| REST API | Alpha | `mcts serve` — 10 endpoints (`--extra api`) |
| Raw envelope output | Alpha | `--format raw` for CI pipelines |
| Optional analyzers | Alpha | YARA, LLM judge, cloud inspect, VirusTotal (opt-in) |
| Risk scoring engine | Alpha | Exponential score + risk index + category breakdown |
| MCTS-T taxonomy | Alpha | Technique/mitigation IDs + AITech crosswalk on findings |
| Terminal UI | Alpha | Rich dashboard + `--terminal-format` table views |
| SARIF + CI gates | Alpha | `--format sarif`, `--min-score`, `--fail-on-category` |
| GitHub Action | Alpha | JSON + SARIF + HTML artifacts (`@v1`) |
| HTML security dashboard | Alpha | `mcts report` — gauge, grades, OWASP, attack chains |
| Compliance checks | Alpha | OWASP LLM Top 10 mapping |
| MCTS Agent | Roadmap | `mcts pentest` (stub) |

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended)

### Install

```bash
git clone https://github.com/MCP-Audit/MCTS.git
cd MCTS
uv sync --all-extras
```

### Scan an MCP server

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py
```

Save JSON and generate an executive HTML dashboard:

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcts report report.json -o security-report.html
open security-report.html
```

The HTML report includes a dark-themed overview (score gauge, letter grade, severity cards, posture summary), risk breakdown with radar chart, searchable findings, attack chain graph, OWASP mapping, and in-browser export (JSON / HTML / PDF). See [docs/reporting/html-report.md](docs/reporting/html-report.md).

### CI gate (fail on critical or score)

```bash
uv run mcts scan ./server.py --fail-on-critical --min-score 70
uv run mcts scan ./server.py -o report.sarif --format sarif
```

See [docs/platform/ci-integration.md](docs/platform/ci-integration.md) and [action/README.md](action/README.md).

### Themes

```bash
uv run mcts scan ./server.py --theme cyber    # default
uv run mcts scan ./server.py --theme minimal --no-progress
```

## Architecture

```
  MCP server (file / repo / config)
              │
              ▼
     Discovery (static Py+TS, live stdio/HTTP, JSON snapshot)
              │
              ▼
     25+ security analyzers + compliance + MCTS-T taxonomy
     (20 enabled by default)
              │
              ▼
        Risk scoring engine
              │
    ┌─────────┼─────────┐
    ▼         ▼         ▼
 Terminal   JSON/     HTML dashboard
 dashboard  SARIF    (mcts report)
```

## Documentation

Full index: [docs/index.md](docs/index.md)

**Get started**
- [Install and first scan](docs/get-started/getting-started.md)

**Scanning**
- [Live Scanning](docs/scanning/live-scanning.md) · [Remote Scanning](docs/scanning/remote-scanning.md) · [Static Snapshot](docs/scanning/static-snapshot.md) · [Fuzzing](docs/scanning/fuzzing.md) · [Inventory](docs/scanning/inventory.md) · [Readiness](docs/scanning/readiness.md)

**Analysis & reporting**
- [Architecture](docs/analysis/architecture.md)
- [Scoring Spec](docs/reporting/scoring-spec.md) · [Threat Taxonomy](docs/reporting/taxonomy.md) · [HTML Dashboard](docs/reporting/html-report.md)

**Platform**
- [CLI Reference](docs/platform/cli.md) · [REST API](docs/platform/rest-api.md) · [CI Integration](docs/platform/ci-integration.md)

**Planning**
- [Feature Expansion Plan](docs/more/feature-expansion-plan.md) · [Roadmap](docs/more/roadmap.md)
- [Changelog](CHANGELOG.md)

## Project Structure

```
MCTS/
├── src/mcts/          # Main package (src layout)
│   ├── cli/             # Typer CLI (`scan`, `report`, `inventory`, `fuzz`, `readiness`, `serve`)
│   ├── core/            # Scanner orchestration, ScanConfig
│   ├── discovery/       # Static (Python/TS), live, JSON snapshot, merge
│   ├── probe/           # Stdio + HTTP sessions, auth, protocol checks
│   ├── analyzers/       # 25+ security analyzers
│   ├── readiness/       # Production readiness heuristics
│   ├── api/             # FastAPI REST server
│   ├── inventory/       # Client config discovery
│   ├── fuzz/            # Protocol fuzz runner
│   ├── taxonomy/        # MCTS-T techniques, Sigma rules
│   ├── scoring/         # Risk scoring engine
│   ├── compliance/      # OWASP & MCP compliance checks
│   ├── reporting/       # ScanReport models, SARIF, HTML entry
│   ├── report/          # HTML dashboard (templates, CSS, JS)
│   ├── ui/              # Terminal dashboard (Rich)
│   └── mcp/             # MCPServerInfo models
├── tests/               # pytest suite + regression fixtures
├── examples/            # Sample MCP servers & benchmarks
├── action/              # GitHub Action (`@v1`)
└── docs/                # Documentation
    ├── get-started/     # Install and first scan
    ├── scanning/        # Live, fuzz, TS discovery, inventory
    ├── analysis/        # Pipeline architecture
    ├── reporting/       # Scoring, taxonomy, HTML dashboard
    ├── platform/        # CLI and CI
    └── more/            # Roadmap and planning
```

## Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check src tests
uv run ruff format src tests
pre-commit install
```

## Positioning

| Tool | Domain |
|------|--------|
| SonarQube | Code quality |
| OWASP ZAP | Web security |
| Trivy | Container security |
| Semgrep | Static analysis |
| **MCTS** | **MCP security** |

## Roadmap

| Doc | Contents |
|-----|----------|
| [Feature Expansion Plan](docs/more/feature-expansion-plan.md) | Full gap analysis, how to implement each capability, module layout, build order |
| [Product Roadmap](docs/more/roadmap.md) | Phased deliverables: foundation → CI adoption → differentiation → platform |

**Next up:** `mcts audit-config`, scan history/trends, `mcts pentest` agent, multi-language behavioral SAST. Phase 0–2 foundation (repo scan, SARIF, live + remote probe, multi-surface, inventory, taxonomy) is shipped — see [Roadmap](docs/more/roadmap.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).
