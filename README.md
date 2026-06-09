# MCTS

**Model Context Threat Scanner**

![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Status](https://img.shields.io/badge/status-alpha-orange)
![Security](https://img.shields.io/badge/focus-MCP%20Security-red)

Security scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers — the programs that give AI assistants access to tools, files, databases, and APIs.

Run one command to find permission issues, injection risks, attack chains, and more. Works locally, in CI, with no cloud account required.

> **New to MCP or MCTS?** See the [documentation index](docs/index.md) and [glossary](docs/glossary.md).

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

AI assistants connect to the outside world through **MCP servers** — small programs that expose callable tools (e.g. "delete user", "read file", "query database"). A misconfigured or malicious server can:

- Grant the AI destructive capabilities it shouldn't have
- Hide malicious instructions in tool descriptions
- Chain innocent tools into data theft or remote code execution
- Leak secrets embedded in server source code

Most teams ship MCP servers without dedicated security review. MCTS makes scanning as routine as running a linter.

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

**From PyPI** (recommended for end users):

> Distribution name is **`mcp-mcts`** (the generic `mcts` name is already taken on PyPI). The import package and CLI remain `mcts`.

```bash
pip install mcp-mcts
# or: uv tool install mcp-mcts

# Optional feature extras
pip install "mcp-mcts[mcp]"        # live probing + fuzzing
pip install "mcp-mcts[api]"        # REST API (`mcts serve`)
pip install "mcp-mcts[all]"        # every optional extra
```

**From source** (contributors):

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

Full index: [docs/index.md](docs/index.md) · [Glossary](docs/glossary.md)

**Get started**
- [Install and first scan](docs/get-started/getting-started.md) — step-by-step guide (~15 min)

**Scanning**
- [Live Scanning](docs/scanning/live-scanning.md) · [Remote Scanning](docs/scanning/remote-scanning.md) · [Static Snapshot](docs/scanning/static-snapshot.md) · [Fuzzing](docs/scanning/fuzzing.md) · [Inventory](docs/scanning/inventory.md) · [Readiness](docs/scanning/readiness.md)

**Analysis & reporting**
- [Architecture](docs/analysis/architecture.md)
- [Scoring Spec](docs/reporting/scoring-spec.md) · [Threat Taxonomy](docs/reporting/taxonomy.md) · [HTML Dashboard](docs/reporting/html-report.md)

**Platform**
- [CLI Reference](docs/platform/cli.md) · [REST API](docs/platform/rest-api.md) · [CI Integration](docs/platform/ci-integration.md)

**Planning**
- [Feature Expansion Plan](docs/more/feature-expansion-plan.md) · [Roadmap](docs/more/roadmap.md) · [Product Positioning](docs/more/product-positioning.md)
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

MCTS is **MCP-boundary security** — tool metadata, schemas, handler source, client configs, protocol behavior, and capability-graph attack chains. It complements general AppSec tools; it does not replace Semgrep, Trivy, or enterprise runtime gateways.

| Tool category | Domain | MCTS overlap |
|---------------|--------|--------------|
| General SAST | Application code vulnerabilities | MCP tool poisoning, schema FSP, cross-server shadowing |
| HTTP DAST | Web application surface | MCP protocol + live tool manifest probes |
| Container / dependency scanners | Images and packages | `--pip-audit` / `--npm-audit` at the MCP repo layer |
| Agent fleet scanners | Agent + MCP inventory | Attack chains, MCTS-T taxonomy, readiness/OPA |
| Trust registries | Cloud scan + reputation | MCTS is local-first; no account required for CI |
| Runtime gateways | Runtime policy & governance | Different layer — MCTS scans before deploy; they enforce at runtime |

**Where MCTS leads today:** auditable exponential scoring, capability-graph attack chains, first-party MCTS-T taxonomy with bundled Sigma rules, executive HTML dashboard, readiness + OPA, YARA on metadata, line-jumping detection, local-first default.

**Highest-priority gaps:** Semgrep SAST adapter (+ Java), skills / `SKILL.md` scanning, machine-wide config scan, MCP server mode (`mcts-mcp`), AI-BOM / CycloneDX export, interactive attack-graph UI, runtime stdio proxy, governance YAML policies.

See [Product Positioning](docs/more/product-positioning.md) and [Feature Expansion Plan — Part 11](docs/more/feature-expansion-plan.md#part-11--prioritized-backlog).

## Roadmap

| Doc | Contents |
|-----|----------|
| [Feature Expansion Plan](docs/more/feature-expansion-plan.md) | Full gap analysis, how to implement each capability, module layout, build order |
| [Product Roadmap](docs/more/roadmap.md) | Phased deliverables: foundation → CI adoption → differentiation → platform |

**Next up (Phase 2–3):** Semgrep SAST layer, skills scanning, `mcts-mcp` server mode, AI-BOM export, attack-graph dashboard UI, runtime stdio proxy, `mcts audit-config`, scan history/trends, `mcts pentest`, remote fuzz (`mcts fuzz --url`). Phase 0–1 foundation is shipped — see [Roadmap](docs/more/roadmap.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).
