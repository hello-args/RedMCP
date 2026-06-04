# MCPAudit

![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Status](https://img.shields.io/badge/status-alpha-orange)
![Security](https://img.shields.io/badge/focus-MCP%20Security-red)

**Offensive security testing framework for Model Context Protocol (MCP) servers.**

Make MCP security testing as easy as running a linter.

```bash
mcpaudit scan ./server.py
```

## Demo

Scan the included vulnerable MCP server:

```bash
uv run mcpaudit scan examples/vulnerable-mcp-server/server.py
```

```
$ mcpaudit scan examples/vulnerable-mcp-server/server.py
[✓] Discovering tools...
[✓] Mapping permissions...
[✓] Detecting attack chains...
[✓] Generating report...

==================== MCPAudit Security Report ====================
Overall Score:   5/100 (CRITICAL)
Risk Index:      100/100
Scoring basis:   3 Critical, 7 High, 2 Medium (12 scorable findings)
Formula:         3×25 + 7×10 + 2×3 = 151 → round(100 × e^(-151/50)) = 5

Severity Summary          Top Findings
● Critical    4           [1] CRITICAL Destructive tool: delete_all_users
● High        7           [2] CRITICAL Read → exfiltration attack chain possible
● Medium      2           ...
```

> **Tip:** Record a terminal GIF of the scan above and add it here as `docs/assets/scan-demo.gif` for maximum README impact.

## Problem

MCP servers expose databases, APIs, file systems, cloud resources, and SaaS tools to AI agents — often without rigorous security review. MCPAudit helps teams find issues before attackers do.

## Features

| Module | Status | Description |
|--------|--------|-------------|
| Permission Analyzer | ✅ Alpha | Flags destructive and over-privileged tools |
| Prompt Injection Simulator | ✅ Alpha | Tests known injection attack patterns |
| Tool Abuse Testing | ✅ Alpha | Detects path traversal and misuse surfaces |
| Data Leakage Detection | ✅ Alpha | Scans for secrets and sensitive references |
| Agent Jailbreak Testing | 🚧 Planned | Resistance scoring against jailbreak suites |
| Multi-Step Attack Chains | ✅ Alpha | Identifies dangerous tool combinations |
| Risk Scoring Engine | ✅ Alpha | Security score + risk index (exponential decay) |
| Terminal UI | ✅ Alpha | Rich dashboard, themes (`cyber`, `minimal`, `github`) |
| Compliance Checks | ✅ Alpha | OWASP LLM Top 10 & MCP best practices |
| CI/CD Integration | 🚧 Planned | GitHub Action for pipeline gates |
| HTML Reports | ✅ Alpha | `mcpaudit report` → `security-report.html` |
| MCP Fuzzer | 🔮 Roadmap | `mcpaudit fuzz` |
| MCPAudit Agent | 🔮 Roadmap | `mcpaudit pentest` |

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended)

### Install

```bash
git clone https://github.com/MCP-Audit/MCPAudit.git
cd MCPAudit
uv sync --all-extras
```

### Scan an MCP server

```bash
uv run mcpaudit scan examples/vulnerable-mcp-server/server.py
```

Save JSON results and generate HTML:

```bash
uv run mcpaudit scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcpaudit report report.json -o security-report.html
```

### CI gate (fail on critical)

```bash
uv run mcpaudit scan ./server.py --fail-on-critical
```

### Themes

```bash
uv run mcpaudit scan ./server.py --theme cyber    # default
uv run mcpaudit scan ./server.py --theme minimal --no-progress
```

## Architecture

```
           ┌──────────────┐
           │ MCP Server   │
           └──────┬───────┘
                  │
                  ▼
         ┌─────────────────┐
         │ MCPAudit Scanner  │
         └─────────────────┘
                  │
     ┌────────────┼────────────┐
     ▼            ▼            ▼
Permission   Injection     Leakage
Analyzer      Engine       Scanner
     ▼            ▼            ▼
       Risk Scoring Engine
                  ▼
          Security Report
```

## Project Structure

```
MCPAudit/
├── src/mcpaudit/          # Main package (src layout)
│   ├── cli/             # Typer CLI (`scan`, `report`, `fuzz`, `pentest`)
│   ├── core/            # Scanner orchestration
│   ├── analyzers/       # Security analyzers
│   ├── scoring/         # Risk scoring engine
│   ├── compliance/      # OWASP & MCP compliance checks
│   ├── reporting/       # Models & HTML reports
│   └── mcp/             # MCP client & discovery
├── tests/               # pytest suite
├── examples/            # Sample vulnerable MCP servers
├── action/              # GitHub Action (planned)
└── docs/                # Documentation
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
| **MCPAudit** | **MCP security** |

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for the phased plan — category risk scoring, GitHub Action, SARIF, attack simulation, and more.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).
