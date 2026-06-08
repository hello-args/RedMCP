# MCTS Documentation

**MCTS** (Model Context Threat Scanner) analyzes MCP servers — static and live discovery, 20 security analyzers by default (25+ with optional flags), risk scoring, terminal dashboard, SARIF/JSON, and shareable HTML reports.

This documentation covers installation, every scan mode, the analysis pipeline, scoring and taxonomy, CLI/CI integration, and long-term planning.

---

## What MCTS does

| Stage | Description |
|-------|-------------|
| **Discover** | Python/TS static analysis; stdio + HTTP/SSE live probe; JSON snapshots; client config inventory |
| **Analyze** | 25+ security analyzers on tools, prompts, resources, instructions, handlers, runtime events |
| **Score** | Exponential security score + category breakdown + auditable `ScoreBasis` |
| **Report** | Rich terminal UI, JSON, SARIF, executive HTML dashboard |

Typical commands:

```bash
mcts scan ./repo/ -o report.json --min-score 70
mcts report report.json -o security-report.html
mcts inventory --scan
```

---

## Get Started

New users: install, run the vulnerable example server, export JSON/SARIF/HTML, optional live modes.

- [Install and first scan](get-started/getting-started.md) — step-by-step with troubleshooting

All pages: [get-started/](get-started/README.md)

---

## Scanning

Discovery modes — how MCTS finds MCP servers and collects signal before analysis.

| Guide | Description |
|-------|-------------|
| [Live Scanning](scanning/live-scanning.md) | Stdio MCP probing, consent, config-based launch, runtime events |
| [Remote Scanning](scanning/remote-scanning.md) | HTTP/SSE endpoints, Bearer/OAuth, protocol probes |
| [Static Snapshot](scanning/static-snapshot.md) | Air-gapped scan from exported `tools/list` JSON |
| [Protocol Fuzzing](scanning/fuzzing.md) | Safe/standard/aggressive fuzz levels; pipe into `--runtime-events` |
| [TypeScript Discovery](scanning/typescript-discovery.md) | Node MCP servers without npm install |
| [Config Inventory](scanning/inventory.md) | Cursor, Claude, VS Code, Windsurf; cross-server shadowing |
| [Readiness Scanning](scanning/readiness.md) | Production readiness heuristics (`mcts readiness`) |

All pages: [scanning/](scanning/README.md)

---

## Analysis

How findings are produced from discovered tools and source code.

| Guide | Description |
|-------|-------------|
| [Security Checks Reference](analysis/security-checks.md) | Every analyzer — what it detects, examples, flags to enable |
| [Architecture](analysis/architecture.md) | Full pipeline: data models, discovery, 20+ analyzers, scoring, reporting |

All pages: [analysis/](analysis/README.md)

---

## Reporting

Scores, taxonomies, and shareable output formats.

| Guide | Description |
|-------|-------------|
| [HTML Security Dashboard](reporting/html-report.md) | Layout, pages, export, design system, implementation |
| [Scoring Specification](reporting/scoring-spec.md) | Formula, categories, CI gates, worked examples |
| [Threat Taxonomy](reporting/taxonomy.md) | MCTS-T techniques, MCTS-M mitigations, Sigma rules |

All pages: [reporting/](reporting/README.md)

---

## Platform

CLI commands, flags, exit codes, and CI/CD integration.

| Guide | Description |
|-------|-------------|
| [CLI Reference](platform/cli.md) | Complete `scan`, `report`, `inventory`, `fuzz`, `readiness`, `serve` |
| [REST API](platform/rest-api.md) | `mcts serve` — FastAPI scan endpoint |
| [CI Integration](platform/ci-integration.md) | GitHub Action, SARIF, gates, workflow patterns |

All pages: [platform/](platform/README.md)

---

## More

Planning, positioning, and external references.

| Guide | Description |
|-------|-------------|
| [Feature Expansion Plan](more/feature-expansion-plan.md) | Gap analysis, phased implementation, module layout |
| [Product Roadmap](more/roadmap.md) | Phases from foundation → platform |
| [Product Positioning](more/product-positioning.md) | Strengths, personas, use cases, design principles |
| [External Frameworks](more/external-frameworks.md) | How industry taxonomies relate to MCTS-T |
| [Feature matrix (README)](../README.md#features) | Current module status |

All pages: [more/](more/README.md)

---

## Changelog

- [Changelog](../CHANGELOG.md) — User-facing release notes

---

## Contributing

- [CONTRIBUTING.md](../CONTRIBUTING.md) — Development workflow, analyzer guide
- [SECURITY.md](../SECURITY.md) — Vulnerability reporting and safe usage
