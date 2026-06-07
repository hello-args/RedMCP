# Product Positioning

What **MCTS** (Model Context Threat Scanner) is built for, what it delivers today, and where the roadmap is headed.

---

## What MCTS is

MCTS is a **local-first MCP server security scanner** for authors and platform teams. It discovers tools from Python and TypeScript source (or live stdio probes), runs 19+ analyzers, scores risk, and outputs terminal dashboards, JSON, SARIF, and HTML reports — with CI gates and no cloud API required for core scans.

```bash
mcts scan ./repo/ -o report.json --min-score 70
mcts report report.json -o security-report.html
```

---

## Core strengths

| Area | What MCTS provides |
|------|-------------------|
| **CI adoption** | SARIF 2.1.0, `--min-score`, `--max-critical`, `--fail-on-category`, published GitHub Action |
| **Risk intelligence** | Exponential security score, risk index, auditable `ScoreBasis`, category breakdown |
| **Threat model** | Capability-graph attack chains (read→exfil, read→exec), not keyword-only heuristics |
| **Reporting** | Rich terminal UI, executive HTML dashboard, OWASP mapping, attack graph |
| **Taxonomy** | First-party `MCTS-T-*` techniques and `MCTS-M-*` mitigations on every finding |
| **Discovery** | Repo-wide Python + TypeScript static scan; optional stdio live probe |
| **Inventory** | Local MCP client configs (Cursor, Claude, VS Code, Windsurf) + cross-server shadowing |
| **Probing** | Consent-tiered protocol fuzz (`safe` read-only default); runtime telemetry analyzers |
| **Offline default** | No LLM or vendor API required for standard `mcts scan` |

---

## Primary use cases

1. **Pre-merge security gate** — fail PRs on critical findings or score thresholds  
2. **MCP server author review** — static analysis of tool metadata, schemas, and handler source  
3. **Executive reporting** — share HTML dashboards with security and leadership stakeholders  
4. **Config hygiene** — inventory installed MCP servers and detect tool name collisions  
5. **Regression safety** — technique fixtures and CI harness for detector accuracy  

---

## Capability coverage

| Layer | Shipped | Notes |
|-------|---------|-------|
| Static metadata analysis | Yes | Poisoning, FSP, permissions, shadowing, line jumping |
| Source-aware SAST | Yes | Secrets, command execution, path validation in handlers |
| Live stdio probe | Yes | `--live`; merges protocol schemas with static context |
| Protocol fuzz | Yes | `mcts fuzz`; pipe `runtime_events` into scan |
| Runtime telemetry | Yes | OAuth, rug-pull, injection patterns via `--runtime-events` |
| Attack chains | Yes | Capability-graph BFS on tool profiles |
| Compliance mapping | Yes | OWASP LLM Top 10 meta-findings |
| Regression harness | Yes | 34+ technique fixtures, ≥80% CI gate |

---

## Known gaps (roadmap)

| Gap | MCTS status |
|-----|-------------|
| SSE/HTTP live transports | Planned |
| Deep multi-language SAST (tree-sitter / taint) | Planned — optional extras |
| General-purpose Semgrep layer | Optional extra (roadmap) |
| MCP server mode for IDE agents (`mcts-mcp`) | Planned (Phase 3) |
| Package vetting (`mcts vet`) | Planned (Phase 3) |
| Agent-assisted pentest (`mcts pentest`) | Stub |
| Scan history / trend charts | Planned |
| SBOM / supply-chain depth | Partial today; expansion planned |

---

## Design principles

1. **Deterministic by default** — scores and gates must work without LLM calls  
2. **MCP-boundary focus** — tool metadata, schemas, handlers, configs, protocol behavior  
3. **Consent before execution** — live probe and aggressive fuzz require explicit flags  
4. **Auditable output** — every score traceable via `ScoreBasis`; findings carry `technique_id`  
5. **Lean core install** — live/fuzz behind optional extras  
6. **First-party taxonomy** — `MCTS-T-*` on reports; external frameworks inform patterns only  

---

## Related

- [Architecture](architecture.md)
- [Threat Taxonomy](taxonomy.md)
- [External Frameworks](external-frameworks.md)
- [Roadmap](roadmap.md)
- [CLI Reference](cli.md)
