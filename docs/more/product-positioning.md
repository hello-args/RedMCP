# Product Positioning

> [Documentation](../index.md) → [More](README.md)

What **MCTS** (Model Context Threat Scanner) is built for, who it serves, what it delivers today, and where the roadmap is headed.

---

## What MCTS is

MCTS is a **local-first MCP server security scanner** for server authors, platform security teams, and agent infrastructure engineers. It discovers tools from Python and TypeScript source (or optional live stdio/HTTP/SSE probes), runs 20 analyzers by default (25+ with optional flags), scores risk with auditable math, and outputs terminal dashboards, JSON, SARIF, and executive HTML reports — **without requiring a cloud API** for standard scans.

```bash
mcts scan ./repo/ -o report.json --min-score 70
mcts report report.json -o security-report.html
mcts inventory --scan -o inventory.json
```

MCTS sits at the **MCP boundary**: tool metadata, JSON schemas, handler source, client configs, and protocol behavior — not generic application pentesting.

---

## Who MCTS is for

| Persona | Primary workflow |
|---------|------------------|
| **MCP server author** | Pre-release scan of tool definitions and handler code |
| **Platform / AppSec** | CI gate on MCP repos; SARIF in GitHub Advanced Security |
| **Agent infra team** | Inventory local MCP configs; detect cross-server shadowing |
| **Security leadership** | HTML dashboard for posture reviews and remediation tracking |
| **Research / red team** | Fuzz + runtime telemetry for protocol and metadata attacks |

---

## Core strengths

| Area | What MCTS provides |
|------|-------------------|
| **CI adoption** | SARIF 2.1.0, `--min-score`, `--max-critical`, `--fail-on-category`, published GitHub Action `@v1` |
| **Risk intelligence** | Exponential security score, risk index, auditable `ScoreBasis`, seven category dimensions |
| **Threat model** | Capability-graph attack chains (read→exfil, read→exec), not keyword-only heuristics |
| **Reporting** | Rich terminal UI (3 themes), executive HTML dashboard, OWASP LLM mapping, attack graph |
| **Taxonomy** | First-party `MCTS-T-*` techniques and `MCTS-M-*` mitigations on every finding |
| **Discovery** | Repo-wide Python + TypeScript static scan; optional stdio or remote HTTP/SSE live probe with merge |
| **Inventory** | Cursor, Claude, VS Code, Windsurf configs + MCTS-T-1008 shadow detection |
| **Probing** | Consent-tiered protocol fuzz (`safe` read-only default); runtime telemetry analyzers |
| **Offline default** | No LLM or vendor API required for standard `mcts scan` |
| **Regression safety** | 34+ technique fixtures; CI harness ≥80% accuracy gate |

---

## Primary use cases

### 1. Pre-merge security gate

Fail PRs when critical findings exist or score drops below team threshold:

```bash
mcts scan ./server.py --fail-on-critical --min-score 70 --max-critical 0
```

Integrate via [CI Integration](../platform/ci-integration.md) or GitHub Action.

### 2. MCP server author review

Static analysis of tool metadata, JSON schemas, and handler source before publishing to a registry or sharing with agents. Catches description poisoning, missing path validation, command execution, and excessive permissions.

### 3. Executive reporting

Share HTML dashboards with security and leadership — score gauge, grade, category radar, prioritized recommendations, OWASP mapping. No separate reporting server required.

### 4. Config hygiene

Inventory installed MCP servers and detect tool name collisions across clients:

```bash
mcts inventory --scan
```

Maps to cross-server agent confusion risk (MCTS-T-1008).

### 5. Regression safety for detectors

Technique fixtures under `tests/fixtures/regression/` ensure analyzer changes do not silently reduce coverage.

---

## Capability coverage matrix

| Layer | Shipped | Notes |
|-------|---------|-------|
| Static metadata analysis | Yes | Poisoning, FSP, permissions, shadowing, line jumping |
| Source-aware SAST | Yes | Secrets, command execution, path validation in handlers |
| Live stdio probe | Yes | `--live`; merges protocol schemas with static context |
| Remote HTTP/SSE probe | Yes | `--url` + `--transport`; Bearer/OAuth — see [Remote Scanning](../scanning/remote-scanning.md) |
| REST API | Yes | `mcts serve` — 10 endpoints (`--extra api`) |
| Protocol fuzz | Yes | `mcts fuzz`; pipe `runtime_events` into scan |
| Runtime telemetry | Yes | OAuth, rug-pull, injection via `--runtime-events` |
| Attack chains | Yes | Capability-graph BFS on tool profiles |
| Compliance mapping | Yes | OWASP LLM Top 10 meta-findings (non-scoring) |
| Sigma metadata rules | Yes | Bundled + `--sigma-rules-path` |
| Semantic secrets | Yes | Opt-in `--semantic-secrets` |
| Baseline / rug-pull | Yes | `--baseline` / `--save-baseline` |
| Regression harness | Yes | 34+ fixtures, ≥80% CI gate |
| HTML dashboard | Yes | `mcts report` |
| GitHub Action | Yes | JSON + SARIF + HTML artifacts |

---

## Comparison framing (not competitive benchmarks)

MCTS is complementary to general-purpose tools:

| Tool category | Focus | MCTS focus |
|---------------|-------|------------|
| SAST (Semgrep, CodeQL) | General code vulnerabilities | MCP tool boundary, schemas, agent abuse |
| DAST (ZAP, Burp) | HTTP application surface | MCP protocol + tool metadata |
| Container scanners (Trivy) | Images and OS packages | MCP server behavior and configs |
| **MCTS** | — | **MCP-specific threat model and scoring** |

Run MCTS **in addition to** existing AppSec tooling on MCP server repositories.

---

## Known gaps (roadmap)

| Gap | Status | Target phase |
|-----|--------|--------------|
| Remote protocol fuzz (`mcts fuzz --url`) | Planned | Phase 2 |
| Deep multi-language SAST (tree-sitter / taint) | Partial | Phase 2 — `uv sync --extra sast` |
| General-purpose Semgrep layer | Optional extra | Phase 2 |
| MCP server mode for IDE agents | Planned | Phase 3 |
| Package vetting (`mcts vet`) | Planned | Phase 3 |
| Agent-assisted pentest (`mcts pentest`) | Stub | Phase 3 |
| Scan history / trend charts | Planned | Phase 2 |
| SBOM / supply-chain depth | Partial | Phase 2–3 |

Details: [Product Roadmap](roadmap.md) · [Feature Expansion Plan](feature-expansion-plan.md)

---

## Design principles

1. **Deterministic by default** — scores and gates must work without LLM calls
2. **MCP-boundary focus** — tool metadata, schemas, handlers, configs, protocol behavior
3. **Consent before execution** — live probe and aggressive fuzz require explicit flags
4. **Auditable output** — every score traceable via `ScoreBasis`; findings carry `technique_id`
5. **Lean core install** — live/fuzz behind optional `mcp` extra
6. **First-party taxonomy** — `MCTS-T-*` on reports; external frameworks inform patterns only

---

## Related

- [Architecture](../analysis/architecture.md)
- [Threat Taxonomy](../reporting/taxonomy.md)
- [External Frameworks](external-frameworks.md)
- [Roadmap](roadmap.md)
- [CLI Reference](../platform/cli.md)
