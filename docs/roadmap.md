# MCTS Roadmap

MCTS aims to become the **default security platform for the MCP ecosystem** — the CVSS-style scorecard, CI gate, and threat intelligence layer for AI agent tooling.

**Detailed implementation guide:** [Feature Expansion Plan](feature-expansion-plan.md) — gap analysis, module layout, build order, and success criteria.

Status labels:

| Label | Meaning |
|-------|---------|
| Shipped | Available in the current release |
| In progress | Actively being built |
| Planned | Scoped for an upcoming phase |
| Future | Longer-term vision |

---

## Vision

Today, MCTS identifies security issues across permissions, prompt injection, tool abuse, data leakage, and attack chains. The next evolution turns those findings into **actionable risk intelligence** that teams can compare, track over time, and enforce in CI/CD — the same way teams use Trivy for containers or Semgrep for code.

**North star:** Make `mcts scan` as standard in MCP projects as `ruff check` is in Python projects.

---

## Current State (Alpha)

| Capability | Status |
|------------|--------|
| Permission analyzer | Shipped |
| Prompt injection simulator | Shipped (heuristic; live probing planned) |
| Tool abuse testing | Shipped |
| Data leakage detection | Shipped (source + metadata) |
| Multi-step attack chain detection | Shipped (hint-based; graph upgrade planned) |
| Compliance checks (OWASP LLM Top 10) | Shipped |
| Exponential risk scoring (score + risk index) | Shipped |
| Terminal UI (Rich, themes, progress animation) | Shipped |
| JSON reports | Shipped |
| HTML security dashboard (`mcts report`) | Shipped |
| Category breakdown (HTML dashboard bars + radar) | Shipped |
| Live stdio probing (`--live`) | Shipped |
| Protocol fuzzing (`mcts fuzz`) | Shipped |
| SARIF output (`--format sarif`) | Shipped |
| CI score thresholds (`--min-score`, `--max-critical`) | Shipped |
| Technique regression harness (34 techniques) | Shipped |
| Runtime telemetry analyzers (`--runtime-events`) | Shipped |
| CLI category breakdown + `--fail-on-category` | Shipped |
| GitHub Action (JSON + SARIF + HTML artifacts) | Shipped — `@v1` tag published |
| Agent pentest (`mcts pentest`) | Planned |
| SSE/HTTP live transports | Planned |

### Known alpha gaps

See [Building in Public](blog-building-mcp-security-in-public.md) and [Feature Expansion Plan — Part 1](feature-expansion-plan.md#part-1--current-state-honest-inventory).

- Multi-file repo discovery shipped; jailbreak analyzer still uses weighted heuristic
- `mcts pentest` remains a stub
- SSE/HTTP live transports not yet implemented
- ~34 / ~75 external-framework techniques covered by regression fixtures (~45%)

---

## Phase 0 — Foundation (Shipped)

> **Goal:** Fix structural limits so new features have a solid base.  
> **Timeline:** ~2–3 weeks. See [Part 4 — Phase 0](feature-expansion-plan.md#phase-0--foundation-23-weeks).

| # | Deliverable | Status |
|---|-------------|--------|
| 0.1 | Multi-file **repository scanning** (`mcts scan ./repo/`) | Done |
| 0.2 | Parse **`input_schema`** + handler snippets | Done |
| 0.3 | **Source-aware analyzers** (secrets in code, command execution, path validation) | Done |
| 0.4 | Fix **placeholder analyzers** + **capability-graph** attack chains | Partial — jailbreak heuristic remains |

**New modules:** `discovery/static.py`, `core/target.py`, analyzers: `schema_surface`, `command_execution`, `path_validation`.

---

## Phase 1 — Adoption & Live Probing (Shipped)

> **Goal:** CI/CD adoption, live MCP enrichment, config inventory.  
> **Timeline:** ~4–6 weeks. See [Part 4 — Phase 1](feature-expansion-plan.md#phase-1--adoption--live-probing-46-weeks).

| # | Deliverable | Status |
|---|-------------|--------|
| 1.1 | CI score thresholds (`--min-score`, `--max-critical`) | Done |
| 1.2 | GitHub Action (JSON + SARIF + HTML) | Done (`@v1` published) |
| 1.3 | SARIF output (`--format sarif`) | Done |
| 1.4 | Live MCP probing (`--live`, stdio) | Done |
| 1.5 | Config inventory (`mcts inventory`) | Done |
| 1.6 | Runtime telemetry analyzers (`--runtime-events`) | Done |
| 1.7 | Technique regression harness (34 techniques, ≥80% gate) | Done |
| 1.8 | CLI category breakdown + `--fail-on-category` gates | Done |

### 1. Security Risk Score (Category Breakdown in CLI) — Shipped

```
Overall Risk Score: 82/100 (Critical)

Breakdown:
  Excessive Permissions      30/30
  Prompt Injection Exposure  20/25
  Data Exfiltration Risk     15/20
  Tool Abuse Potential       12/15
  Secrets Handling            5/10
```

**Flags:** `--min-score 70`, `--max-critical 0`, `--fail-on-category permissions:10`

---

### 2. GitHub Action

Ship a published Action:

```yaml
- uses: MCP-Audit/MCTS@v1
  with:
    target: ./server.py
    fail-on-critical: true
    min-score: 70
```

Upload JSON, SARIF, and HTML artifacts. Implementation: [`action/action.yml`](../action/action.yml) — validated in CI via [`.github/workflows/action-validate.yml`](../.github/workflows/action-validate.yml). Publish with `git tag v1`.

---

### 3. SARIF Output — Shipped

```bash
mcts scan ./server.py -o report.sarif --format sarif
```

Integrations: GitHub Advanced Security, GitLab, Azure DevOps, VS Code Security Panel.

---

### 4. Live MCP Probing — Shipped

```bash
mcts scan --live --command uv --args run,server.py
mcts scan --config ~/.cursor/mcp.json --server my-server
```

Stdio first; consent gate + `--i-understand-live-risk` for CI. Modules: `probe/session.py`, `discovery/live.py`.

---

### 5. Config Inventory — Shipped

```bash
mcts inventory
mcts inventory --scan
```

Discover Cursor, Claude Desktop, VS Code configs. **Cross-server shadowing** analyzer (`MCTS-T-1008`).

---

### 6. Capability Profiles

Per-tool capability dimensions (reads untrusted input, egresses network, executes commands) feed attack chains. HTML **Capability Matrix** section still planned.

---

### 7. MCTS-T Technique Taxonomy — Shipped (core)

`technique_id` on findings; [taxonomy.md](taxonomy.md); bundled Sigma rules. Technique Map in HTML dashboard still planned.

---

### 8. Benchmark Corpus

`examples/bench/` + regression fixtures + [scoring-spec.md](scoring-spec.md) for gate semantics. Expanded corpus still planned.

---

## Phase 2 — Differentiation (Future)

> **Goal:** Threat simulation and probing beyond static heuristics.  
> See [Part 4 — Phase 2](feature-expansion-plan.md#phase-2--differentiation-610-weeks).

| # | Deliverable | Command |
|---|-------------|---------|
| 2.1 | Protocol fuzzing (safe defaults) Yes | `mcts fuzz` — see [fuzzing.md](fuzzing.md) |
| 2.2 | Config audit (no LLM side effects) | `mcts audit-config` |
| 2.3 | Rug-pull baselines Yes | `--baseline` / `--save-baseline` |
| 2.4 | Description vs implementation drift | `ImplementationDriftAnalyzer` |
| 2.5 | TypeScript/JavaScript static discovery Yes | `discovery/static_js.py` — see [typescript-discovery.md](typescript-discovery.md) |
| 2.6 | Scan history + trend chart | `.mcts/history/` |
| 2.7 | Attack simulation mode | `mcts simulate` |
| 2.8 | Visual attack graph export | Mermaid, Graphviz, PNG |
| 2.9 | MCP marketplace scorecards | Public benchmark publishing |

---

## Phase 3 — Platform & Community (Future)

> **Goal:** Recognized security standard in the MCP ecosystem.  
> See [Part 4 — Phase 3](feature-expansion-plan.md#phase-3--platform-10-weeks).

| # | Deliverable |
|---|-------------|
| 3.1 | Package vetting (`mcts vet pypi:…`) |
| 3.2 | Local REST API (`mcts serve`) |
| 3.3 | MCP server mode for IDE agents (`mcts-mcp`) |
| 3.4 | Opt-in LLM review (`--llm-review`) |
| 3.5 | Security baselines (`--profile strict\|balanced\|dev`) |
| 3.6 | Certification badges (`mcts badge`) |
| 3.7 | Expanded benchmark suite (Juice Shop–style MCP corpus) |
| 3.8 | Community hub — research, hall of fame, disclosures |

---

## What We Will Not Build

Stay focused on MCP server-author security. Deferred or out of scope:

- Cloud-dependent analysis APIs (local-first default)
- Agent Guard / runtime monitoring hooks
- General-purpose 1,700-rule SAST
- Gamification or closed-source scanner cores
- Vendoring third-party threat framework corpora (link + map IDs only)

Full rationale: [Feature Expansion Plan — Part 8](feature-expansion-plan.md#part-8--what-not-to-build).

---

## Priority Summary

| Phase | Focus | Key deliverables |
|-------|-------|------------------|
| **Phase 0–1** Yes | Foundation + adoption | Repo scan · SARIF · Action · live probe · inventory · taxonomy · fuzz |
| **Phase 2** | Differentiation | audit-config · trends · simulation · SSE/HTTP |
| **Phase 3** | Platform | Vet · API · MCP tools · certification |

### Suggested build order

```
Week 1-2:  Phase 0 (repo scan, source analyzers, attack graph)
Week 3-4:  SARIF, CI gates, publish Action
Week 5-6:  Live stdio probe
Week 7-8:  Inventory, capability profiles, cross-server
Week 9-10: MCTS-T taxonomy, benchmarks
Week 11+:  Phase 2
```

**First PR bundle:** repo discovery · source leakage/command analyzers · SARIF · `--min-score` · attack graph data fix.

---

## Success Criteria

Phase 1 is complete when:

- [x] CI gates on score/SARIF without cloud APIs
- [x] Scan works on a repo directory
- [x] Live stdio probe optional with consent
- [x] Findings include `technique_id`, `location`, `confidence`
- [x] Attack chains use capability graph
- [x] Benchmark/regression suite prevents detector regressions

Remaining Phase 1 polish: CLI/HTML Technique Map, capability matrix in dashboard, SSE/HTTP transports.

Full checklist: [Feature Expansion Plan — Part 10](feature-expansion-plan.md#part-10--success-criteria).

---

## How to Contribute

1. Read [Feature Expansion Plan](feature-expansion-plan.md) for implementation detail.
2. Pick a phase item and open a [feature request](https://github.com/MCP-Audit/MCTS/issues/new?template=feature_request.yml) or [Discussion](https://github.com/MCP-Audit/MCTS/discussions).
3. See [CONTRIBUTING.md](../CONTRIBUTING.md) for dev setup.

---

## Related

- [Feature Expansion Plan](feature-expansion-plan.md) — Full gap analysis and how-to
- [Architecture](architecture.md) — Current and target pipeline
- [CLI Reference](cli.md) — Commands including planned surface
- [HTML Security Dashboard](html-report.md)
- [Building in Public](blog-building-mcp-security-in-public.md)
