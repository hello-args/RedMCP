# MCTS Feature Expansion Plan

Detailed gap analysis and implementation guide for evolving MCTS from alpha static scanner to a full MCP security platform. This plan is **original MCTS architecture** — informed by [product positioning](product-positioning.md) and [external frameworks](external-frameworks.md).

**Related:** [Product Roadmap](roadmap.md) · [Architecture](architecture.md) · [CLI Reference](cli.md)

---

## Part 1 — Current State (Honest Inventory)

### Shipped and real

| Layer | Files | What actually works |
|-------|-------|---------------------|
| **Orchestration** | `core/scanner.py`, `core/config.py` | 20+ analyzers → compliance → scoring → `ScanReport` |
| **Discovery** | `discovery/*`, `mcp/client.py` | Multi-file Python + TypeScript static discovery; live stdio merge |
| **Analyzers** | `analyzers/*.py` | Metadata, SAST, runtime events, Sigma, OAuth, supply chain, fuzz |
| **Attack chains** | `attack_chains.py` | Hint-based chains (capability-graph upgrade planned) |
| **Scoring** | `scoring/engine.py` | Exponential decay + auditable `ScoreBasis` |
| **Compliance** | `compliance/checks.py` | OWASP LLM meta-findings |
| **CLI** | `cli/main.py` | `scan`, `report`, `inventory`, `fuzz`; stub `pentest` |
| **Terminal UI** | `ui/*` | Rich themes, progress, report renderer |
| **HTML dashboard** | `report/*`, `reporting/html.py` | Full executive UI from JSON |
| **Tests** | `tests/` | 138+ tests incl. technique regression (34 techniques) |
| **CI** | `action/action.yml`, `.github/workflows/ci.yml` | SARIF scan validation; Action ready for `@v1` tag |

### Placeholder / aspirational

- `PromptInjectionAnalyzer` — keyword match, payloads never sent
- `JailbreakAnalyzer` — fires when `len(tools) >= 5`
- `DataLeakageAnalyzer` — scans tool metadata only, not source file
- `MCPClient` — live stdio probe shipped; SSE/HTTP transports planned
- `mcts pentest` — stub only
- Score history / `--fail-on-category` — planned

### Architectural strengths to preserve

1. **Attack-chain-first threat model** — core differentiator
2. **Auditable exponential scoring** — extend with category gates
3. **HTML executive dashboard** — feed it better data
4. **Local-first, deterministic default** — no cloud API dependency
5. **Modular `BaseAnalyzer`** — natural extension point

---

## Part 2 — Industry Capabilities → MCTS Equivalents

| Industry capability | MCTS equivalent (original design) | Priority |
|----------------------|---------------------------------------|----------|
| Live MCP handshake | `ProbeSession` + `LiveDiscovery` | P0 |
| Client config discovery | `mcts inventory` | P1 |
| Multi-file / repo scan | `ScanTarget` (repo, not file) | P0 |
| Source-level SAST | `SourceAnalyzer` (AST, not regex-only) | P0 |
| Tool description poisoning | `MetadataIntegrityAnalyzer` | P0 |
| Schema poisoning (FSP) | `SchemaSurfaceAnalyzer` | P1 |
| Tool shadowing | `CrossServerAnalyzer` (config mode) | P1 |
| Toxic capability labels | `CapabilityProfile` per tool | P1 |
| Behavioral doc vs code mismatch | `ImplementationDriftAnalyzer` | P2 |
| Rug-pull / baseline diff | `ManifestBaselineStore` | P2 |
| Supply chain / deps | `DependencyPostureAnalyzer` | P2 |
| Package pre-install scan | `mcts vet <package>` | P3 |
| MCTS threat taxonomy | `technique_id` + `mitigation_ids` on `Finding` | P1 |
| SARIF / CI gates | `reporting/sarif.py` + published Action | P0 |
| REST API | `mcts serve` (optional) | P3 |
| MCP server mode | `mcts-mcp` stdio tools | P3 |
| LLM semantic review | `mcts review --llm` (opt-in) | P3 |
| Skills scanning | `mcts inventory --skills` | P3 |
| Fuzzing | `mcts fuzz` (protocol probes) | P2 |
| Config red-team | `mcts audit-config` (dry-run) | P2 |
| Benchmark corpus | `examples/` + `benchmarks/expected/` | P1 |
| Trend / history | `.mcts/history/` | P2 |

---

## Part 3 — Target Architecture

Evolve from “single-file static parser” to a **three-layer pipeline**:

```
┌─────────────────────────────────────────────────────────────────┐
│                        ScanTarget                                │
│  (file | repo | config | live_command | remote_url)              │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Discovery Layer                              │
│  StaticDiscovery │ LiveDiscovery │ ConfigDiscovery             │
│  → MCPServerInfo (tools, prompts, resources, instructions, code) │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Analysis Layer                               │
│  Metadata │ Source │ Capability │ Chains │ Compliance │ Policy │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Output Layer                                 │
│  ScanReport → JSON │ SARIF │ HTML │ Markdown │ CI gate           │
└─────────────────────────────────────────────────────────────────┘
```

### Extended core types

```python
# mcts/mcp/models.py — extend MCPServerInfo
class MCPTool(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    source_file: str | None = None
    source_line: int | None = None
    handler_snippet: str | None = None
    capability: CapabilityProfile | None = None

class CapabilityProfile(BaseModel):
    reads_untrusted_input: bool = False
    accesses_sensitive_data: bool = False
    mutates_state: bool = False
    egresses_network: bool = False
    executes_commands: bool = False

class Finding(BaseModel):
    # ... existing fields ...
    technique_id: str | None = None      # e.g. "MCTS-T-1001"
    mitigation_ids: list[str] = []
    cwe_id: str | None = None
    confidence: float = 1.0
    location: SourceLocation | None = None
```

Use **`MCTS-T-*`** (MCTS Technique) as the taxonomy namespace — cross-referenced optionally to external frameworks in metadata, not copied dossiers.

---

## Part 4 — Phased Implementation

### Phase 0 — Foundation (2–3 weeks)

Fix structural limits before adding features.

#### 0.1 Multi-file repository scanning

**Why:** Serious scanners analyze repos, not one entrypoint.

**How:**

1. Add `ScanTarget` in `core/target.py` with `kind: file | directory | config | live`
2. Add `src/mcts/discovery/static.py` — walk repo, find `@tool` patterns
3. Discovery rules: files containing `@tool`, `mcp.tool`, `FastMCP`, `Server("mcp")`; skip `tests/`, `venv/`, `.git/`
4. Extend `ScanConfig` with `scope`, `include_globs`, `exclude_globs`, `max_file_bytes`
5. **CLI:** `mcts scan ./my-mcp-server/` (directory)

**Tests:** Fixture repo with tools in `handlers/tools.py` + entrypoint in `server.py`.

#### 0.2 Parse `input_schema` and source context

**How:**

1. AST extract function args + type hints → minimal JSON Schema
2. Store `handler_snippet` (capped 80 lines) for source analyzers
3. New **`SchemaSurfaceAnalyzer`** — suspicious defaults, credential param names, missing `required` on dangerous params → `MCTS-T-1001.002`

#### 0.3 Source-aware analyzers

**How:**

1. Add `SourceContext` to `MCPServerInfo` (`files: dict[str, str]`)
2. Refactor `DataLeakageAnalyzer` to scan all files with line-level `location`
3. Add **`CommandExecutionAnalyzer`** — AST for `subprocess`, `os.system`, `eval`; tie to nearest `@tool`
4. Add **`PathValidationAnalyzer`** — missing path canonicalization in file handlers
5. Static findings: `confidence: 0.7`; live-probed: `1.0`

#### 0.4 Fix placeholder analyzers

**PromptInjectionAnalyzer:** Unicode/hidden chars, instruction-like imperatives, description vs handler mismatch.

**JailbreakAnalyzer:** Weighted manipulation surface (tool count, executes_commands, missing schema, chain edges).

**AttackChainAnalyzer:** Build directed graph from `CapabilityProfile`; BFS for critical paths; store in `ScanReport.attack_graph`.

---

### Phase 1 — Adoption & Live Probing (4–6 weeks)

#### 1.1 Live MCP discovery (`ProbeSession`)

**How:**

1. `src/mcts/probe/session.py` — async stdio connect, `list_tools`, `list_prompts`, `list_resources`, `get_instructions`
2. `LiveDiscovery` same interface as `StaticDiscovery`
3. **CLI:**
   ```bash
   mcts scan ./server.py                    # static (default)
   mcts scan --live --command uv --args run,server.py
   mcts scan --config ~/.cursor/mcp.json --server my-server
   ```
4. Consent gate + CI bypass: `--i-understand-live-risk`
5. Merge static + live in `Scanner`; live enriches schemas

#### 1.2 `mcts inventory`

**How:**

1. `src/mcts/inventory/discoverers/` — Cursor, Claude Desktop, VS Code
2. ```bash
   mcts inventory
   mcts inventory --scan
   mcts inventory --scan --server X
   ```
3. **`CrossServerAnalyzer`** — Levenshtein tool name collisions, cross-server description refs → `MCTS-T-1008`

#### 1.3 Capability profiles

**How:**

1. `src/mcts/capability/inferrer.py` — rule-based `CapabilityProfile` from name, description, schema, handler
2. Extend attack chains: `reads_untrusted_input + egresses_network` → CRITICAL
3. HTML dashboard: Capability Matrix page

#### 1.4 SARIF output

**How:**

1. `src/mcts/reporting/sarif.py` — SARIF 2.1.0 mapping
2. ```bash
   mcts scan ./server.py -o report.sarif --format sarif
   ```

#### 1.5 CI scorecard + gates

**How:**

1. `ScanConfig`: `min_score`, `max_critical`, `fail_on_categories`
2. Expose `CATEGORY_DEFS` scores in CLI
3. Publish GitHub Action (`uses: MCP-Audit/MCTS@v1`), upload SARIF + HTML

#### 1.6 MCTS technique taxonomy (`MCTS-T-*`)

**How:**

1. `src/mcts/taxonomy/techniques.yaml`
2. Analyzers assign `technique_id` on `Finding`
3. HTML: Technique Map section
4. Link to external frameworks in `evidence`, do not vendor third-party technique corpora

#### 1.7 Benchmark corpus

**How:**

1. Expand `examples/bench/` with technique-specific servers
2. `benchmarks/expected/<server>.json` with `required_findings`, `score_range`
3. `tests/test_benchmarks.py` regression suite
4. Document weights in `docs/scoring-spec.md`

---

### Phase 2 — Differentiation (6–10 weeks)

#### 2.1 `mcts fuzz`

- Read-only probes by default; `--fuzz-level safe|standard|aggressive`
- Malformed handshake, traversal tool names, oversized params
- Classify stack traces, path echoes, dangerous successes
- `analyzer: "fuzz"`

#### 2.2 `mcts audit-config`

- Parse `mcpServers` JSON; static checks (secrets in env, broad filesystem paths, `npx -y` risk)
- Optional `--probe` with consent; no LLM agent tool invocation

#### 2.3 Rug-pull baselines

```bash
mcts scan --record-baseline -o .mcts/baseline.json
mcts scan --check-baseline .mcts/baseline.json
```

#### 2.4 `ImplementationDriftAnalyzer`

- Compare description claims vs handler signals (subprocess, open, httpx)
- Optional `--llm-confirm` for mismatches only (opt-in)

#### 2.5 TypeScript / JavaScript static discovery

- `discovery/static_js.py` — `server.tool(`, `setRequestHandler` patterns
- `ScanConfig.languages: ["python", "typescript"]`

#### 2.6 Report history + trend

- Append scans to `.mcts/history/<target-hash>.jsonl`
- Populate HTML trend chart; `mcts trend ./server.py`

---

### Phase 3 — Platform (10+ weeks)

| Feature | Command / module |
|---------|------------------|
| Package supply chain | `mcts vet pypi:…` / `npm:…` |
| Local REST API | `mcts serve` (FastAPI, optional extra) |
| MCP server mode | `mcts-mcp` — `scan_mcp_target`, `explain_finding`, `compare_baselines` |
| Opt-in LLM review | `mcts scan --llm-review` (never required for CI) |
| Security baselines | `mcts scan --profile strict\|balanced\|dev` |
| Certification badges | `mcts badge report.json -o mcts-badge.svg` |

---

## Part 5 — Module Layout (Additive)

```
src/mcts/
├── discovery/
│   ├── static.py
│   ├── static_js.py
│   ├── live.py
│   └── config.py
├── probe/
│   ├── session.py
│   ├── stdio.py
│   └── consent.py
├── inventory/
│   ├── runner.py
│   └── discoverers/
├── capability/
│   └── inferrer.py
├── analyzers/
│   ├── schema_surface.py
│   ├── metadata_integrity.py
│   ├── command_execution.py
│   ├── path_validation.py
│   ├── implementation_drift.py
│   ├── cross_server.py
│   └── dependency_posture.py
├── fuzz/
│   └── runner.py
├── taxonomy/
│   ├── techniques.yaml
│   └── mapper.py
├── policy/
│   └── profiles.yaml
├── reporting/
│   ├── sarif.py
│   └── markdown.py
├── baseline/
│   └── store.py
└── api/                    # optional extra
    └── server.py
```

---

## Part 6 — Documentation to Add/Update

| Doc | Status |
|-----|--------|
| `docs/scoring-spec.md` | Shipped |
| `docs/taxonomy.md` | Shipped |
| `docs/live-scanning.md` | Shipped |
| `docs/inventory.md` | Shipped |
| `docs/ci-integration.md` | Shipped |
| `docs/product-positioning.md` | Shipped |
| `docs/architecture.md` | Updated — discovery, probe, analyzer list |
| `docs/cli.md` | Updated — all commands and flags |
| `docs/roadmap.md` | Aligned with Phases 0–3 |
| `docs/fuzzing.md` | Shipped |
| `docs/typescript-discovery.md` | Shipped |
| `action/README.md` | Shipped |

---

## Part 7 — Dependencies

| Extra | Packages | Used for |
|-------|----------|----------|
| `mcp` (existing) | `mcp>=1.27` | Live probe |
| `sarif` | `jsonschema` | SARIF validation |
| `fuzz` | stdlib + mcp | Protocol fuzz |
| `api` | `fastapi`, `uvicorn` | REST server |
| `js` | `tree-sitter-typescript` (optional) | TS discovery |

Keep **core install lean** — live/fuzz/api behind extras.

---

## Part 8 — What NOT to Build

| Feature | Why skip or defer |
|---------|-------------------|
| Snyk-style cloud analysis API | Violates local-first; privacy |
| Agent Guard runtime hooks | Different product (runtime monitoring) |
| Gamification / closed-core scanner | Distraction from security depth |
| LLM red-team config narratives | Non-deterministic; use `audit-config` instead |
| 1,700-rule general SAST | Stay MCP-boundary focused |
| Content moderation rules | Noise for MCP security |
| Full external technique corpus vendoring | Link + map IDs only |

---

## Part 9 — Build Order

```
Week 1-2:  Phase 0.1–0.4 (repo scan, source analyzers, fix placeholders, attack graph)
Week 3-4:  Phase 1.4–1.5 (SARIF, CI gates, publish Action)
Week 5-6:  Phase 1.1 (live stdio probe)
Week 7-8:  Phase 1.2–1.3 (inventory, capability profiles, cross-server)
Week 9-10: Phase 1.6–1.7 (MCTS-T taxonomy, benchmarks)
Week 11+:  Phase 2 (fuzz, audit-config, baselines, drift, TS discovery)
```

**First PR bundle (highest impact, lowest risk):**

1. Repo-wide static discovery
2. Source-aware `DataLeakageAnalyzer` + `CommandExecutionAnalyzer`
3. SARIF + `--min-score`
4. Attack graph fix in `report/data.py`

---

## Part 10 — Success Criteria

- [ ] CI can gate on score/SARIF without cloud APIs
- [ ] Scan works on a **repo**, not one file
- [ ] Live stdio probe enriches tool schemas (optional, consented)
- [ ] Config inventory detects cross-server shadowing
- [ ] Findings carry `technique_id`, `location`, `confidence`
- [ ] Attack chains use capability graph, not keyword hints
- [ ] HTML dashboard trend + capability matrix from real data
- [ ] Benchmark suite prevents scoring/analyzer regressions
- [ ] `fuzz` and `audit-config` replace stubs with safe, deterministic behavior

---

## How to Contribute

Pick a phase item, read the implementation notes above, and open a [feature request](https://github.com/MCP-Audit/MCTS/issues/new?template=feature_request.yml) or [Discussion](https://github.com/MCP-Audit/MCTS/discussions) to align on design before opening a PR.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup.
