# Architecture

> [Documentation](../index.md) → [Analysis](README.md)

MCTS follows a modular **discover → analyze → score → report** pipeline. The scanner orchestrates static and optional live discovery, runs a registry of security analyzers, applies compliance checks and taxonomy enrichment, and emits JSON/SARIF/terminal/HTML output.

This document describes every major layer, data model, analyzer registry, and extension point. **Planning docs:** [Feature Expansion Plan](../more/feature-expansion-plan.md) · [Roadmap](../more/roadmap.md)

---

## End-to-end pipeline

```
ScanConfig (CLI → core/config.py)
        │
        ▼
┌─────────────────── Discovery ───────────────────┐
│  StaticDiscovery (Python)  ─┐                   │
│  JsStaticDiscovery (TS/JS) ─┼─ merge (repo)     │
│  LiveDiscovery (stdio / HTTP/SSE) ─┘  --live / --url │
│  StaticJsonLoader ────────────────────  --snapshot    │
└───────────────────────┬─────────────────────────┘
                        ▼
              MCPServerInfo
         (tools, prompts, resources, instructions,
          schemas, source snippets, runtime_events)
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   25+ analyzers  ComplianceChecker   enrich_findings
   (20 default)
   (see table)     (OWASP meta)        (MCTS-T / MCTS-M)
        │               │               │
        └───────────────┴───────────────┘
                        ▼
         dedupe_sigma_findings → RiskScoringEngine
                        ▼
                  ScanReport
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
  Terminal UI      JSON / SARIF    mcts report → HTML
  (Rich dashboard)
```

Entry point: `Scanner.run()` in `core/scanner.py`. CLI command: `mcts scan` in `cli/main.py`.

---

## Target resolution

`core/target.py` classifies scan targets:

| Kind | Example | Discovery behavior |
|------|---------|-------------------|
| **File** | `./server.py`, `./src/index.ts` | Single-language static on file + neighbors |
| **Directory** | `./my-mcp-repo/` | Walk tree; Python + TS merge |
| **Config** | `.` + `--config` + `--server` | Launch from client MCP JSON; static empty if no source |

`MCPClient.discover()` in `mcp/client.py` chooses static-only, live-only, or merged paths based on `ScanConfig.live` and `merge_static_live`.

---

## Core data models

### MCPServerInfo (`mcp/models.py`)

| Field | Type | Purpose |
|-------|------|---------|
| `name` | string | Server identifier |
| `version` | string | Declared version when known |
| `tools` | `MCPTool[]` | Discovered tools with schemas and source |
| `prompts` | `MCPPrompt[]` | From live probe |
| `resources` | `MCPResource[]` | From live probe |
| `instructions` | string? | Server system instructions when exposed |
| `transport` | string | Default `stdio` |
| `discovery_mode` | string | `static`, `live`, `merged`, `empty` |
| `source_files` | dict | Path → content cache for SAST |
| `runtime_events` | dict[] | Telemetry for runtime analyzers |

### MCPTool

| Field | Purpose |
|-------|---------|
| `name`, `description` | Tool metadata |
| `input_schema` | Parsed JSON Schema object |
| `source_file`, `source_line` | Static discovery location |
| `handler_snippet` | Source excerpt for SAST analyzers |
| `capability` | `CapabilityProfile` for attack chains |
| `discovered_via` | `static`, `live`, etc. |

### Finding (`reporting/models.py`)

| Field | Purpose |
|-------|---------|
| `id` | Stable finding identifier |
| `analyzer` | Source analyzer key (e.g. `permission_analyzer`) |
| `title`, `description`, `recommendation` | Human-readable content |
| `severity` | `critical`, `high`, `medium`, `low` |
| `tool` | Related tool name when applicable |
| `evidence` | Structured proof (snippets, matched patterns) |
| `technique_id` | MCTS-T-* after enrichment |
| `mitigation_ids` | MCTS-M-* list |
| `cwe_id`, `confidence` | Optional classification |
| `location` | `SourceLocation` file + line |

### ScanReport

| Field | Purpose |
|-------|---------|
| `version` | MCTS release version |
| `target`, `scanned_at` | Scan metadata |
| `server` | Full `MCPServerInfo` snapshot |
| `findings` | All analyzer + compliance findings |
| `summary` | Severity counts |
| `score` | `RiskScore` with auditable `basis` |
| `attack_graph` | Capability-graph structure for HTML/CLI |

---

## ScanConfig highlights (`core/config.py`)

| Field | Default | Role |
|-------|---------|------|
| `languages` | `python`, `typescript` | Static discovery backends |
| `exclude_dirs` | `.git`, `node_modules`, venv, caches | Walk pruning |
| `max_file_bytes` | 500_000 | Per-file read cap |
| `live`, `live_command`, `live_args` | false | Live probe |
| `config_path`, `config_server` | — | Client config launch |
| `runtime_events` | [] | Injected telemetry |
| `behavioral_probe` | false (true with `--live`) | MCTS-T-1026 events |
| `baseline_path`, `save_baseline_path` | — | Rug-pull detection |
| `sigma_rules_path` | — | Extra Sigma YAML dirs |
| `semantic_secrets` | false | Embedding-based secrets |
| `fail_on_category` | {} | CI category gates |
| `enable_jailbreak`, `enable_attack_chains` | true | Analyzer toggles |
| `surfaces` | all four | MCP artifact types to scan |
| `remote_url`, `remote_transport` | — | HTTP/SSE live probe |
| `snapshot_path` | — | Static JSON metadata input |
| `pip_audit`, `npm_audit` | false | Dependency CVE scanning |
| `enable_yara`, `enable_llm_judge`, `enable_cloud_inspect` | false | Optional analyzers |
| `protocol_probe` | false | Active MCPS HTTP checks |
| `expand_vars` | `auto` | Config env var expansion |

---

## Discovery layer (`discovery/`)

| Module | Role |
|--------|------|
| `static.py` | Python AST: `@tool`, schemas, handler snippets |
| `static_js.py` | TS/JS pattern match — see [typescript-discovery](../scanning/typescript-discovery.md) |
| `static_runner.py` | Orchestrates `languages` list |
| `static_merge.py` | Merges multi-language tool lists |
| `live.py` | Stdio or remote MCP `list_*` probe |
| `live_config.py` | Resolves launch from client JSON |
| `static_json.py` | Load pre-exported tools/prompts/resources JSON |
| `env_expand.py` | `$VAR` / `%VAR%` expansion in configs |
| `json5_util.py` | Commented JSON / JSON5 config parsing |
| `merge.py` | Static + live `MCPServerInfo` merge |
| `config.py` | MCP client config parsing helpers |

**Runtime telemetry:** `--runtime-events` JSON, `--live`, `--url`, `--behavioral-probe`, and `mcts fuzz` output attach rows to `runtime_events` before analyzers run.

Deep dives: [Live Scanning](../scanning/live-scanning.md) · [Remote Scanning](../scanning/remote-scanning.md) · [Static Snapshot](../scanning/static-snapshot.md) · [Fuzzing](../scanning/fuzzing.md)

---

## Probe layer (`probe/`)

| Module | Role |
|--------|------|
| `session.py` | Async stdio probe (MCP SDK) |
| `http_session.py` | Remote SSE / streamable HTTP probe |
| `auth.py` | Bearer, headers, OAuth client credentials |
| `protocol_checks.py` | Active MCPS HTTP security probes |
| `consent.py` | `--i-understand-live-risk` / `MCTS_LIVE_OK=1` |
| `events.py` | Live listings → runtime event rows |
| `behavioral.py` | Multi-turn probe patterns |

---

## Scanner orchestration (`core/scanner.py`)

`Scanner.run()` steps:

1. **`MCPClient.discover()`** → `MCPServerInfo`
2. **Merge runtime events** from config file, live probe, behavioral probe
3. **Run analyzers** — each returns `list[Finding]`
4. **`dedupe_sigma_findings()`** — collapse duplicate Sigma matches
5. **`enrich_findings()`** — attach `technique_id`, `mitigation_ids`, URLs
6. **`ComplianceChecker.check()`** — OWASP LLM meta-findings (non-scoring)
7. **`RiskScoringEngine.score()`** — with `verify()` integrity check
8. **Optional `save_baseline()`** when `--save-baseline` set
9. **Build `ScanReport`** with attack graph from `AttackChainAnalyzer`

### Conditional analyzers

| Analyzer | Enabled when |
|----------|--------------|
| `JailbreakAnalyzer` | `enable_jailbreak` (default on) |
| `AttackChainAnalyzer` | `enable_attack_chains` (default on) |
| `MetadataDiffAnalyzer` | `--baseline` provided |
| `EmbeddingSecretsAnalyzer` | `--semantic-secrets` |
| `VulnerablePackageAnalyzer` | `--pip-audit` |
| `NpmAuditAnalyzer` | `--npm-audit` |
| `YaraMetadataAnalyzer` | `--yara` |
| `LlmJudgeAnalyzer` | `--llm-judge` + API key |
| `CloudInspectAnalyzer` | `--cloud-inspect` + API key |
| `VirusTotalAnalyzer` | `--virustotal` + API key |

`SurfaceMetadataAnalyzer`, `PromptDefenseAnalyzer`, and `BehavioralStaticAnalyzer` are on by default.

---

## Analyzer registry

Each analyzer implements `BaseAnalyzer.analyze(server: MCPServerInfo) -> list[Finding]`.

| Analyzer | Key | Focus | Example techniques |
|----------|-----|-------|-------------------|
| `PermissionAnalyzer` | `permission_analyzer` | Destructive / over-privileged tools | MCTS-T-1006 |
| `MetadataIntegrityAnalyzer` | `metadata_integrity` | Description poisoning | MCTS-T-1001 |
| `PromptInjectionAnalyzer` | `prompt_injection` | Injection in metadata | MCTS-T-1001 |
| `ToolShadowingAnalyzer` | `tool_shadowing` | Duplicate/shadow tool names | MCTS-T-1020 |
| `LineJumpingAnalyzer` | `line_jumping` | Context precedence attacks | MCTS-T-1021 |
| `ToolAbuseAnalyzer` | `tool_abuse` | Path traversal in metadata | MCTS-T-1002 |
| `SchemaSurfaceAnalyzer` | `schema_surface` | Full Schema Poisoning (FSP) | MCTS-T-1001.002 |
| `DataLeakageAnalyzer` | `data_leakage` | Secrets in source + metadata | MCTS-T-1004 |
| `CommandExecutionAnalyzer` | `command_execution` | Shell/exec in handlers | MCTS-T-1003 |
| `PathValidationAnalyzer` | `path_validation` | Missing path checks | MCTS-T-1002 |
| `RuntimeEventsAnalyzer` | `runtime_events` | Telemetry cluster | MCTS-T-1023+ |
| `SigmaMetadataAnalyzer` | `sigma_metadata` | Bundled + custom Sigma YAML | MCTS-T-1010 |
| `OAuthConfigAnalyzer` | `oauth_config` | OAuth misconfiguration | MCTS-T-1011–1019 |
| `SupplyChainAnalyzer` | `supply_chain` | Dependency posture | — |
| `EmbeddingSecretsAnalyzer` | `embedding_secrets` | Semantic credentials (opt-in) | MCTS-T-1022 |
| `MetadataDiffAnalyzer` | `metadata_diff` | Baseline diff / rug-pull | MCTS-T-1013, MCTS-T-1040 |
| `JailbreakAnalyzer` | `jailbreak` | Output manipulation resistance | MCTS-T-1007 |
| `CrossServerAnalyzer` | `cross_server` | Cross-server name collisions | MCTS-T-1008 |
| `AttackChainAnalyzer` | `attack_chains` | Multi-step capability graphs | MCTS-T-1005 |
| `SurfaceMetadataAnalyzer` | `surface_metadata` | Poisoning on all MCP surfaces | MCTS-T-1001 |
| `PromptDefenseAnalyzer` | `prompt_defense` | Missing defensive prompt language | MCTS-T-1001 |
| `BehavioralStaticAnalyzer` | `behavioral_static` | Description vs handler mismatch + taint flow | MCTS-T-1001 |
| `VulnerablePackageAnalyzer` | `vulnerable_package` | pip-audit CVEs | MCTS-T-1014 |
| `NpmAuditAnalyzer` | `npm_audit` | npm audit CVEs | MCTS-T-1014 |
| `YaraMetadataAnalyzer` | `yara_metadata` | YARA pattern matches | MCTS-T-1010 |
| `LlmJudgeAnalyzer` | `llm_judge` | Opt-in LLM semantic review | MCTS-T-1001 |
| `CloudInspectAnalyzer` | `cloud_inspect` | Opt-in cloud ML API | MCTS-T-1001 |
| `VirusTotalAnalyzer` | `virustotal` | Binary hash malware lookup | MCTS-T-1038 |

Multi-surface iteration: `analyzers/surfaces.py` — `ScanSurface` abstraction for tools, prompts, resources, instructions.

### Behavioral SAST (`sast/`)

`BehavioralStaticAnalyzer` compares tool descriptions against handler implementations and traces untrusted parameters to security sinks.

| Module | Languages | Role |
|--------|-----------|------|
| `sast/python/taint.py` | Python | AST parameter-to-sink flow |
| `sast/python/crossfile.py` | Python | Expand handlers across `source_files` |
| `sast/typescript/sinks.py`, `taint.py` | TS/JS | Regex + optional tree-sitter-typescript |
| `sast/go/sinks.py`, `taint.py` | Go | `exec.Command`, `os.Remove`, HTTP sinks |
| `sast/rust/sinks.py`, `taint.py` | Rust | `Command::new`, `fs::write`, `reqwest` |
| `sast/eval.py` | — | Corpus runner for regression metrics |

Eval corpus: `eval/behavioral/cases.json` (22 cases across Python, TypeScript, Go, Rust). Run via `scripts/run_behavioral_eval.py` or `tests/test_behavioral_eval.py`. Install optional tree-sitter parsers with `uv sync --extra sast`.

Taxonomy crosswalk: `taxonomy/crosswalk.json` adds `aitech`, `aisubtech`, `saf_mcp` to finding evidence via `enrich_findings()`.

### RuntimeEventsAnalyzer sub-detectors

`RuntimeEventsAnalyzer` delegates telemetry rows to focused detector modules under `analyzers/`:

| Module | Technique examples |
|--------|-------------------|
| `autonomous_loop.py` | MCTS-T-1035 |
| `command_injection.py` | MCTS-T-1023 |
| `oauth_mixup.py` | MCTS-T-1012 |
| `rug_pull.py` | MCTS-T-1013 |
| `behavioral_extraction.py` | MCTS-T-1026 |
| `credential_access.py` | MCTS-T-1024 |
| `tool_redefinition.py` | MCTS-T-1040 |
| `over_privileged.py` | MCTS-T-1006 |
| `exposed_endpoint.py` | MCTS-T-1027 |
| `dns_poisoning.py` | MCTS-T-1028 |
| `tool_output_injection.py` | MCTS-T-1007 |
| `cross_server_registry.py` | MCTS-T-1029 |
| `privilege_tool_abuse.py` | MCTS-T-1030 |
| `suspicious_registration.py` | MCTS-T-1031 |
| `fake_tool_invocation.py` | MCTS-T-1032 |
| `sandbox_escape.py` | MCTS-T-1033 |
| `oauth_escalation_runtime.py` | MCTS-T-1017–1019 |
| `instruction_steganography.py` | MCTS-T-1041 |
| `vector_poisoning.py` | MCTS-T-1034 |
| `inspector_rce.py` | MCTS-T-1036 |
| `oauth_token_persistence.py` | MCTS-T-1037 |
| `backdoored_install.py` | MCTS-T-1038 |
| `context_memory_implant.py` | MCTS-T-1039 |
| `sampling_abuse.py` | MCTS-T-1016 |

See [Threat Taxonomy](../reporting/taxonomy.md) for the full catalog.

---

## Capability graph and attack chains

`capability/inferrer.py` assigns each tool a `CapabilityProfile`:

| Flag | Meaning |
|------|---------|
| `reads_untrusted_input` | Accepts user/agent-controlled input |
| `accesses_sensitive_data` | Files, secrets, PII patterns |
| `mutates_state` | Writes/deletes data |
| `egresses_network` | HTTP, API calls |
| `executes_commands` | subprocess, shell |

`AttackChainAnalyzer` performs BFS on the capability graph to find paths like **read → exfiltrate** or **read → execute**. Results populate `ScanReport.attack_graph` for terminal and HTML visualization.

---

## Fuzzing (`fuzz/`)

Separate command path: `FuzzRunner` → protocol probes → findings + `runtime_events` JSON.

```bash
mcts fuzz ./server.py --i-understand-live-risk -o fuzz.json
mcts scan ./server.py --runtime-events fuzz.json
```

See [Protocol Fuzzing](../scanning/fuzzing.md).

---

## Inventory (`inventory/`)

`mcts inventory` discovers client configs; `CrossServerAnalyzer.analyze_inventory()` flags tool shadowing.

See [Config Inventory](../scanning/inventory.md).

---

## Scoring (`scoring/engine.py`)

| Metric | Formula | Interpretation |
|--------|---------|----------------|
| Raw risk | C×25 + H×10 + M×3 + L×1 | Linear weighted sum |
| Overall score | `round(100 × e^(-raw/50))` | Higher is better |
| Risk index | `min(100, raw_risk)` | Higher is worse |

Compliance findings (`analyzer: compliance`) excluded via `NON_SCORING_ANALYZERS`.

Full spec: [Scoring Specification](../reporting/scoring-spec.md).

---

## Reporting

### JSON / SARIF (`reporting/`)

- `models.py` — Pydantic schemas
- `sarif.py` — SARIF 2.1.0 emission for Code Scanning

### Terminal UI (`ui/`)

| Module | Role |
|--------|------|
| `theme.py` | `cyber`, `minimal`, `github` |
| `progress.py` | Pre-scan animation |
| `dashboard.py` | Metrics grid, category bars |
| `report_renderer.py` | Full terminal report |

### HTML dashboard (`report/`)

`mcts report` → `report/data.py` (payload) → `generators/html_report.py` (Jinja2 + inline assets).

See [HTML Security Dashboard](../reporting/html-report.md).

---

## Taxonomy (`taxonomy/`)

| Asset | Role |
|-------|------|
| `techniques.json` | MCTS-T catalog with CWE/OWASP |
| `mapper.py` | Post-analyzer enrichment |
| `sigma/metadata_rules.json` | Bundled metadata Sigma rules |
| `mitigation_urls.py` | GitHub doc links for HTML/SARIF |

Custom rules: `--sigma-rules-path` pointing at `MCTS-T-*/detection-rule.yml` directories.

---

## Compliance (`compliance/checks.py`)

`ComplianceChecker` maps existing findings to **OWASP LLM Top 10** meta-findings. These appear in reports and HTML OWASP section but **do not affect** the security score.

---

## Regression testing (`testing/`)

| Asset | Role |
|-------|------|
| `tests/fixtures/regression/MCTS-T-*/` | 34+ technique fixtures |
| `testing/regression_harness.py` | CI accuracy gate (≥80%) |
| `tests/fixtures/sigma_fixtures/` | Sigma rule validation |
| `eval/behavioral/cases.json` | Behavioral SAST corpus (multi-language) |
| `scripts/run_behavioral_eval.py` | Malicious-case recall metrics for behavioral SAST |

---

## Package layout

```
src/mcts/
├── cli/           # Typer: scan, report, inventory, fuzz, pentest (stub)
├── core/          # Scanner, ScanConfig, ScanTarget
├── discovery/     # Static (Py/TS), live, merge
├── probe/         # Live stdio session, consent, behavioral events
├── analyzers/     # Security analyzers + runtime detectors
├── sast/          # Behavioral static analysis (Python/TS/Go/Rust)
├── readiness/     # HEUR rules + OPA policies + optional LLM judge
├── api/           # FastAPI REST surface (`mcts serve`)
├── capability/    # Per-tool capability inference (attack chains)
├── inventory/     # Client config discovery
├── fuzz/          # Protocol fuzz runner
├── scoring/       # RiskScoringEngine
├── compliance/    # OWASP LLM checks
├── reporting/     # Models, SARIF, HTML entry
├── report/        # HTML dashboard templates/assets
├── taxonomy/      # MCTS-T/M, Sigma rules
├── testing/       # Regression harness
└── ui/            # Rich terminal dashboard
```

---

## Adding an analyzer

1. Subclass `BaseAnalyzer` in `analyzers/`.
2. Set `name` class attribute and implement `analyze()`.
3. Register in `Scanner.__init__` analyzer list (`core/scanner.py`).
4. Add `technique_id` on findings (or rely on mapper catalog lookup).
5. Add regression fixture under `tests/fixtures/regression/MCTS-T-*/` when applicable.
6. Update [Threat Taxonomy](../reporting/taxonomy.md) if adding new technique IDs.

---

## Planned evolution

| Feature | Status |
|---------|--------|
| Remote protocol fuzz (`mcts fuzz --url`) | Planned |
| `mcts audit-config`, `mcts simulate`, `mcts pentest`, `mcts vet` | Planned / stub |
| Scan history / trends (`.mcts/history/`) | Planned |
| HTML Capability Matrix + Technique Map | Planned |
| Tree-sitter depth for TypeScript handlers | Partial (`--extra sast`) |
| Go/Rust behavioral SAST | Shipped (regex; tree-sitter optional) |
| SSE/HTTP live transports | Shipped (`--url`, `--transport`) |
| REST API (`mcts serve`) | Shipped (10 endpoints) |
| Expanded behavioral eval corpus | Partial (22 cases in `eval/behavioral/`) |

See [Roadmap](../more/roadmap.md) and [Feature Expansion Plan](../more/feature-expansion-plan.md).

---

## Related

- [CLI Reference](../platform/cli.md)
- [Live Scanning](../scanning/live-scanning.md)
- [Scoring Spec](../reporting/scoring-spec.md)
- [CI Integration](../platform/ci-integration.md)
