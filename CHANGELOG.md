# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Repository scanning** — `mcts scan ./repo/` walks Python files, discovers `@tool` handlers across the project (skips `tests/`, venv, `.git`)
- **Static discovery layer** — `discovery/static.py` parses `input_schema`, handler snippets, source locations, and capability profiles
- **Source-aware analyzers** — `CommandExecutionAnalyzer`, `PathValidationAnalyzer`, `SchemaSurfaceAnalyzer`; `DataLeakageAnalyzer` scans source files with line-level locations
- **Capability-graph attack chains** — attack chain detection uses per-tool capability profiles instead of keyword hints; real graph stored on `ScanReport.attack_graph`
- **SARIF output** — `mcts scan -o report.sarif --format sarif` for CI and GitHub Advanced Security integration
- **CI score gates** — `--min-score`, `--max-critical` exit codes for pipeline enforcement
- **Finding metadata** — `technique_id`, `location`, `confidence` on findings; `MCTS-T-*` technique IDs on new analyzers
- Benchmark fixture: `examples/bench/multi-file-server/` for multi-file discovery tests
- **`mcts inventory`** — discover MCP servers in Cursor, Claude, VS Code, Windsurf configs
- **Cross-server shadowing** — `CrossServerAnalyzer` detects tool name collisions (`MCTS-T-1008`)
- **Metadata integrity analyzer** — description poisoning and line-jumping patterns
- **MCTS-T taxonomy** — `techniques.json` with CWE/OWASP mapping; auto-enriched on findings
- **GitHub Action** — JSON + SARIF + HTML artifacts, `--min-score` input, Code Scanning upload
- Docs: [Product Positioning](docs/product-positioning.md)
- **Live stdio probing** — `mcts scan --live --i-understand-live-risk` connects via MCP protocol; merges live schemas with static analysis
- **Config-based live scan** — `mcts scan --config ~/.cursor/mcp.json --server NAME --live --i-understand-live-risk`
- Example: `examples/live-mcp-server/server.py` for probe integration tests
- **`mcts fuzz`** — safe read-only protocol fuzzing (`--fuzz-level safe|standard|aggressive`); aggressive requires `--i-understand-fuzz-risk`
- **TypeScript/JavaScript static discovery** — `discovery/static_js.py` finds `registerTool`, `server.tool`, and `setRequestHandler` patterns; `ScanConfig.languages` defaults to `python` + `typescript`
- Benchmark fixture: `examples/bench/multi-file-ts-server/` for TS discovery tests
- **HTML security dashboard** — `mcts report` renders a self-contained, dark-themed executive dashboard (score gauge, letter grade, severity cards, posture summary, category breakdown + radar chart, findings table, attack chain graph, OWASP mapping, in-browser JSON/HTML/PDF export)
- **Terminal UI** — Rich-based CLI with themes (`cyber`, `minimal`, `github`), scan progress animation, aligned metrics panels, and brand PNG logo on supported terminals (ASCII fallback elsewhere)
- **Exponential risk scoring** — Security score `round(100 × e^(-raw_risk/50))`, risk index, and auditable `ScoreBasis` on every report (compliance meta-findings excluded)
- Example servers: `examples/safe-mcp-server/`, `examples/medium-risk-mcp-server/` for scoring regression bands
- Brand assets in `src/mcts/brand/` (canonical logo + HTML-optimized embed)
- Docs: [HTML Security Dashboard](docs/html-report.md), updated CLI, getting started, architecture, and README

### Changed

- `MCPTool.input_schema` is now a parsed JSON Schema object (was a string)
- `PromptInjectionAnalyzer` and `JailbreakAnalyzer` use heuristics beyond keyword/tool-count placeholders
- HTML attack graph no longer synthesizes fake "related" edges when no chains exist
- Renamed project and repository to **MCTS** (Model Context Threat Scanner): `mcts` package and CLI, GitHub repo `MCP-Audit/MCTS` (formerly MCPAudit / `mcpaudit` / `MCP-Audit/MCPAudit`)
- `mcts report` now delegates to the premium dashboard generator (replaces minimal inline HTML template)

## [0.1.0] - 2026-06-03

### Added

- Initial project scaffold with `uv`, `src/` layout, and `pyproject.toml`
- CLI: `mcts scan`, `mcts report`, `mcts fuzz`, `mcts pentest` (stubs)
- Analyzers: permissions, prompt injection, tool abuse, data leakage, jailbreak, attack chains
- Risk scoring engine and basic HTML report generation
- Example vulnerable MCP server and pytest suite
- GitHub Actions CI, pre-commit, and OSS community files
- Alpha release: static analysis scanner for Python MCP servers
