# MCTS Documentation

**MCTS** (Model Context Threat Scanner) analyzes MCP servers — static and live discovery, 19+ security analyzers, risk scoring, terminal dashboard, SARIF/JSON, and shareable HTML reports.

## Guides

- [Getting Started](getting-started.md) — Install, first scan, HTML dashboard
- [CLI Reference](cli.md) — `scan`, `report`, `inventory`, `fuzz`, flags, exit codes
- [Architecture](architecture.md) — Discovery → analyzers → scoring → reporting pipeline
- [HTML Security Dashboard](html-report.md) — Layout, export, and design system

## Scan modes

- [Live Scanning](live-scanning.md) — Stdio MCP probing, consent, config-based launch
- [Protocol Fuzzing](fuzzing.md) — Safe read-only fuzz levels; pipe into `--runtime-events`
- [TypeScript Discovery](typescript-discovery.md) — Node MCP servers without npm install
- [Config Inventory](inventory.md) — Cursor, Claude, VS Code, Windsurf discovery

## Scoring & CI

- [Scoring Specification](scoring-spec.md) — Formula, category breakdown, gate semantics
- [CI Integration](ci-integration.md) — GitHub Action, SARIF upload, thresholds
- [Threat Taxonomy](taxonomy.md) — MCTS-T techniques and MCTS-M mitigations

## Planning

- [Feature Expansion Plan](feature-expansion-plan.md) — Gap analysis, phased implementation, module layout
- [Product Roadmap](roadmap.md) — Phases from foundation → platform
- [Product Positioning](product-positioning.md) — Strengths, use cases, design principles
- [External Frameworks](external-frameworks.md) — How industry taxonomies relate to MCTS-T
- [Feature matrix (README)](../README.md#features) — Current module status

## Blog & community

- [Building MCP Security in Public](blog-building-mcp-security-in-public.md) — Alpha status, known gaps, discussion prompts
- [Product overview (promotional)](promotional-article.md) — Shorter introduction for sharing

## Changelog

- [Changelog](../CHANGELOG.md) — User-facing release notes
