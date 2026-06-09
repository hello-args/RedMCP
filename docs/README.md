# MCTS Docs

Welcome to the MCTS documentation. This folder contains guides for installing, using, and contributing to the Model Context Threat Scanner.

> **Start here:** [Documentation index](index.md)

---

## New to MCTS?

1. Read the [Glossary](glossary.md) if terms like MCP, SARIF, or attack chain are unfamiliar
2. Follow [Install and first scan](get-started/getting-started.md) (~15 minutes)
3. Pick your next guide from the [index](index.md#choose-your-path) based on your role

---

## Sections at a glance

| Section | Who it's for | Start here |
|---------|--------------|------------|
| [Get Started](get-started/README.md) | Everyone — first-time setup | [getting-started.md](get-started/getting-started.md) |
| [Scanning](scanning/README.md) | Developers choosing a scan mode | [Which scan mode?](scanning/README.md#which-scan-mode-should-i-use) |
| [Analysis](analysis/README.md) | Security engineers understanding findings | [Security Checks](analysis/security-checks.md) |
| [Reporting](reporting/README.md) | Anyone interpreting scores and exports | [Scoring Spec](reporting/scoring-spec.md) |
| [Platform](platform/README.md) | DevOps and CI engineers | [CLI Reference](platform/cli.md) |
| [Contributing](contributing/README.md) | Issue authors and triagers | [Issue labeling guide](contributing/issue-labeling.md) |
| [More](more/README.md) | Contributors and product stakeholders | [Product Positioning](more/product-positioning.md) |

---

## Quick commands

```bash
uv sync --all-extras
uv run mcts scan examples/vulnerable-mcp-server/server.py
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcts report report.json -o security-report.html
```

---

## Other resources

- [Issue labeling guide](contributing/issue-labeling.md) — how to open and label GitHub issues
- [Glossary](glossary.md) — term definitions
- [Changelog](../CHANGELOG.md) — release notes
- [Main README](../README.md) — project overview
