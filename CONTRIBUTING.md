# Contributing to MCTS

Thank you for helping make MCP security testing accessible to everyone.

> **New to the project?** Read [Getting Started](docs/get-started/getting-started.md) and the [Glossary](docs/glossary.md) first.

---

## Getting Started

1. Fork and clone the repository
2. Install [uv](https://docs.astral.sh/uv/getting-started/installation/)
3. Run `uv sync --all-extras`
4. Install pre-commit hooks: `pre-commit install`

See [Getting Started](docs/get-started/getting-started.md) and [CLI Reference](docs/platform/cli.md) for usage beyond local development.

---

## Development Workflow

```bash
# Run tests
uv run pytest

# Lint & format
uv run ruff check .
uv run ruff format src tests

# Try the CLI locally
uv run mcts scan examples/vulnerable-mcp-server/server.py

# Generate the HTML security dashboard
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcts report report.json -o security-report.html
```

---

## Filing Issues

Before opening a GitHub issue:

1. Search [existing issues](https://github.com/MCP-Audit/MCTS/issues) for duplicates
2. Reproduce on the latest `main` branch
3. Apply the label taxonomy: one `type:*`, one `priority:P*`, and at least one `component:*`

Full guide: **[Issue Labeling & Creation](docs/contributing/issue-labeling.md)** — types, priorities, components, finding labels, status workflow, body template, and examples.

Use the repo templates when possible: [bug report](https://github.com/MCP-Audit/MCTS/issues/new?template=bug_report.yml) · [feature request](https://github.com/MCP-Audit/MCTS/issues/new?template=feature_request.yml)

---

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Add tests for new behavior
- Update `CHANGELOG.md` under `[Unreleased]` for user-facing changes
- Follow existing code style (ruff enforces this in CI)
- Update documentation when adding user-facing features

---

## Branch Protection

Pull requests to `main` require the **test** CI check to pass.

### Enable on GitHub (one-time, repo admin)

**Option A — Script**

```bash
./scripts/enable-branch-protection.sh MCP-Audit/MCTS
```

**Option B — GitHub UI**

1. Go to **Settings → Rules → Rulesets → New branch ruleset**
2. Target: default branch (`main`)
3. Add rule: **Require status checks to pass**
4. Required check: `test`
5. Save and enable enforcement

The ruleset definition lives in `.github/rulesets/main.json`.

---

## Planning & Roadmap

Before large features, read:

| Document | What it covers |
|----------|---------------|
| [Documentation index](docs/index.md) | All user and contributor docs |
| [Glossary](docs/glossary.md) | Term definitions |
| [Feature Expansion Plan](docs/more/feature-expansion-plan.md) | Gap analysis, implementation how-to, prioritized backlog |
| [Product Roadmap](docs/more/roadmap.md) | Phased deliverables and success criteria |
| [Product Positioning](docs/more/product-positioning.md) | Positioning, differentiation, and roadmap gaps |

When proposing parity with another MCP security tool, cite the capability layer (static scan, supply chain, runtime, governance, graph) and confirm it fits MCTS's local-first MCP-boundary scope — see [Feature Expansion Plan Part 8](docs/more/feature-expansion-plan.md#part-8--what-not-to-build).

Pick a phase item from [Part 11](docs/more/feature-expansion-plan.md#part-11--prioritized-backlog) or the [full GAP appendix](docs/more/feature-expansion-plan.md#part-11-appendix--full-gap-backlog-gap-001240) and open a [feature request](https://github.com/MCP-Audit/MCTS/issues/new?template=feature_request.yml) or Discussion to align on design.

---

## Adding a New Analyzer

1. Create a module under `src/mcts/analyzers/`
2. Subclass `BaseAnalyzer` and implement `analyze()`
3. Register it in `src/mcts/core/scanner.py`
4. Add benchmark fixture in `examples/bench/` when applicable
5. Assign `technique_id` (`MCTS-T-*`) — see [Threat Taxonomy](docs/reporting/taxonomy.md)
6. Add tests under `tests/`
7. Document the check in [Security Checks Reference](docs/analysis/security-checks.md)

Full guide: [Architecture — Adding an analyzer](docs/analysis/architecture.md#adding-an-analyzer)

---

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

---

## Questions?

Open a [GitHub Discussion](https://github.com/MCP-Audit/MCTS/discussions) or an [issue](https://github.com/MCP-Audit/MCTS/issues) using the [labeling guide](docs/contributing/issue-labeling.md).
