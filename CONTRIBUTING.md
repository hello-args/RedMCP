# Contributing to RedMCP

Thank you for helping make MCP security testing accessible to everyone.

## Getting Started

1. Fork and clone the repository
2. Install [uv](https://docs.astral.sh/uv/getting-started/installation/)
3. Run `uv sync --all-extras`
4. Install pre-commit hooks: `pre-commit install`

## Development Workflow

```bash
# Run tests
uv run pytest

# Lint & format
uv run ruff check .
uv run ruff format src tests

# Try the CLI locally
uv run redmcp scan examples/vulnerable-mcp-server/server.py
```

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Add tests for new behavior
- Update `CHANGELOG.md` under `[Unreleased]` for user-facing changes
- Follow existing code style (ruff enforces this in CI)

## Branch Protection

Pull requests to `main` require the **test** CI check to pass.

### Enable on GitHub (one-time, repo admin)

**Option A — Script**

```bash
./scripts/enable-branch-protection.sh hello-args/RedMCP
```

**Option B — GitHub UI**

1. Go to **Settings → Rules → Rulesets → New branch ruleset**
2. Target: default branch (`main`)
3. Add rule: **Require status checks to pass**
4. Required check: `test`
5. Save and enable enforcement

The ruleset definition lives in `.github/rulesets/main.json`.

## Adding a New Analyzer

1. Create a module under `src/redmcp/analyzers/`
2. Subclass `BaseAnalyzer` and implement `analyze()`
3. Register it in `src/redmcp/core/scanner.py`
4. Add tests under `tests/`

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Questions?

Open a [GitHub Discussion](https://github.com/redmcp/redmcp/discussions) or issue.
