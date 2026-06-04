# CLI Reference

## `mcpaudit scan`

Run a full security scan.

```bash
mcpaudit scan <target> [--output report.json] [--fail-on-critical] [--theme cyber]
```

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Write JSON report to file |
| `--fail-on-critical` | Exit code 1 if critical findings exist |
| `--theme` | Terminal theme: `cyber` (default), `minimal`, `github` |
| `--no-progress` | Skip pre-report progress animation |

### Scoring output

Each scan prints:

- **Overall Score** — security score (higher is better), from exponential decay on weighted findings
- **Risk Index** — raw risk capped at 100 (higher is worse)
- **Scoring basis** — severity counts used (compliance meta-findings are excluded from the formula)

JSON reports include `score.overall`, `score.risk_index`, `score.raw_risk`, and `score.basis`.

## `mcpaudit report`

Generate HTML from a JSON scan report.

```bash
mcpaudit report report.json [--output security-report.html] [--theme cyber]
```

| Flag | Description |
|------|-------------|
| `--output`, `-o` | HTML report path |
| `--theme` | Terminal theme for status messages |

## `mcpaudit fuzz` (roadmap)

Fuzz an MCP server with generated attack payloads.

## `mcpaudit pentest` (roadmap)

AI-assisted penetration testing agent.

## `mcpaudit --version`

Print the installed version.
