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

Generate a **premium HTML security dashboard** from a JSON scan report produced by `mcpaudit scan -o`.

```bash
mcpaudit report report.json [--output security-report.html] [--theme cyber]
```

| Flag | Description |
|------|-------------|
| `--output`, `-o` | HTML report path (default: `security-report.html`) |
| `--theme` | Terminal theme for the success message only |

### What you get

A self-contained, dark-themed dashboard suitable for engineering review and executive briefings. See [HTML Security Dashboard](html-report.md) for full detail.

**Overview page**

- Overall risk score — semi-circle gauge, numeric score, letter grade (A–F), posture badge, score methodology tooltip
- Severity cards — Critical / High / Medium / Low / Tools with counts and risk badges
- Security Posture Summary — narrative plus prioritized recommended actions (P1/P2)
- Risk Score Breakdown — per-category progress bars and radar chart
- Risk Score Trend — history chart when multiple scans exist; otherwise a guided empty state
- Risk Level Guide — reference cards for score bands

**Additional pages (sidebar)**

- Findings (search, filter, sort)
- Analyzers
- Attack Chains (SVG graph)
- OWASP LLM Mapping
- Recommendations
- Appendix (raw JSON)

**In-browser export:** JSON download, HTML save, PDF via print.

### Example

```bash
uv run mcpaudit scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcpaudit report report.json -o security-report.html
open security-report.html
```

## `mcpaudit fuzz` (roadmap)

Fuzz an MCP server with generated attack payloads.

## `mcpaudit pentest` (roadmap)

AI-assisted penetration testing agent.

## `mcpaudit --version`

Print the installed version.
