# Getting Started

## Install

```bash
pip install mcpaudit
# or with uv
uv tool install mcpaudit
```

## Scan your first server

```bash
mcpaudit scan ./server.py
```

MCPAudit performs static analysis on Python MCP servers, discovering `@tool` decorators and running security analyzers against them.

## Example output

```text
[✓] Discovering tools...
[✓] Mapping permissions...
[✓] Detecting attack chains...
[✓] Generating report...

==================== MCPAudit Security Report ====================
Overall Score:   5/100 (CRITICAL)
Risk Index:      100/100
Scoring basis:   3 Critical, 7 High, 2 Medium, 0 Low (12 scorable findings)

● Critical    4
● High        7
● Medium      2
● Low         0
```

Scores are computed from findings (not hardcoded). See [CLI Reference](cli.md) for `--theme` and `--no-progress`.

## HTML security dashboard

Share results with stakeholders using the interactive HTML report:

```bash
mcpaudit scan examples/vulnerable-mcp-server/server.py -o report.json
mcpaudit report report.json -o security-report.html
```

Open `security-report.html` in Chrome, Firefox, Safari, or Edge. The dashboard includes:

- Executive overview with score gauge, grade, and severity cards
- Security posture summary and prioritized recommendations
- Risk breakdown (category bars + radar chart)
- Searchable findings, OWASP mapping, and attack chain graph

See [HTML Security Dashboard](html-report.md) for layout and export options.

## Next steps

- Save JSON: `mcpaudit scan ./server.py -o report.json`
- Generate HTML: `mcpaudit report report.json -o security-report.html`
- Try example servers: `examples/safe-mcp-server/`, `examples/medium-risk-mcp-server/`
- Add to CI: see `action/action.yml`
