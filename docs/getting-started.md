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

## Next steps

- Save JSON: `mcpaudit scan ./server.py -o report.json`
- Generate HTML: `mcpaudit report report.json`
- Try example servers: `examples/safe-mcp-server/`, `examples/medium-risk-mcp-server/`
- Add to CI: see `action/action.yml`
