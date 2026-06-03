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

```
────────────────────── MCPAudit Security Report ──────────────────────
Target: examples/vulnerable-mcp-server/server.py
Overall Score: 42/100

        Findings by Severity
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ Critical │     3 │
│ High     │     4 │
...
```

## Next steps

- Save JSON: `mcpaudit scan ./server.py -o report.json`
- Generate HTML: `mcpaudit report report.json`
- Add to CI: see `action/action.yml`
