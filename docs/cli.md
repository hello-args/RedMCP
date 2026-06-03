# CLI Reference

## `mcpaudit scan`

Run a full security scan.

```bash
mcpaudit scan <target> [--output report.json] [--fail-on-critical]
```

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Write JSON report to file |
| `--fail-on-critical` | Exit code 1 if critical findings exist |

## `mcpaudit report`

Generate HTML from a JSON scan report.

```bash
mcpaudit report report.json [--output security-report.html]
```

## `mcpaudit fuzz` (roadmap)

Fuzz an MCP server with generated attack payloads.

## `mcpaudit pentest` (roadmap)

AI-assisted penetration testing agent.

## `mcpaudit --version`

Print the installed version.
