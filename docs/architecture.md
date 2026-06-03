# Architecture

MCPAudit follows a modular pipeline architecture designed for extensibility.

## Components

### Scanner (`core/scanner.py`)

Orchestrates discovery, analyzers, compliance checks, and scoring into a single `ScanReport`.

### MCP Client (`mcp/client.py`)

Currently performs **static analysis** of Python MCP server source files. Future versions will support live MCP transport probing (stdio, SSE, HTTP).

### Analyzers (`analyzers/`)

Each analyzer implements `BaseAnalyzer.analyze(server) -> list[Finding]`:

| Analyzer | Purpose |
|----------|---------|
| `PermissionAnalyzer` | Destructive & privileged tools |
| `PromptInjectionAnalyzer` | Injection attack surfaces |
| `ToolAbuseAnalyzer` | Path traversal & misuse |
| `DataLeakageAnalyzer` | Secrets & sensitive data |
| `JailbreakAnalyzer` | Agent manipulation resistance |
| `AttackChainAnalyzer` | Multi-step attack paths |

### Scoring (`scoring/engine.py`)

Penalty-based score: `100 - sum(severity_weights)`.

### Reporting (`reporting/`)

Pydantic models for structured JSON output and Jinja2 HTML reports.

## Adding live MCP probing

The `MCPClient` interface is the extension point. Implement transport-specific discovery in `mcp/client.py` and wire dynamic analyzers to send real payloads through the MCP protocol.
