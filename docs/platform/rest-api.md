# REST API

> [Documentation](../index.md) → [Platform](README.md)

MCTS exposes an optional **FastAPI** server for programmatic scans — same `Scanner` class as the CLI.

Implementation: `api/app.py` · CLI: `mcts serve`.

---

## Install

```bash
uv sync --extra api
```

Adds `fastapi` and `uvicorn`.

---

## Start server

```bash
mcts serve --host 127.0.0.1 --port 8080
# OpenAPI docs: http://127.0.0.1:8080/docs
```

When `MCTS_API_KEY` is set in the environment, every endpoint except `/health` requires an `X-API-Key` header matching that value. When unset, the API accepts unauthenticated requests (local development only).

---

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | No | Health check `{ "status": "ok" }` |
| `POST` | `/scan` | Optional | Full security scan |
| `POST` | `/scan-tool` | Optional | Scan a single tool by name |
| `POST` | `/scan-all-tools` | Optional | Scan each tool separately |
| `POST` | `/scan-prompt` | Optional | Scan a single prompt |
| `POST` | `/scan-all-prompts` | Optional | Scan all prompts |
| `POST` | `/scan-resource` | Optional | Scan a single resource URI |
| `POST` | `/scan-all-resources` | Optional | Scan all resources |
| `POST` | `/scan-instructions` | Optional | Scan server instructions |
| `POST` | `/readiness` | Optional | Production readiness (HEUR + optional OPA) |

---

## Authentication

Set `MCTS_API_KEY` before starting the server:

```bash
export MCTS_API_KEY="your-secret-key"
mcts serve
```

Clients must send the header on POST requests:

```bash
curl -s -X POST http://127.0.0.1:8080/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{"target": "examples/vulnerable-mcp-server/server.py"}' | jq .score
```

Implementation: `api/auth.py` (`require_api_key`).

---

## Request bodies

### Shared `ScanRequest` fields

All scan endpoints accept these fields (plus endpoint-specific fields where noted):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | `"."` | Server file or repo path |
| `live` | bool | `false` | Connect to live MCP server |
| `url` | string | — | Remote MCP URL (implies live) |
| `transport` | string | `"streamable-http"` | `streamable-http` or `sse` |
| `bearer_token` | string | — | Bearer token for remote MCP |
| `surfaces` | string[] | all four | `tool`, `prompt`, `resource`, `instruction` |
| `resource_mime_allowlist` | string[] | `[]` | MIME filter for resources |
| `pip_audit` | bool | `false` | Run pip-audit |
| `protocol_probe` | bool | `false` | Active MCPS HTTP checks on `url` |
| `hide_safe` | bool | `false` | Omit low-severity informational findings |
| `tool_filter` | string[] | `[]` | Limit scan to named tools |
| `analyzer_filter` | string[] | `[]` | Limit output to named analyzers |

Endpoint-specific fields:

| Endpoint | Extra fields |
|----------|--------------|
| `/scan-tool` | `tool_name` (required) |
| `/scan-prompt` | `prompt_name` (required) |
| `/scan-resource` | `resource_uri` (required); default MIME allowlist `text/plain`, `text/html` |
| `/readiness` | `enable_opa` (bool, default `false`) — see `ReadinessRequest` |

### `POST /scan` example

```json
{
  "target": ".",
  "live": false,
  "url": "https://mcp.example.com/mcp",
  "transport": "streamable-http",
  "bearer_token": "optional",
  "surfaces": ["tool", "prompt", "resource", "instruction"],
  "resource_mime_allowlist": ["text/plain", "application/json"],
  "pip_audit": false,
  "protocol_probe": false
}
```

Response: full `ScanReport` JSON (`model_dump()`).

### Example

```bash
curl -s -X POST http://127.0.0.1:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "examples/vulnerable-mcp-server/server.py"}' | jq .score

curl -s -X POST http://127.0.0.1:8080/scan-prompt \
  -H "Content-Type: application/json" \
  -d '{"target": ".", "prompt_name": "support_template", "live": true, "url": "..."}'
```

---

## Related

- [CLI Reference](cli.md)
- [Remote Scanning](../scanning/remote-scanning.md)
