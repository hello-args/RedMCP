# REST API

> [Documentation](../index.md) → [Platform](README.md)

MCTS can run as a **REST API server** for programmatic scans — useful when you want other tools or services to trigger scans without using the CLI directly.

> **Most users should use the CLI.** The REST API is for automation and integration scenarios.

---

## In plain English

Instead of running `mcts scan` from the command line, you can start a local HTTP server with `mcts serve` and send scan requests via REST endpoints. The API runs the same scanner as the CLI and returns the same JSON report format.

Use cases:
- Integrate MCTS into an internal security platform
- Trigger scans from a web dashboard or orchestration tool
- Run scans from languages other than Python/shell

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

When `MCTS_API_KEY` is set, every endpoint except `/health` requires an `X-API-Key` header. When unset, loopback binds (`127.0.0.1`) are allowed with a startup warning. Binding to a non-loopback address without a key requires `--allow-unauthenticated`.

---

## Threat model

| Risk | Mitigation |
|------|------------|
| Unauthenticated remote access | Set `MCTS_API_KEY`; do not use `--allow-unauthenticated` in production |
| Live MCP probing via API | Set `understand_live_risk: true`, header `X-MCTS-Live-Consent: 1`, or server env `MCTS_LIVE_OK=1` |
| Resource exhaustion | Rate limits and fan-out caps (`MCTS_API_*` env vars — see [Rate limits](#rate-limits)) |

Only expose the API on trusted networks. `/health` stays public for load balancers.

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

### Live scan consent

Live or remote scans (`live: true` or `url`) require the same consent as the CLI:

- Request body: `"understand_live_risk": true`
- Header: `X-MCTS-Live-Consent: 1`
- Server environment: `MCTS_LIVE_OK=1`

Without consent the API returns HTTP 403.

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

### Planned API extensions

| Capability | Status | GAP | Notes |
|------------|--------|-----|-------|
| Per-request analyzer/scoring knobs (full parity with CLI) | Shipped | GAP-213 | Expanded `ScanRequest` |
| OAuth object on REST auth | Shipped | GAP-093 | OAuth fields on `ScanRequest` |
| Taxonomy tree in API response | Missing | GAP-094 | Hierarchical MCTS-T |
| MCP server mode over stdio | Planned | GAP-115 | `scan_mcp_target`, `explain_finding` tools |
| Fleet upload / bootstrap ingest | Planned | GAP-116–118 | Enterprise defer |

See [Feature Expansion Plan — REST API](../more/feature-expansion-plan.md#rest-api-1).

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
