# Protocol Fuzzing

> [Documentation](../index.md) → [Scanning](README.md)

**Fuzzing** sends test messages to a live MCP server to check how it handles malformed or unexpected input. It tests protocol robustness — not business logic.

> **Safe by default.** The default `safe` level never calls your tools. See [Fuzz levels](#fuzz-levels) below.
> **Requires consent** — fuzzing starts a real server subprocess.

---

## In plain English

Fuzzing is like knocking on a server's door with weird requests to see if it crashes, leaks information, or handles errors gracefully. MCTS sends deterministic test probes (not random mutations) and records what happens.

Three levels:
- **safe** (default) — read-only protocol checks, never invokes tools
- **standard** — adds resource/prompt edge cases, still read-only
- **aggressive** — may call tools with test payloads (requires extra consent)

Fuzz output can be fed into a full scan via `--runtime-events` for deeper analysis.

---

## Design philosophy

1. **Safe by default** — `safe` level never calls `tools/call`
2. **Explicit consent tiers** — live subprocess + optional aggressive invocation
3. **Deterministic probes** — reproducible CI signals, not random mutation
4. **Pipeline integration** — fuzz JSON feeds `--runtime-events` on scan

---

## Fuzz levels

| Level | Probes include | MCP methods touched | Tool invocation |
|-------|----------------|---------------------|-----------------|
| **safe** (default) | Malformed JSON, bad initialize, unknown methods, duplicate `tools/list` | Read-only / protocol edge cases | None |
| **standard** | safe + `resources/read` traversal URIs, `prompts/get` injection names | Read-only resource/prompt APIs | None |
| **aggressive** | standard + `tools/call` fuzz on discovered tool names | May invoke tools with test payloads | Requires `--i-understand-fuzz-risk` |

Level selection: `--fuzz-level safe|standard|aggressive` → `FuzzLevel` enum in `fuzz/payloads.py`.

### Example safe probes

| Probe ID | What it sends | What it tests |
|----------|---------------|---------------|
| `malformed-json` | Invalid JSON on stdin | Parser crash / stack trace leak |
| `missing-method` | JSON-RPC without `method` | Error handling |
| `invalid-method` | Unknown method name | Should return JSON-RPC error |
| `bad-init-version` | Invalid `protocolVersion` on initialize | Version negotiation |
| `oversized-payload` | Very large string fields | DoS / buffer behavior |
| `duplicate-tools-list` | Repeated `tools/list` | State consistency |

Standard level adds URI traversal patterns on `resources/read` and malicious prompt names on `prompts/get`. Aggressive level synthesizes `tools/call` requests per discovered tool.

---

## Usage

```bash
uv sync --extra mcp

# Safe read-only (recommended for CI)
mcts fuzz examples/live-mcp-server/server.py \
  --fuzz-level safe \
  --i-understand-live-risk

# Standard — read-only resource/prompt probes
mcts fuzz examples/live-mcp-server/server.py \
  --fuzz-level standard \
  --i-understand-live-risk

# Aggressive — may invoke tools
mcts fuzz examples/live-mcp-server/server.py \
  --fuzz-level aggressive \
  --i-understand-live-risk \
  --i-understand-fuzz-risk

# Custom launch
mcts fuzz ./server.py --command uv --args run,server.py \
  --fuzz-level safe --i-understand-live-risk

# From client config
mcts fuzz . --config ~/.cursor/mcp.json --server my-server \
  --fuzz-level safe --i-understand-live-risk -o fuzz.json
```

### Remote fuzz (HTTP/SSE)

Fuzz a remote MCP endpoint over HTTP or SSE instead of spawning a local subprocess:

```bash
# Streamable HTTP (default transport)
mcts fuzz --url https://mcp.example.com/mcp \
  --fuzz-level safe \
  --i-understand-live-risk

# With Bearer token authentication
mcts fuzz --url https://mcp.example.com/mcp \
  --bearer-token "$MCP_TOKEN" \
  --fuzz-level standard \
  --i-understand-live-risk

# SSE transport
mcts fuzz --url https://mcp.example.com/sse \
  --transport sse \
  --i-understand-live-risk

# Custom headers
mcts fuzz --url https://mcp.example.com/mcp \
  --header "X-API-Key: secret" \
  --header "X-Tenant: acme" \
  --i-understand-live-risk -o fuzz.json
```

`--url` is mutually exclusive with `--command` and `--config`. When `--url` is
provided, MCTS sends raw JSON-RPC POST requests to the endpoint using `httpx`
and classifies the responses with the same rules as stdio fuzz.

---

## Consent

| Flag / env | Required for |
|------------|--------------|
| `--i-understand-live-risk` | Starting any fuzz session (stdio subprocess **or** remote HTTP/SSE) |
| `MCTS_LIVE_OK=1` | CI bypass for live consent |
| `--i-understand-fuzz-risk` | **aggressive** level only |

Without live consent, exit code **2**. Without fuzz-risk consent on aggressive, exit code **2**.

### Remote probing consent

Remote fuzzing (`--url`) carries the same consent requirement as local stdio
fuzzing. Sending fuzz probes to a remote MCP server can trigger unexpected
behavior, consume resources, or expose security weaknesses. **Always** obtain
authorization from the server operator before running remote fuzz.

- Never fuzz production endpoints without explicit approval.
- Use `--fuzz-level safe` (default) for initial assessments — it never invokes
  `tools/call`.
- Bearer tokens and custom headers supplied via `--bearer-token` / `--header`
  are sent with every probe request. Treat them like credentials — do not log
  them or commit them to source control.
- Set `MCTS_LIVE_OK=1` in CI to bypass the interactive consent gate.

---

## Output format

Write results with `-o fuzz.json`:

```json
{
  "target": "examples/live-mcp-server/server.py",
  "fuzz_level": "safe",
  "probes_run": 12,
  "runtime_events": [
    {
      "event_type": "fuzz_probe",
      "probe_id": "malformed-json",
      "severity_hint": "medium"
    }
  ],
  "findings": [
    {
      "id": "...",
      "analyzer": "fuzz",
      "title": "Stack trace in JSON-RPC error response",
      "severity": "high",
      "technique_id": "MCTS-T-1009"
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `probes_run` | Count of executed probe cases |
| `runtime_events` | Rows for `RuntimeEventsAnalyzer` via `--runtime-events` |
| `findings` | Taxonomy-enriched fuzz findings (`analyzer: fuzz`) |

---

## Scan pipeline integration

```bash
# Step 1: Fuzz
mcts fuzz ./server.py --i-understand-live-risk -o fuzz.json

# Step 2: Full scan with telemetry replay
mcts scan ./server.py --runtime-events fuzz.json -o report.json

# Step 3: Optional HTML dashboard
mcts report report.json -o security-report.html
```

`events_from_fuzz_findings()` in `analyzers/runtime_events.py` converts fuzz output into runtime event rows.

---

## Finding classifications

`fuzz/classifier.py` categorizes server responses:

| Classification | Severity tendency | Meaning |
|----------------|-------------------|---------|
| Stack trace leaked | High | Internal paths or exceptions in response |
| Path or secret echo | High | Sensitive data reflected in error |
| Dangerous success | Medium–High | Malformed input accepted without error |
| Server crash / hang | Critical | Subprocess died or timed out |
| Clean rejection | None | Expected JSON-RPC error — no finding |

Findings receive **MCTS-T-1009** (Protocol Fuzzing Exposure) and standard `mitigation_ids` via `taxonomy/mapper.py`.

---

## Exit codes

| Code | When |
|------|------|
| 0 | No critical/high findings |
| 1 | Any **critical** or **high** fuzz finding |
| 2 | Consent error, bad level, launch failure |

---

## CI recommendation

Use **safe** level on trusted fixture servers only:

```yaml
- name: Protocol fuzz (safe)
  env:
    MCTS_LIVE_OK: "1"
  run: |
    mcts fuzz ./examples/live-mcp-server/server.py \
      --fuzz-level safe --i-understand-live-risk -o fuzz.json
    mcts scan ./examples/live-mcp-server/server.py \
      --runtime-events fuzz.json --no-progress -o report.json
```

Never run **aggressive** fuzz against production or third-party servers.

### Remote fuzz CI example

```yaml
- name: Remote protocol fuzz (safe)
  env:
    MCTS_LIVE_OK: "1"
    MCP_TOKEN: ${{ secrets.MCP_BEARER_TOKEN }}
  run: |
    mcts fuzz --url https://staging-mcp.example.com/mcp \
      --bearer-token "$MCP_TOKEN" \
      --fuzz-level safe --i-understand-live-risk -o fuzz.json
    mcts scan . --runtime-events fuzz.json --no-progress -o report.json
```

---

## Planned fuzz capabilities

| Capability | Status | GAP | Notes |
|------------|--------|-----|-------|
| Remote protocol fuzz (`mcts fuzz --url`) | **Shipped** | GAP-190 | HTTP/SSE via `--url`, `--transport`, `--bearer-token` |
| WebSocket MCP transport fuzz | Missing | GAP-187 | WebSocket transport coverage |
| Docker MCP server auto-detection | Missing | GAP-188 | Container-launched servers |
| Deeper aggressive corpus | Partial | GAP-186 | Expanded dynamic analyzer corpus |

See [Feature Expansion Plan — Fuzzing](../more/feature-expansion-plan.md#fuzzing-4).

---

## Related

- [Live Scanning](live-scanning.md)
- [CLI Reference — mcts fuzz](../platform/cli.md#mcts-fuzz)
- [Architecture — Fuzzing](../analysis/architecture.md#fuzzing-fuzz)
- [Threat Taxonomy — MCTS-T-1009](../reporting/taxonomy.md)
