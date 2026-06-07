# Protocol Fuzzing

MCTS includes **safe read-only protocol fuzzing** — deterministic probes that test MCP stdio robustness without destructive payloads by default.

## Fuzz levels

| Level | What it does | Tool invocation |
|-------|----------------|-----------------|
| **safe** (default) | Malformed JSON-RPC, bad initialize, duplicate `tools/list` | None — read-only |
| **standard** | safe + `resources/read` traversal URIs, `prompts/get` injection names | Read-only MCP methods only |
| **aggressive** | standard + `tools/call` fuzz on discovered tools | Requires `--i-understand-fuzz-risk` |

Implementation: `fuzz/runner.py`, `fuzz/payloads.py`, `fuzz/classifier.py`.

---

## Usage

```bash
uv sync --extra mcp

# Safe read-only protocol fuzz (default)
mcts fuzz examples/live-mcp-server/server.py \
  --fuzz-level safe \
  --i-understand-live-risk

# Standard — adds read-only resource/prompt probes
mcts fuzz examples/live-mcp-server/server.py \
  --fuzz-level standard \
  --i-understand-live-risk

# Custom launch
mcts fuzz ./server.py --command uv --args run,server.py \
  --fuzz-level safe --i-understand-live-risk

# From client config
mcts fuzz . --config ~/.cursor/mcp.json --server my-server \
  --fuzz-level safe --i-understand-live-risk -o fuzz.json
```

---

## Consent

| Flag / env | Purpose |
|------------|---------|
| `--i-understand-live-risk` | Starts a real MCP server subprocess |
| `--i-understand-fuzz-risk` | Required for **aggressive** (may call tools with test payloads) |
| `MCTS_LIVE_OK=1` | CI bypass for live consent |

---

## Output & scan pipeline

Fuzz writes JSON with `findings`, `runtime_events`, `probes_run`, and `fuzz_level`:

```bash
mcts fuzz ./server.py --i-understand-live-risk -o fuzz.json
mcts scan ./server.py --runtime-events fuzz.json -o report.json
```

`RuntimeEventsAnalyzer` consumes telemetry rows; findings use analyzer `fuzz` and technique **MCTS-T-1009**.

Exit code **1** when any critical or high fuzz finding is present.

---

## Findings

Classifications include:

- Stack traces leaked in responses
- Path or secret echoes
- Dangerous success (probe accepted without JSON-RPC error)
- Server crash / hang

Findings are taxonomy-enriched (`technique_id`, `mitigation_ids`) like static scan results.

---

## Design philosophy

MCTS fuzz defaults to **read-only protocol probes** with explicit consent tiers. Use `safe` or `standard` in CI; reserve `aggressive` (may invoke `tools/call`) for trusted lab servers only.

---

## Related

- [Live Scanning](live-scanning.md)
- [CLI Reference — mcts fuzz](cli.md#mcts-fuzz)
- [Architecture — Fuzzing](architecture.md#fuzzing-fuzz)
