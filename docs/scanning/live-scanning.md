# Live MCP Probing

> [Documentation](../index.md) → [Scanning](README.md)

**Live probing** starts your MCP server as a subprocess and asks it what tools, prompts, and resources it exposes at runtime. This catches differences between what your source code says and what the server actually advertises.

> **Default scan mode (static) is enough for most users.** Only use live probing when you need runtime schemas or don't have source code.
> **Requires consent** — live mode starts a real server process. See [Consent model](#consent-model) below.

---

## In plain English

A static scan reads your source code. A live probe **runs your server** and talks to it over the MCP protocol to get the actual tool list, schemas, and server instructions.

Use live probing when:
- You want to verify what the server **actually exposes** at runtime (not just what's in the code)
- You don't have source code — only a config entry pointing to an npm package or binary
- You want to detect **rug pulls** — when a server's advertised tools change between scans

Live probing does **not** call your tools during a scan (read-only `list_*` methods only). To test tool invocation, use [Protocol Fuzzing](fuzzing.md).

---

## When to use live probing

| Scenario | Recommendation |
|----------|----------------|
| Python/TS source available in repo | Static scan first; add `--live` to merge schemas |
| Config-only server (npm package, remote binary) | `--config` + `--server` + `--live` |
| Rug-pull / metadata drift detection | Compare live listings with `--baseline` |
| Runtime technique detection | `--live` enables behavioral probe events (MCTS-T-1026) |
| CI on trusted fixture server | `MCTS_LIVE_OK=1` + `--no-progress` |

Live probing does **not** invoke tools during scan (read-only `list_*` methods). Controlled invocation belongs in [Protocol Fuzzing](fuzzing.md) (`aggressive` level only).

---

## Consent model

Live probing **always starts a subprocess** and speaks MCP over stdio. MCTS will not spawn servers silently.

| Method | Usage |
|--------|-------|
| `--i-understand-live-risk` | Interactive CLI consent |
| `MCTS_LIVE_OK=1` | CI / automation consent (environment variable) |

Fuzzing reuses the same live consent gate. **Aggressive** fuzz additionally requires `--i-understand-fuzz-risk` because it may call `tools/call`.

Implementation: `probe/consent.py` → `live_consent_granted()`.

---

## Install

```bash
uv sync --extra mcp
```

Requires the official MCP Python SDK (`mcp>=1.27`). Without it, live and fuzz commands fail at import or session setup.

---

## Usage patterns

### Auto-launch Python entrypoint

```bash
mcts scan examples/live-mcp-server/server.py \
  --live --i-understand-live-risk
```

MCTS resolves a launch command from the target file (typically `python server.py`) unless overridden.

### Custom launch command

Use when the server needs a specific runner:

```bash
mcts scan ./server.py --live --i-understand-live-risk \
  --command uv --args run,server.py
```

`--args` is comma-separated (no spaces inside the flag value).

### From client MCP config

Scan a server defined in Cursor, Claude, VS Code, or Windsurf config without local source:

```bash
mcts scan . --live --i-understand-live-risk \
  --config ~/.cursor/mcp.json --server my-server
```

Use `.` as the target placeholder when launching purely from config. Requires both `--config` and `--server`.

Config parsing: `discovery/live_config.py` reads `command`, `args`, and `env` from the `mcpServers` entry.

---

## Discovery modes

After discovery, `MCPServerInfo.discovery_mode` indicates how tools were obtained:

| Mode | Value | When set |
|------|-------|----------|
| Static | `static` | Default repo/file scan without `--live` |
| Live | `live` | Live-only (no mergeable static tools) |
| Merged | `merged` | `--live` with static tools present — richest schema wins per tool name |
| Empty | `empty` | Config-only target with no resolvable source files |

### Merge semantics

When `--live` is set and static discovery found tools, `discovery/merge.py` combines:

- Tool names and descriptions from both sources
- `input_schema` — prefers the schema with more properties / richer types
- `handler_snippet` and `source_file` — retained from static side when available
- `discovered_via` — tracks `"static"`, `"live"`, or merged provenance

Config flag: `ScanConfig.merge_static_live` (default `true`).

---

## Probe session internals

| Module | Responsibility |
|--------|----------------|
| `probe/session.py` | Async stdio `ProbeSession` using MCP SDK |
| `discovery/live.py` | Orchestrates probe → `MCPServerInfo` |
| `probe/events.py` | Normalizes listings into `runtime_events` rows |
| `probe/behavioral.py` | Multi-turn behavioral patterns (MCTS-T-1026) |

Typical live session sequence:

1. Spawn subprocess with resolved command/args/env
2. MCP `initialize` handshake
3. `tools/list`, `prompts/list`, `resources/list` as supported
4. Read server instructions / metadata when exposed
5. Tear down subprocess

Timeout: `ScanConfig.timeout_seconds` (default 120).

---

## Runtime events and behavioral probe

Live scans attach telemetry consumed by `RuntimeEventsAnalyzer` and sub-detectors (`oauth_mixup`, `command_injection`, `rug_pull`, `behavioral_extraction`, etc.).

### Automatic with `--live`

- **Live metadata events** — tool/prompt/resource listings from probe session
- **Behavioral probe** — enabled by default when `--live` is set (`behavioral_probe=True` in config)

### Explicit behavioral probe (static + events file)

```bash
mcts scan ./server.py --behavioral-probe
```

Useful when you have source but want multi-turn probe patterns without full live schema merge.

### Pre-recorded or fuzz-generated events

```bash
mcts fuzz ./server.py --i-understand-live-risk -o fuzz.json
mcts scan ./server.py --runtime-events fuzz.json
```

`--runtime-events` accepts:

- A JSON **array** of event objects, or
- An object with a `runtime_events` array

Each row is a `dict` merged into `MCPServerInfo.runtime_events` before analyzers run.

---

## TypeScript and config-only servers

When no Python/TS source exists in the target path:

```bash
mcts scan . --config ~/.cursor/mcp.json --server node-server \
  --live --i-understand-live-risk
```

If source **is** present, static TS discovery still runs in parallel. See [TypeScript Discovery](typescript-discovery.md).

---

## Interaction with other scan flags

| Flag | Interaction with `--live` |
|------|---------------------------|
| `--languages` | Static side only; live always uses protocol |
| `--baseline` / `--save-baseline` | Compares metadata snapshots; useful for rug-pull |
| `--runtime-events` | Merged with live-generated events |
| `--sigma-rules-path` | Applies to merged `MCPServerInfo` |
| `--semantic-secrets` | Static source analysis; independent of live |
| `--fail-on-*` gates | Apply to final report regardless of discovery mode |

---

## Remote transport (HTTP / SSE)

For hosted MCP servers, use `--url` instead of `--live` subprocess launch:

```bash
mcts scan . --url https://mcp.example.com/mcp \
  --bearer-token "$TOKEN" --i-understand-live-risk
```

See [Remote Scanning](remote-scanning.md) for SSE, OAuth, and `--protocol-probe`.

---

## Env var expansion

IDE configs often use `$HOME` or `%USERPROFILE%` in commands. MCTS expands these by default:

```bash
mcts scan . --config ~/.cursor/mcp.json --server my-server \
  --expand-vars auto --live --i-understand-live-risk
```

Implementation: `discovery/env_expand.py`.

---

## Stderr capture

Debug failing server launches:

```bash
mcts scan ./server.py --live --i-understand-live-risk \
  --stderr-file /tmp/mcp-server.stderr
```

---

## Limitations (alpha)

| Limitation | Detail | Notes |
|------------|--------|-------|
| **Read-only probe** | No `tools/call` during scan | Use `mcts fuzz` |
| **Consent required** | No silent subprocess/remote | By design |
| **Single server** | One target per scan | Inventory + cross-server analyzer for multi-config |
| **Trust boundary** | Only probe servers you authorize | Documented in SECURITY.md |
| **Fuzz stdio-only** | `mcts fuzz` does not support `--url` yet | Remote fuzz planned |

---

## CI example

```bash
export MCTS_LIVE_OK=1
pip install "mcp-mcts[mcp]"

mcts scan examples/live-mcp-server/server.py \
  --live --no-progress \
  -o report.json \
  --min-score 70
```

---

## Related

- [Remote Scanning](remote-scanning.md)
- [CLI Reference — scan flags](../platform/cli.md#mcts-scan)
- [CI Integration — MCTS_LIVE_OK](../platform/ci-integration.md)
- [Protocol Fuzzing](fuzzing.md)
- [Architecture — Probe layer](../analysis/architecture.md#probe-layer-probe)
