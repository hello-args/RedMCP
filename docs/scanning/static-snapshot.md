# Static JSON Snapshot Scanning

> [Documentation](../index.md) → [Scanning](README.md)

**Snapshot scanning** analyzes a pre-exported JSON file of MCP tool metadata — no source code, no running server, no network. Ideal for air-gapped environments or CI pipelines that export tool lists separately.

> **Have source code?** A regular static scan is simpler: `mcts scan ./repo/`

---

## In plain English

Sometimes you can't run MCTS against live source code or a running server — for example, in an air-gapped CI environment. Snapshot mode lets you export your server's tool list as JSON (from a trusted environment) and scan that file offline.

MCTS reads the JSON, extracts tool names, descriptions, and schemas, and runs the same security analyzers as a normal scan. Handler source code checks won't run (there's no source), but metadata checks (permissions, poisoning, schema issues) still work.

---

## When to use

| Scenario | Why snapshot mode |
|----------|-------------------|
| CI without subprocess/network | Scan exported JSON artifact only |
| Regulated environments | No live MCP connection |
| Comparing analyzer versions | Same input across MCTS releases |
| PR review of tool metadata | Scan changed `tools.json` from build |

**Use snapshot when** the authoritative source is an exported MCP `tools/list` (or combined prompts/resources JSON) from a live server — not when prompts live only as markdown files in your repo.

Snapshot mode expects a real MCP metadata export. Do not pass `mcts_analysis/scan-report.json` or another MCTS scan report as `--snapshot`; those files are reports about a scan, not `tools/list` inputs.

---

## Snapshot vs repository markdown discovery

MCTS supports two ways to analyze prompt/instruction content without a live MCP connection:

| Approach | Input | Best for |
|----------|-------|----------|
| **`--snapshot`** | Exported JSON (`tools`, `prompts`, `resources`, `instructions` from MCP protocol) | Air-gapped CI, regulated envs, comparing live server metadata across MCTS versions |
| **Repo markdown discovery** (default on static scans) | Files under scan target: `SKILL.md`, `*prompt*.md`, `system_prompt.md` | Agent repos (Aegra, Cursor skills, embedded system prompts) with no MCP `prompts/list` |

```bash
# Snapshot — metadata from a prior live export
mcts scan . --snapshot ./artifacts/mcp-export.json --surfaces prompt,instruction

# Repo markdown — walks the repository (no JSON export needed)
mcts scan . --surfaces prompt,instruction
```

| | Snapshot | Repo markdown |
|--|----------|---------------|
| Requires live export step | Yes | No |
| Finds `skills/foo/SKILL.md` in repo | Only if you put it in snapshot JSON | Yes (default) |
| Handler / SAST on `.py` tools | No (no source in JSON) | Yes when combined with normal static scan |
| Disabled when | N/A | `--no-discover-instructions`, or when using `--snapshot` / `--live` / `--url` |

For hybrid workflows, run a full static scan (tools from source + prompts from markdown), or export live MCP surfaces to JSON and scan with `--snapshot` when the server is the source of truth.

---

## Input formats

### Combined snapshot object

```json
{
  "tools": [
    {
      "name": "fetch",
      "description": "Fetch a URL",
      "inputSchema": { "type": "object", "properties": { "url": { "type": "string" } } }
    }
  ],
  "prompts": [],
  "resources": [],
  "instructions": "You are a helpful assistant."
}
```

### Tools-only array

```json
[
  { "name": "greet", "description": "Say hello", "inputSchema": {} }
]
```

### Separate files (advanced)

Use individual paths via CLI when exporting prompts/resources separately (future flags); primary entry is `--snapshot`.

---

## Usage

```bash
# Export tools from a trusted environment, then scan offline
mcts scan . --snapshot ./artifacts/tools-list.json -o report.json

# With CI gates
mcts scan . --snapshot tools.json \
  --fail-on-critical --min-score 70 \
  -o report.json
```

`discovery_mode` on the resulting `MCPServerInfo` is `static-json`.

---

## Analyzers that apply

All metadata analyzers run on snapshot data:

- `SurfaceMetadataAnalyzer` — tools, prompts, resources, instructions
- `SigmaMetadataAnalyzer`, `PromptInjectionAnalyzer`, etc. on tools
- `PromptDefenseAnalyzer` on prompts/instructions
- Supply chain analyzers still scan the **repository** at `target` when `--pip-audit` / `--npm-audit` are set

Snapshot mode does **not** produce live `runtime_events` unless you also pass `--runtime-events`.

---

## Exporting a snapshot

Use `mcts snapshot` to connect live and write normalized JSON for offline scans:

```bash
mcts snapshot . \
  --config .mcp.json \
  --server my-server \
  --i-understand-live-risk \
  -o tools-snapshot.json

mcts scan . --snapshot tools-snapshot.json -o report.json
```

Alternative: use your MCP client's `tools/list` JSON-RPC response directly.

---

## Related

- [CLI Reference](../platform/cli.md#mcts-scan)
- [Remote Scanning](remote-scanning.md)
- [CI Integration](../platform/ci-integration.md)
