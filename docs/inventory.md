# MCP Config Inventory

`mcts inventory` discovers MCP servers configured on the local machine by reading known client config files. Optional static scans list tool names per server; cross-server analysis flags **tool shadowing** when the same tool name appears on multiple servers.

---

## Usage

```bash
# List configured servers
mcts inventory

# Static-scan each server entrypoint and export JSON
mcts inventory --scan -o inventory.json
```

Exit code **1** when cross-server shadow findings include critical or high severity.

---

## Supported clients

Platform-specific paths are checked under `inventory/discoverers.py`:

| Client | Config locations (examples) |
|--------|----------------------------|
| **Cursor** | `~/.cursor/mcp.json` |
| **Claude Desktop** | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows: `%AppData%/Roaming/Claude/claude_desktop_config.json` |
| **VS Code** | `~/.vscode/mcp.json`, `settings.json` (`mcp.servers`) |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` |

Only existing files are scanned. Client name is inferred from the path.

---

## Output

Terminal listing:

```
MCP inventory — 2 config file(s)
  • cursor
  • claude
  [cursor] my-server (12 tools) — /Users/you/.cursor/mcp.json
  [claude] filesystem — /Users/you/Library/.../claude_desktop_config.json

Cross-server shadowing: 1 finding(s)
  • Tool name collision: read_file
```

JSON export (`-o`) structure:

```json
{
  "clients_scanned": ["cursor", "claude"],
  "config_files_found": 2,
  "entries": [
    {
      "client": "cursor",
      "server_name": "my-server",
      "command": "uv",
      "args": ["run", "server.py"],
      "config_path": "/Users/you/.cursor/mcp.json",
      "tools": ["read_file", "write_file"]
    }
  ],
  "shadow_findings": []
}
```

With `--scan`, `tools` is populated by running a lightweight static `Scanner` on each resolved entrypoint (`.py` path preferred from `args`).

---

## Cross-server shadowing

`CrossServerAnalyzer.analyze_inventory()` detects when **identical tool names** appear on different MCP servers in the inventory. This maps to **MCTS-T-1008** (Cross-Server Tool Shadowing) — an agent may invoke the wrong server's handler when names collide.

During `mcts scan`, the same analyzer runs when inventory context is provided (future: auto-inventory hook).

---

## Scanning from inventory

To security-scan a server listed in your config:

```bash
mcts scan . --config ~/.cursor/mcp.json --server my-server
mcts scan . --config ~/.cursor/mcp.json --server my-server \
  --live --i-understand-live-risk
```

See [live-scanning.md](live-scanning.md).

---

## Limitations

- Discovers **local user configs** only — not remote or enterprise fleet management
- `--scan` resolves targets heuristically from `command`/`args`; non-Python entrypoints may need explicit `mcts scan` with `--command`
- Breadth is limited to four common MCP clients today; broader agent support is on the roadmap

---

## Related

- [CLI Reference — mcts inventory](cli.md#mcts-inventory--shipped)
- [Architecture — Inventory](architecture.md#inventory-inventory)
- [Taxonomy — MCTS-T-1008](taxonomy.md)
