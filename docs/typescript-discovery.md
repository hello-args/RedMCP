# TypeScript / JavaScript Static Discovery

MCTS discovers MCP tools in TypeScript and JavaScript source without running Node or installing npm dependencies.

## Supported patterns

| Pattern | Example |
|---------|---------|
| `registerTool` | Modern `@modelcontextprotocol/sdk` `McpServer.registerTool("name", { inputSchema: { ... } }, handler)` |
| `server.tool` | Shorthand `server.tool("name", { param: z.string() }, handler)` |
| `setRequestHandler(ListToolsRequestSchema)` | Legacy SDK — extracts tools from inline `tools: [{ name, description, inputSchema }]` |
| `setRequestHandler(CallToolRequestSchema)` | Fallback tool names from `params.name === "..."` / `case "..."` branches |

## File types

`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`

Skipped by default: `node_modules`, `dist`, `build`, `tests/`, `__tests__/`

## Usage

```bash
# Scan a TS MCP repo (Python + TypeScript by default)
mcts scan examples/bench/multi-file-ts-server/

# TypeScript only
mcts scan ./my-server/ --languages typescript

# Python only (skip JS/TS)
mcts scan ./repo/ --languages python

# Single file
mcts scan src/server.ts
```

## Configuration

`ScanConfig.languages` defaults to `["python", "typescript"]`. Directory scans run both backends and merge tools by name (richest schema wins).

Zod schemas (`z.string()`, `z.number()`, etc.) and inline JSON Schema `properties` are mapped to tool `input_schema` for analyzers and capability inference.

## Design note

MCTS focuses on **MCP-specific tool registration patterns** with zero extra dependencies — suitable for CI scans of Node MCP servers alongside Python repos.

Optional future: tree-sitter depth for TypeScript handler parsing (Phase 2+).
