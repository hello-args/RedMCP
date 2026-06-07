"""Repository-wide static MCP tool discovery for TypeScript and JavaScript."""

from __future__ import annotations

import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from mcts.capability.inferrer import infer_capability
from mcts.core.config import ScanConfig
from mcts.core.target import ScanTarget, TargetKind
from mcts.mcp.models import MCPServerInfo, MCPTool

JS_EXTENSIONS = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})

JS_GLOBS = ("**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs")

MCP_FILE_INDICATORS = (
    "registerTool(",
    ".tool(",
    "setRequestHandler",
    "ListToolsRequestSchema",
    "CallToolRequestSchema",
    "McpServer",
    "@modelcontextprotocol/sdk",
)

DEFAULT_SKIP_PATH_PARTS = frozenset({"tests", "test", "__tests__"})

REGISTER_TOOL_PATTERN = re.compile(
    r"\.registerTool\s*\(\s*['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)

TOOL_METHOD_PATTERN = re.compile(
    r"\.tool\s*\(\s*['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)

LIST_TOOLS_HANDLER_PATTERN = re.compile(
    r"setRequestHandler\s*\(\s*ListToolsRequestSchema\s*,",
    re.MULTILINE,
)

TOOL_OBJECT_NAME_PATTERN = re.compile(
    r"name\s*:\s*['\"]([^'\"]+)['\"]",
)

DESCRIPTION_PATTERN = re.compile(
    r"description\s*:\s*['\"]([^'\"]+)['\"]",
)

ZOD_PROP_PATTERN = re.compile(
    r"(\w+)\s*:\s*z\.(string|number|boolean|array|object)\(\)",
)

JSON_SCHEMA_PROP_PATTERN = re.compile(
    r"(\w+)\s*:\s*\{\s*type\s*:\s*['\"](\w+)['\"]",
)

CALL_TOOL_NAME_PATTERN = re.compile(
    r"(?:params\.name\s*===\s*|case\s+)['\"]([^'\"]+)['\"]",
)

ZOD_TYPE_MAP = {
    "string": "string",
    "number": "number",
    "boolean": "boolean",
    "array": "array",
    "object": "object",
}


class JsStaticDiscovery:
    """Discover MCP tools by walking TypeScript and JavaScript source files."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.target = ScanTarget(config.target)

    def discover(self) -> MCPServerInfo:
        if self.target.kind == TargetKind.FILE:
            return self._discover_file(self.target.path)

        source_files = self._collect_source_files(self.target.path)
        tools: list[MCPTool] = []
        for file_path in source_files:
            tools.extend(self._parse_tools_from_file(Path(file_path)))

        return MCPServerInfo(
            name=self.target.path.name,
            tools=_dedupe_tools(tools),
            transport="stdio",
            discovery_mode="static",
            source_files=source_files,
        )

    def _discover_file(self, file_path: Path) -> MCPServerInfo:
        if not file_path.exists():
            return MCPServerInfo(name=str(file_path), tools=[])

        content = self._read_file(file_path)
        tools = _dedupe_tools(self._parse_tools_from_content(file_path, content))
        return MCPServerInfo(
            name=file_path.stem,
            tools=tools,
            transport="stdio",
            discovery_mode="static",
            source_files={str(file_path): content},
        )

    def _collect_source_files(self, root: Path) -> dict[str, str]:
        files: dict[str, str] = {}
        for glob in JS_GLOBS:
            for path in sorted(root.glob(glob)):
                if not self._should_scan(path, root):
                    continue
                content = self._read_file(path)
                if content and self._looks_like_mcp_file(content):
                    files[str(path)] = content
        return files

    def _should_scan(self, path: Path, root: Path) -> bool:
        if path.suffix.lower() not in JS_EXTENSIONS:
            return False
        rel = path.relative_to(root)
        parts = set(rel.parts)
        if parts & DEFAULT_SKIP_PATH_PARTS:
            return False
        if any(part in self.config.exclude_dirs for part in rel.parts):
            return False
        rel_str = str(rel)
        if self.config.exclude_globs and any(fnmatch(rel_str, g) for g in self.config.exclude_globs):
            return False
        if self.config.include_globs:
            py_only = all(g.endswith(".py") for g in self.config.include_globs)
            if py_only:
                return True
            if not any(fnmatch(rel_str, g) for g in self.config.include_globs):
                return False
        try:
            if path.stat().st_size > self.config.max_file_bytes:
                return False
        except OSError:
            return False
        return True

    def _read_file(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ""

    def _looks_like_mcp_file(self, content: str) -> bool:
        return any(indicator in content for indicator in MCP_FILE_INDICATORS)

    def _parse_tools_from_file(self, file_path: Path) -> list[MCPTool]:
        content = self._read_file(file_path)
        if not content:
            return []
        return self._parse_tools_from_content(file_path, content)

    def _parse_tools_from_content(self, file_path: Path, content: str) -> list[MCPTool]:
        tools: list[MCPTool] = []
        tools.extend(self._tools_from_register_and_tool_methods(file_path, content))
        tools.extend(self._tools_from_list_handler(file_path, content))
        tools.extend(self._tools_from_call_handler(file_path, content))
        return tools

    def _tools_from_register_and_tool_methods(self, file_path: Path, content: str) -> list[MCPTool]:
        tools: list[MCPTool] = []
        for pattern in (REGISTER_TOOL_PATTERN, TOOL_METHOD_PATTERN):
            for match in pattern.finditer(content):
                tool_name = match.group(1)
                line = content[: match.start()].count("\n") + 1
                window = content[match.start() : match.start() + 1200]
                description = _first_match(DESCRIPTION_PATTERN, window) or ""
                schema = _schema_from_window(window)
                snippet = _handler_snippet(content, match.start())
                tool = MCPTool(
                    name=tool_name,
                    description=description,
                    input_schema=schema,
                    source_file=str(file_path),
                    source_line=line,
                    handler_snippet=snippet,
                )
                tool.capability = infer_capability(tool)
                tools.append(tool)
        return tools

    def _tools_from_list_handler(self, file_path: Path, content: str) -> list[MCPTool]:
        tools: list[MCPTool] = []
        for match in LIST_TOOLS_HANDLER_PATTERN.finditer(content):
            block = _extract_brace_block(content, match.end())
            if not block:
                continue
            line = content[: match.start()].count("\n") + 1
            for name_match in TOOL_OBJECT_NAME_PATTERN.finditer(block):
                tool_name = name_match.group(1)
                local = block[name_match.start() : name_match.start() + 600]
                description = _first_match(DESCRIPTION_PATTERN, local) or ""
                schema = _schema_from_window(local)
                tool = MCPTool(
                    name=tool_name,
                    description=description,
                    input_schema=schema,
                    source_file=str(file_path),
                    source_line=line,
                    handler_snippet=block[:80],
                )
                tool.capability = infer_capability(tool)
                tools.append(tool)
        return tools

    def _tools_from_call_handler(self, file_path: Path, content: str) -> list[MCPTool]:
        if "CallToolRequestSchema" not in content:
            return []

        known = (
            {match.group(1) for match in REGISTER_TOOL_PATTERN.finditer(content)}
            | {match.group(1) for match in TOOL_METHOD_PATTERN.finditer(content)}
            | {match.group(1) for match in TOOL_OBJECT_NAME_PATTERN.finditer(content)}
        )

        tools: list[MCPTool] = []
        for match in CALL_TOOL_NAME_PATTERN.finditer(content):
            tool_name = match.group(1)
            if tool_name in known:
                continue
            line = content[: match.start()].count("\n") + 1
            snippet = _handler_snippet(content, match.start(), max_lines=30)
            tool = MCPTool(
                name=tool_name,
                source_file=str(file_path),
                source_line=line,
                handler_snippet=snippet,
            )
            tool.capability = infer_capability(tool)
            tools.append(tool)
            known.add(tool_name)
        return tools


def _dedupe_tools(tools: list[MCPTool]) -> list[MCPTool]:
    by_name: dict[str, MCPTool] = {}
    for tool in tools:
        existing = by_name.get(tool.name)
        if existing is None or _tool_richness(tool) > _tool_richness(existing):
            by_name[tool.name] = tool
    return list(by_name.values())


def _tool_richness(tool: MCPTool) -> int:
    score = len(tool.input_schema.get("properties", {}))
    score += 2 if tool.description else 0
    score += 2 if tool.handler_snippet else 0
    return score


def _first_match(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1) if match else None


def _schema_from_window(text: str) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []

    for match in ZOD_PROP_PATTERN.finditer(text):
        prop_name = match.group(1)
        json_type = ZOD_TYPE_MAP.get(match.group(2), "string")
        properties[prop_name] = {"type": json_type}
        required.append(prop_name)

    for match in JSON_SCHEMA_PROP_PATTERN.finditer(text):
        prop_name = match.group(1)
        if prop_name not in properties:
            properties[prop_name] = {"type": match.group(2)}

    req_match = re.search(r"required\s*:\s*\[(.*?)\]", text, re.DOTALL)
    if req_match:
        required = re.findall(r"['\"](\w+)['\"]", req_match.group(1))

    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = sorted(set(required))
    return schema


def _extract_brace_block(content: str, start: int) -> str:
    brace_start = content.find("{", start)
    if brace_start < 0:
        return ""
    depth = 0
    for index in range(brace_start, min(len(content), brace_start + 8000)):
        char = content[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return content[brace_start : index + 1]
    return content[brace_start : brace_start + 2000]


def _handler_snippet(content: str, start: int, max_lines: int = 40) -> str:
    line_start = content.rfind("\n", 0, start) + 1
    lines = content[line_start:].splitlines()[:max_lines]
    return "\n".join(lines)
