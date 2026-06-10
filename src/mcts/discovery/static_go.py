"""Repository-wide static MCP tool discovery for Go."""

from __future__ import annotations

import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from mcts.capability.inferrer import infer_capability
from mcts.core.config import ScanConfig
from mcts.core.target import ScanTarget, TargetKind
from mcts.mcp.models import MCPServerInfo, MCPTool

GO_EXTENSIONS = frozenset({".go"})
GO_GLOBS = ("**/*.go",)

MCP_FILE_INDICATORS = (
    "AddTool(",
    "RegisterTool(",
    "ListToolsRequestSchema",
    "CallToolRequestSchema",
    "github.com/modelcontextprotocol/go-sdk",
    "github.com/mark3labs/mcp-go",
    "mcp.NewServer",
    "server.AddTool",
)

DEFAULT_SKIP_PATH_PARTS = frozenset({"tests", "test", "vendor", "testdata"})

ADD_TOOL_PATTERN = re.compile(
    r"\.AddTool\s*\(\s*(?:mcp\.)?Tool\s*\{[^}]*Name\s*:\s*\"([^\"]+)\"",
    re.MULTILINE | re.DOTALL,
)
ADD_TOOL_STRING_PATTERN = re.compile(
    r"\.AddTool\s*\(\s*[\"']([^\"']+)[\"']",
    re.MULTILINE,
)
REGISTER_TOOL_PATTERN = re.compile(
    r"RegisterTool\s*\(\s*[\"']([^\"']+)[\"']",
    re.MULTILINE,
)
DESCRIPTION_PATTERN = re.compile(
    r"Description\s*:\s*\"([^\"]+)\"",
)
CALL_TOOL_NAME_PATTERN = re.compile(
    r"case\s+[\"']([^\"']+)[\"']\s*:",
)


class GoStaticDiscovery:
    """Discover MCP tools by walking Go source files."""

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
        for glob in GO_GLOBS:
            for path in sorted(root.glob(glob)):
                if not self._should_scan(path, root):
                    continue
                content = self._read_file(path)
                if content and self._looks_like_mcp_file(content):
                    files[str(path)] = content
        return files

    def _should_scan(self, path: Path, root: Path) -> bool:
        if path.suffix.lower() not in GO_EXTENSIONS:
            return False
        rel = path.relative_to(root)
        if set(rel.parts) & DEFAULT_SKIP_PATH_PARTS:
            return False
        if any(part in self.config.exclude_dirs for part in rel.parts):
            return False
        rel_str = str(rel)
        if self.config.exclude_globs and any(fnmatch(rel_str, g) for g in self.config.exclude_globs):
            return False
        if self.config.include_globs:
            py_or_js_only = all(
                g.endswith(".py") or g.endswith(".ts") or g.endswith(".js") for g in self.config.include_globs
            )
            if py_or_js_only:
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
        for pattern in (ADD_TOOL_STRING_PATTERN, REGISTER_TOOL_PATTERN):
            for match in pattern.finditer(content):
                tools.append(self._tool_from_match(file_path, content, match))
        for match in ADD_TOOL_PATTERN.finditer(content):
            tools.append(self._tool_from_struct_match(file_path, content, match))
        tools.extend(self._tools_from_call_handler(file_path, content, tools))
        return tools

    def _tool_from_match(self, file_path: Path, content: str, match: re.Match[str]) -> MCPTool:
        tool_name = match.group(1)
        line = content[: match.start()].count("\n") + 1
        window = content[match.start() : match.start() + 1200]
        description = _first_match(DESCRIPTION_PATTERN, window) or ""
        tool = MCPTool(
            name=tool_name,
            description=description,
            input_schema={"type": "object", "properties": {}},
            source_file=str(file_path),
            source_line=line,
            handler_snippet=_handler_snippet(content, match.start()),
        )
        tool.capability = infer_capability(tool)
        return tool

    def _tool_from_struct_match(self, file_path: Path, content: str, match: re.Match[str]) -> MCPTool:
        return self._tool_from_match(file_path, content, match)

    def _tools_from_call_handler(
        self, file_path: Path, content: str, existing: list[MCPTool]
    ) -> list[MCPTool]:
        known = {tool.name for tool in existing}
        tools: list[MCPTool] = []
        for match in CALL_TOOL_NAME_PATTERN.finditer(content):
            tool_name = match.group(1)
            if tool_name in known:
                continue
            line = content[: match.start()].count("\n") + 1
            tool = MCPTool(
                name=tool_name,
                source_file=str(file_path),
                source_line=line,
                handler_snippet=_handler_snippet(content, match.start(), max_lines=30),
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


def _handler_snippet(content: str, start: int, max_lines: int = 40) -> str:
    line_start = content.rfind("\n", 0, start) + 1
    lines = content[line_start:].splitlines()[:max_lines]
    return "\n".join(lines)
