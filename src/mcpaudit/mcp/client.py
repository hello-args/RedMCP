"""MCP client for server discovery and probing."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from mcpaudit.mcp.models import MCPServerInfo, MCPTool

TOOL_DECORATOR_PATTERN = re.compile(
    r"@(?:\w+\.)?tool\s*\([^)]*\)\s*\n\s*(?:async\s+)?def\s+(\w+)\s*\(",
    re.MULTILINE,
)
DOCSTRING_PATTERN = re.compile(
    r"def\s+\w+\s*\([^)]*\)\s*(?:->[^:]*)?:\s*(?:\"\"\"(.*?)\"\"\"|'\'\'(.*?)\'\'\')?",
    re.DOTALL,
)


class MCPClient:
    """Discovers MCP server capabilities from source or live connection."""

    def __init__(self, target: Path) -> None:
        self.target = target

    def discover(self) -> MCPServerInfo:
        """Discover tools from a Python MCP server entrypoint (static analysis)."""
        if not self.target.exists():
            return MCPServerInfo(name=str(self.target), tools=[])

        source = self.target.read_text(encoding="utf-8")
        tools = self._parse_tools_from_source(source)
        return MCPServerInfo(
            name=self.target.stem,
            tools=tools,
            transport="stdio",
        )

    def _parse_tools_from_source(self, source: str) -> list[MCPTool]:
        tools: list[MCPTool] = []
        for match in TOOL_DECORATOR_PATTERN.finditer(source):
            func_name = match.group(1)
            description = self._extract_docstring(source, func_name)
            tools.append(MCPTool(name=func_name, description=description))
        return tools

    def _extract_docstring(self, source: str, func_name: str) -> str:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return ""

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == func_name:
                doc = ast.get_docstring(node)
                return doc or ""
        return ""
