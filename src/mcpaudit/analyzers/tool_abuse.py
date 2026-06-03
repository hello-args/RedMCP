"""Tool abuse and path traversal testing."""

from __future__ import annotations

from mcpaudit.analyzers.base import BaseAnalyzer
from mcpaudit.mcp.models import MCPServerInfo, MCPTool
from mcpaudit.reporting.models import Finding, Severity

TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../.env",
    "~/.aws/credentials",
    "/etc/shadow",
]

FILE_TOOL_HINTS = ("read", "file", "path", "open", "load", "fetch")


class ToolAbuseAnalyzer(BaseAnalyzer):
    """Identifies tools susceptible to path traversal and unauthorized access."""

    name = "tool_abuse"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            if self._is_file_tool(tool):
                findings.append(
                    Finding(
                        id=f"abuse-path-{tool.name}",
                        analyzer=self.name,
                        title=f"Path traversal risk: {tool.name}",
                        description="File-access tool may allow directory traversal or sensitive paths.",
                        severity=Severity.HIGH,
                        tool=tool.name,
                        recommendation="Validate and canonicalize paths; restrict to an allowlisted root.",
                        evidence={"test_payloads": TRAVERSAL_PAYLOADS},
                    )
                )
        return findings

    def _is_file_tool(self, tool: MCPTool) -> bool:
        haystack = f"{tool.name} {tool.description}".lower()
        return any(hint in haystack for hint in FILE_TOOL_HINTS)
