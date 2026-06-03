"""Permission and privilege analyzer."""

from __future__ import annotations

import re

from mcpaudit.analyzers.base import BaseAnalyzer
from mcpaudit.mcp.models import MCPServerInfo, MCPTool
from mcpaudit.reporting.models import Finding, Severity

DESTRUCTIVE_PATTERNS = re.compile(
    r"\b(delete|drop|remove|destroy|wipe|purge|truncate|kill|shutdown)\b",
    re.IGNORECASE,
)
HIGH_RISK_PATTERNS = re.compile(
    r"\b(exec|execute|run|shell|sudo|admin|grant|revoke|write|upload)\b",
    re.IGNORECASE,
)


class PermissionAnalyzer(BaseAnalyzer):
    """Flags destructive, over-privileged, and missing-confirmation tools."""

    name = "permission_analyzer"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            findings.extend(self._analyze_tool(tool))
        return findings

    def _analyze_tool(self, tool: MCPTool) -> list[Finding]:
        findings: list[Finding] = []
        haystack = f"{tool.name} {tool.description}"

        if DESTRUCTIVE_PATTERNS.search(haystack):
            findings.append(
                Finding(
                    id=f"perm-destructive-{tool.name}",
                    analyzer=self.name,
                    title=f"Destructive tool: {tool.name}",
                    description="Tool appears to perform destructive operations without safeguards.",
                    severity=Severity.CRITICAL,
                    tool=tool.name,
                    recommendation="Require explicit confirmation token or human-in-the-loop approval.",
                    evidence={"description": tool.description},
                )
            )

        if HIGH_RISK_PATTERNS.search(haystack):
            findings.append(
                Finding(
                    id=f"perm-high-risk-{tool.name}",
                    analyzer=self.name,
                    title=f"High-risk tool: {tool.name}",
                    description="Tool exposes privileged or execution-capable behavior.",
                    severity=Severity.HIGH,
                    tool=tool.name,
                    recommendation="Apply least privilege and scope tool inputs strictly.",
                    evidence={"description": tool.description},
                )
            )

        return findings
