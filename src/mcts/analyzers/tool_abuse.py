"""Tool abuse and path traversal testing."""

from __future__ import annotations

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.path_traversal import SENSITIVE_PATH_TARGETS, TRAVERSAL_PAYLOADS
from mcts.analyzers.tool_classification import is_file_access_tool
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity


class ToolAbuseAnalyzer(BaseAnalyzer):
    """Identifies tools susceptible to path traversal and unauthorized access."""

    name = "tool_abuse"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            if is_file_access_tool(tool):
                findings.append(
                    Finding(
                        id=f"abuse-path-{tool.name}",
                        analyzer=self.name,
                        title=f"Path traversal risk: {tool.name}",
                        description=(
                            "File-access tool may allow directory traversal, encoded paths, "
                            "or sensitive file targets."
                        ),
                        severity=Severity.HIGH,
                        tool=tool.name,
                        recommendation="Validate and canonicalize paths; restrict to an allowlisted root.",
                        technique_id="MCTS-T-1002",
                        evidence={
                            "test_payloads": list(TRAVERSAL_PAYLOADS),
                            "sensitive_targets": list(SENSITIVE_PATH_TARGETS),
                        },
                    )
                )
        return findings
