"""Path validation gaps in file-access tool handlers."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.tool_classification import is_file_access_tool
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation

CANONICALIZATION_HINTS = re.compile(
    r"\b(resolve|realpath|abspath|canonicalize|normpath|is_relative_to|startswith)\b",
    re.I,
)


class PathValidationAnalyzer(BaseAnalyzer):
    """Flags file tools that lack path canonicalization or traversal guards."""

    name = "path_validation"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            if not is_file_access_tool(tool):
                continue
            snippet = tool.handler_snippet or ""
            if tool.source_file and tool.source_file in server.source_files:
                snippet = server.source_files[tool.source_file]
            if not CANONICALIZATION_HINTS.search(snippet):
                findings.append(
                    Finding(
                        id=f"path-missing-validation-{tool.name}",
                        analyzer=self.name,
                        title=f"Missing path validation: {tool.name}",
                        description="File-access tool does not canonicalize or restrict paths.",
                        severity=Severity.HIGH,
                        tool=tool.name,
                        recommendation="Resolve paths and restrict access to an allowlisted root directory.",
                        technique_id="MCTS-T-1002",
                        confidence=0.7,
                        location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                        evidence={"missing": "path_canonicalization"},
                    )
                )
        return findings
