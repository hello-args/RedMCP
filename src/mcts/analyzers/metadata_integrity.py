"""Tool metadata integrity checks (description poisoning)."""

from __future__ import annotations

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.tpa_patterns import (
    scan_text_poison,
    scan_text_templates,
)
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity, SourceLocation

EXCESSIVE_LENGTH = 500


class MetadataIntegrityAnalyzer(BaseAnalyzer):
    """Detects poisoned or manipulative tool descriptions."""

    name = "metadata_integrity"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            findings.extend(self._analyze_tool(tool))
        return findings

    def _analyze_tool(self, tool: MCPTool) -> list[Finding]:
        findings: list[Finding] = []
        description = tool.description or ""

        for field, text in (("description", description), ("name", tool.name)):
            for label, severity in scan_text_poison(text) + scan_text_templates(text):
                findings.append(
                    self._finding(tool, f"meta-poison-{tool.name}-{field}-{label}", label, severity, field)
                )

        if len(description) > EXCESSIVE_LENGTH:
            findings.append(
                Finding(
                    id=f"meta-excessive-desc-{tool.name}",
                    analyzer=self.name,
                    title=f"Excessive description length on {tool.name}",
                    description=(
                        f"Description is {len(description)} chars — may hide instructions (line jumping)."
                    ),
                    severity=Severity.MEDIUM,
                    tool=tool.name,
                    recommendation="Keep tool descriptions concise; move docs outside the MCP surface.",
                    technique_id="MCTS-T-1001",
                    confidence=0.6,
                    location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                    evidence={"length": len(description)},
                )
            )

        return findings

    def _finding(
        self,
        tool: MCPTool,
        finding_id: str,
        label: str,
        severity: Severity,
        field: str,
    ) -> Finding:
        return Finding(
            id=finding_id,
            analyzer=self.name,
            title=f"Metadata poisoning on {tool.name} ({field}): {label.replace('_', ' ')}",
            description="Tool metadata contains manipulative or injection patterns.",
            severity=severity,
            tool=tool.name,
            recommendation="Rewrite descriptions as neutral capability summaries.",
            technique_id="MCTS-T-1001",
            confidence=0.85,
            location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
            evidence={"pattern": label, "field": field},
        )
