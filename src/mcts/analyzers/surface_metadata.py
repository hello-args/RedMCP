"""Metadata security checks across tools, prompts, resources, and instructions."""

from __future__ import annotations

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.surface_context import is_intentional_context_surface, scan_surfaces
from mcts.analyzers.surfaces import ScanSurface, ScanSurfaceKind, parse_surfaces
from mcts.analyzers.tpa_patterns import scan_text_poison, scan_text_templates
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation


class SurfaceMetadataAnalyzer(BaseAnalyzer):
    """Applies poisoning and injection pattern checks to all MCP surfaces."""

    name = "surface_metadata"

    def __init__(self, surfaces: list[str] | None = None) -> None:
        self._surfaces = parse_surfaces(surfaces)

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for surface in scan_surfaces(server, self._surfaces):
            findings.extend(self._analyze_surface(surface))
        return findings

    def _analyze_surface(self, surface: ScanSurface) -> list[Finding]:
        findings: list[Finding] = []
        loc = SourceLocation(file=surface.source_file or "", line=surface.source_line)

        intentional_context = is_intentional_context_surface(surface)
        if not intentional_context:
            for field, text in (
                ("name", surface.name),
                ("description", surface.description),
                ("extra", surface.extra_text),
            ):
                if not text:
                    continue
                for label, severity in scan_text_poison(text) + scan_text_templates(text):
                    fid = f"surface-poison-{surface.label}-{field}-{label}"
                    findings.append(self._finding(surface, fid, label, severity, field, loc))

        if (
            surface.kind != ScanSurfaceKind.TOOL
            and len(surface.description) > 800
            and not intentional_context
        ):
            findings.append(
                Finding(
                    id=f"surface-excessive-{surface.label}",
                    analyzer=self.name,
                    title=f"Excessive {surface.kind.value} text on {surface.name}",
                    description="Long MCP surface text may hide instructions (line jumping).",
                    severity=Severity.MEDIUM,
                    tool=surface.name if surface.kind == ScanSurfaceKind.TOOL else None,
                    recommendation="Keep MCP surface descriptions concise and neutral.",
                    technique_id="MCTS-T-1001",
                    confidence=0.65,
                    location=loc,
                    evidence={"surface": surface.kind.value, "length": len(surface.description)},
                )
            )
        return findings

    def _finding(
        self,
        surface: ScanSurface,
        finding_id: str,
        label: str,
        severity: Severity,
        field: str,
        loc: SourceLocation,
    ) -> Finding:
        return Finding(
            id=finding_id,
            analyzer=self.name,
            title=f"Metadata poisoning on {surface.label} ({field}): {label.replace('_', ' ')}",
            description=f"MCP {surface.kind.value} contains manipulative or injection patterns.",
            severity=severity,
            tool=surface.name if surface.kind == ScanSurfaceKind.TOOL else None,
            recommendation="Rewrite MCP surface text as neutral capability summaries.",
            technique_id="MCTS-T-1001",
            confidence=0.85,
            location=loc,
            evidence={"pattern": label, "field": field, "surface": surface.kind.value},
        )
