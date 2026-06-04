"""Main scan orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime

from mcpaudit import __version__
from mcpaudit.analyzers.attack_chains import AttackChainAnalyzer
from mcpaudit.analyzers.data_leakage import DataLeakageAnalyzer
from mcpaudit.analyzers.jailbreak import JailbreakAnalyzer
from mcpaudit.analyzers.permissions import PermissionAnalyzer
from mcpaudit.analyzers.prompt_injection import PromptInjectionAnalyzer
from mcpaudit.analyzers.tool_abuse import ToolAbuseAnalyzer
from mcpaudit.compliance.checks import ComplianceChecker
from mcpaudit.core.config import ScanConfig
from mcpaudit.mcp.client import MCPClient
from mcpaudit.reporting.models import Finding, ScanReport, ScanSummary
from mcpaudit.scoring.engine import RiskScoringEngine


class Scanner:
    """Coordinates analyzers and produces a unified security report."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.client = MCPClient(config.target)
        self.analyzers = [
            PermissionAnalyzer(),
            PromptInjectionAnalyzer(),
            ToolAbuseAnalyzer(),
            DataLeakageAnalyzer(),
            JailbreakAnalyzer(),
            AttackChainAnalyzer(),
        ]
        self.compliance = ComplianceChecker()
        self.scoring = RiskScoringEngine()

    def run(self) -> ScanReport:
        """Execute all enabled analyzers against the target MCP server."""
        server_info = self.client.discover()
        findings: list[Finding] = []

        for analyzer in self.analyzers:
            if not self._is_enabled(analyzer):
                continue
            findings.extend(analyzer.analyze(server_info))

        findings.extend(self.compliance.check(findings))
        score = self.scoring.score(findings)
        summary = ScanSummary.from_findings(findings)

        if not RiskScoringEngine.verify(findings, score):
            raise RuntimeError("Risk score does not match findings — scoring regression")

        return ScanReport(
            version=__version__,
            target=str(self.config.target),
            scanned_at=datetime.now(UTC),
            server=server_info,
            findings=findings,
            summary=summary,
            score=score,
        )

    def analyzers_run_count(self) -> int:
        """Return the number of security analyzers executed."""
        return sum(1 for analyzer in self.analyzers if self._is_enabled(analyzer))

    def _is_enabled(self, analyzer: object) -> bool:
        name = type(analyzer).__name__
        if name == "JailbreakAnalyzer":
            return self.config.enable_jailbreak
        if name == "AttackChainAnalyzer":
            return self.config.enable_attack_chains
        return True
