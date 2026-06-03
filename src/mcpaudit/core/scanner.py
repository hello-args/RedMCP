"""Main scan orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime

from rich.console import Console
from rich.table import Table

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

console = Console()


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

        return ScanReport(
            version=__version__,
            target=str(self.config.target),
            scanned_at=datetime.now(UTC),
            server=server_info,
            findings=findings,
            summary=summary,
            score=score,
        )

    def print_summary(self, report: ScanReport) -> None:
        """Render a human-readable summary to the terminal."""
        console.print()
        console.rule("[bold red]MCPAudit Security Report[/bold red]")
        console.print(f"Target: [cyan]{report.target}[/cyan]")
        console.print(f"Overall Score: [bold]{report.score.overall}/100[/bold]")
        console.print()

        table = Table(title="Findings by Severity")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for severity, count in [
            ("Critical", report.summary.critical),
            ("High", report.summary.high),
            ("Medium", report.summary.medium),
            ("Low", report.summary.low),
        ]:
            table.add_row(severity, str(count))
        console.print(table)

        if report.findings:
            console.print()
            for finding in report.findings[:10]:
                console.print(
                    f"[{finding.severity.color}]{finding.severity.value.upper()}[/]: {finding.title}"
                )
            if len(report.findings) > 10:
                console.print(f"... and {len(report.findings) - 10} more findings")

    def _is_enabled(self, analyzer: object) -> bool:
        name = type(analyzer).__name__
        if name == "JailbreakAnalyzer":
            return self.config.enable_jailbreak
        if name == "AttackChainAnalyzer":
            return self.config.enable_attack_chains
        return True
