"""Main scan orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime

from mcts import __version__
from mcts.analyzers.attack_chains import AttackChainAnalyzer
from mcts.analyzers.command_execution import CommandExecutionAnalyzer
from mcts.analyzers.cross_server import CrossServerAnalyzer
from mcts.analyzers.data_leakage import DataLeakageAnalyzer
from mcts.analyzers.embedding_secrets import EmbeddingSecretsAnalyzer
from mcts.analyzers.jailbreak import JailbreakAnalyzer
from mcts.analyzers.line_jumping import LineJumpingAnalyzer
from mcts.analyzers.metadata_diff import MetadataDiffAnalyzer, save_baseline
from mcts.analyzers.metadata_integrity import MetadataIntegrityAnalyzer
from mcts.analyzers.oauth_config import OAuthConfigAnalyzer
from mcts.analyzers.path_validation import PathValidationAnalyzer
from mcts.analyzers.permissions import PermissionAnalyzer
from mcts.analyzers.prompt_injection import PromptInjectionAnalyzer
from mcts.analyzers.runtime_events import RuntimeEventsAnalyzer
from mcts.analyzers.schema_surface import SchemaSurfaceAnalyzer
from mcts.analyzers.sigma_dedupe import dedupe_sigma_findings
from mcts.analyzers.sigma_metadata import SigmaMetadataAnalyzer
from mcts.analyzers.supply_chain import SupplyChainAnalyzer
from mcts.analyzers.tool_abuse import ToolAbuseAnalyzer
from mcts.analyzers.tool_shadowing import ToolShadowingAnalyzer
from mcts.compliance.checks import ComplianceChecker
from mcts.core.config import ScanConfig
from mcts.inventory.models import InventoryEntry
from mcts.mcp.client import MCPClient
from mcts.reporting.models import Finding, ScanReport, ScanSummary
from mcts.scoring.engine import RiskScoringEngine
from mcts.taxonomy.mapper import enrich_findings


class Scanner:
    """Coordinates analyzers and produces a unified security report."""

    def __init__(
        self,
        config: ScanConfig,
        inventory: list[InventoryEntry] | None = None,
    ) -> None:
        self.config = config
        self.client = MCPClient(config.target, config)
        self.inventory = inventory or []
        self.attack_chains = AttackChainAnalyzer()
        self.analyzers = [
            PermissionAnalyzer(),
            MetadataIntegrityAnalyzer(),
            PromptInjectionAnalyzer(),
            ToolShadowingAnalyzer(),
            LineJumpingAnalyzer(),
            ToolAbuseAnalyzer(),
            SchemaSurfaceAnalyzer(),
            DataLeakageAnalyzer(),
            CommandExecutionAnalyzer(),
            PathValidationAnalyzer(),
            RuntimeEventsAnalyzer(),
            SigmaMetadataAnalyzer(sigma_rules_path=config.sigma_rules_path),
            OAuthConfigAnalyzer(target=config.target, inventory=self.inventory),
            SupplyChainAnalyzer(target=config.target),
            EmbeddingSecretsAnalyzer(semantic_secrets=config.semantic_secrets),
            MetadataDiffAnalyzer(baseline_path=config.baseline_path),
            JailbreakAnalyzer(),
            CrossServerAnalyzer(inventory=self.inventory),
            self.attack_chains,
        ]
        self.compliance = ComplianceChecker()
        self.scoring = RiskScoringEngine()

    def run(self) -> ScanReport:
        """Execute all enabled analyzers against the target MCP server."""
        server_info = self.client.discover()
        runtime_events = list(self.config.runtime_events)
        if self.config.live:
            from mcts.probe.behavioral import events_from_behavioral_probe
            from mcts.probe.events import events_from_live_server, merge_runtime_events

            runtime_events = merge_runtime_events(
                runtime_events,
                events_from_live_server(server_info),
                events_from_behavioral_probe(server_info, multi_turn=self.config.behavioral_probe),
            )
        elif self.config.behavioral_probe:
            from mcts.probe.behavioral import events_from_behavioral_probe
            from mcts.probe.events import merge_runtime_events

            runtime_events = merge_runtime_events(
                runtime_events,
                events_from_behavioral_probe(server_info, multi_turn=True),
            )
        if runtime_events:
            server_info = server_info.model_copy(
                update={
                    "runtime_events": [
                        *server_info.runtime_events,
                        *runtime_events,
                    ]
                }
            )
        findings: list[Finding] = []

        for analyzer in self.analyzers:
            if not self._is_enabled(analyzer):
                continue
            findings.extend(analyzer.analyze(server_info))

        findings = dedupe_sigma_findings(findings)
        findings = enrich_findings(findings)
        findings.extend(self.compliance.check(findings))
        score = self.scoring.score(findings)
        summary = ScanSummary.from_findings(findings)

        if not RiskScoringEngine.verify(findings, score):
            raise RuntimeError("Risk score does not match findings — scoring regression")

        attack_graph = self.attack_chains.last_graph if self.config.enable_attack_chains else {}

        if self.config.save_baseline_path is not None:
            save_baseline(server_info, self.config.save_baseline_path, target=str(self.config.target))

        return ScanReport(
            version=__version__,
            target=str(self.config.target),
            scanned_at=datetime.now(UTC),
            server=server_info,
            findings=findings,
            summary=summary,
            score=score,
            attack_graph=attack_graph,
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
        if name == "MetadataDiffAnalyzer":
            return self.config.baseline_path is not None
        if name == "EmbeddingSecretsAnalyzer":
            return self.config.semantic_secrets
        return True
