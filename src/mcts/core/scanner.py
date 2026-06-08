"""Main scan orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime

from mcts import __version__
from mcts.analyzers.attack_chains import AttackChainAnalyzer
from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
from mcts.analyzers.cloud_inspect import CloudInspectAnalyzer
from mcts.analyzers.command_execution import CommandExecutionAnalyzer
from mcts.analyzers.cross_server import CrossServerAnalyzer
from mcts.analyzers.data_leakage import DataLeakageAnalyzer
from mcts.analyzers.embedding_secrets import EmbeddingSecretsAnalyzer
from mcts.analyzers.jailbreak import JailbreakAnalyzer
from mcts.analyzers.line_jumping import LineJumpingAnalyzer
from mcts.analyzers.llm_judge import LlmJudgeAnalyzer
from mcts.analyzers.metadata_dedupe import dedupe_metadata_findings
from mcts.analyzers.metadata_diff import MetadataDiffAnalyzer, save_baseline
from mcts.analyzers.metadata_integrity import MetadataIntegrityAnalyzer
from mcts.analyzers.npm_audit import NpmAuditAnalyzer
from mcts.analyzers.oauth_config import OAuthConfigAnalyzer
from mcts.analyzers.path_validation import PathValidationAnalyzer
from mcts.analyzers.permissions import PermissionAnalyzer
from mcts.analyzers.prompt_defense import PromptDefenseAnalyzer
from mcts.analyzers.prompt_injection import PromptInjectionAnalyzer
from mcts.analyzers.runtime_events import RuntimeEventsAnalyzer
from mcts.analyzers.schema_surface import SchemaSurfaceAnalyzer
from mcts.analyzers.sigma_dedupe import dedupe_sigma_findings
from mcts.analyzers.sigma_metadata import SigmaMetadataAnalyzer
from mcts.analyzers.supply_chain import SupplyChainAnalyzer
from mcts.analyzers.surface_metadata import SurfaceMetadataAnalyzer
from mcts.analyzers.tool_abuse import ToolAbuseAnalyzer
from mcts.analyzers.tool_shadowing import ToolShadowingAnalyzer
from mcts.analyzers.virustotal import VirusTotalAnalyzer
from mcts.analyzers.vulnerable_package import VulnerablePackageAnalyzer
from mcts.analyzers.yara_metadata import YaraMetadataAnalyzer
from mcts.compliance.checks import ComplianceChecker
from mcts.core.config import ScanConfig
from mcts.inventory.models import InventoryEntry
from mcts.mcp.client import MCPClient
from mcts.mcp.models import MCPServerInfo, SurfaceScanOptions
from mcts.probe.protocol_checks import probe_protocol_security
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
        self.analyzers = self._build_analyzers()
        self.compliance = ComplianceChecker()
        self.scoring = RiskScoringEngine()

    def _build_analyzers(self) -> list[object]:
        cfg = self.config
        rows: list[object] = [
            PermissionAnalyzer(),
            MetadataIntegrityAnalyzer(skip_poison_checks=cfg.enable_surface_metadata),
            PromptInjectionAnalyzer(),
            ToolShadowingAnalyzer(),
            LineJumpingAnalyzer(),
            ToolAbuseAnalyzer(),
            SchemaSurfaceAnalyzer(),
            DataLeakageAnalyzer(),
            CommandExecutionAnalyzer(),
            PathValidationAnalyzer(),
            RuntimeEventsAnalyzer(),
            SigmaMetadataAnalyzer(sigma_rules_path=cfg.sigma_rules_path),
            OAuthConfigAnalyzer(target=cfg.target, inventory=self.inventory),
            SupplyChainAnalyzer(target=cfg.target),
            EmbeddingSecretsAnalyzer(semantic_secrets=cfg.semantic_secrets),
            MetadataDiffAnalyzer(baseline_path=cfg.baseline_path),
            JailbreakAnalyzer(),
            CrossServerAnalyzer(inventory=self.inventory),
            self.attack_chains,
        ]
        if cfg.enable_surface_metadata:
            rows.insert(1, SurfaceMetadataAnalyzer(surfaces=cfg.surfaces))
        if cfg.enable_prompt_defense:
            rows.append(PromptDefenseAnalyzer())
        if cfg.enable_behavioral_static:
            rows.append(BehavioralStaticAnalyzer())
        if cfg.pip_audit:
            rows.append(VulnerablePackageAnalyzer(target=cfg.target))
        if cfg.npm_audit:
            rows.append(NpmAuditAnalyzer(target=cfg.target))
        if cfg.enable_yara:
            rows.append(YaraMetadataAnalyzer(rules_path=cfg.yara_rules_path))
        if cfg.enable_llm_judge:
            rows.append(LlmJudgeAnalyzer(model=cfg.llm_model))
        if cfg.enable_cloud_inspect:
            rows.append(CloudInspectAnalyzer(endpoint=cfg.cloud_endpoint))
        if cfg.enable_virustotal:
            rows.append(VirusTotalAnalyzer(target=cfg.target, max_files=cfg.vt_max_files))
        return rows

    def run(self) -> ScanReport:
        """Execute all enabled analyzers against the target MCP server."""
        server_info = self._attach_surface_options(self.client.discover())
        return self.analyze_server(server_info)

    def analyze_server(self, server_info: MCPServerInfo) -> ScanReport:
        """Run analyzers against an already-discovered server snapshot."""
        server_info = self._attach_surface_options(server_info)
        runtime_events = list(self.config.runtime_events)
        if self.config.live or self.config.remote_url:
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
            if not self._analyzer_allowed(analyzer):
                continue
            findings.extend(analyzer.analyze(server_info))

        if self.config.protocol_probe and self.config.remote_url:
            findings.extend(probe_protocol_security(self.config.remote_url))

        findings = self._apply_filters(findings)
        findings = dedupe_metadata_findings(findings)
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

    def _attach_surface_options(self, server_info: MCPServerInfo) -> MCPServerInfo:
        cfg = self.config
        return server_info.model_copy(
            update={
                "surface_scan": SurfaceScanOptions(
                    surfaces=list(cfg.surfaces),
                    resource_mime_allowlist=list(cfg.resource_mime_allowlist),
                )
            }
        )

    def analyzers_run_count(self) -> int:
        """Return the number of security analyzers executed."""
        return sum(
            1
            for analyzer in self.analyzers
            if self._is_enabled(analyzer) and self._analyzer_allowed(analyzer)
        )

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

    def _analyzer_allowed(self, analyzer: object) -> bool:
        if not self.config.analyzers:
            return True
        name = getattr(analyzer, "name", type(analyzer).__name__)
        return name in self.config.analyzers or type(analyzer).__name__ in self.config.analyzers

    def _apply_filters(self, findings: list[Finding]) -> list[Finding]:
        rows = findings
        if self.config.analyzer_filter:
            allowed = set(self.config.analyzer_filter)
            rows = [f for f in rows if f.analyzer in allowed]
        if self.config.severity_filter:
            allowed = {s.lower() for s in self.config.severity_filter}
            rows = [f for f in rows if f.severity.value in allowed]
        if self.config.tool_filter:
            allowed = set(self.config.tool_filter)
            rows = [f for f in rows if f.tool is None or f.tool in allowed]
        return rows
