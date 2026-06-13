"""Apply findings trust layer outside the main Scanner pipeline."""

from __future__ import annotations

from typing import Any

from mcts.core.config import ScanConfig
from mcts.mcp.models import MCPTool
from mcts.reporting.display import effective_severity
from mcts.reporting.models import Finding, Severity
from mcts.reporting.trust_pipeline import apply_trust_layer, build_trust_context


def apply_config_trust_layer(
    findings: list[Finding],
    config: ScanConfig,
    *,
    scan_scope: str = "repository",
    tools: list[MCPTool] | None = None,
    attack_graph: dict[str, Any] | None = None,
) -> list[Finding]:
    ctx = build_trust_context(
        mode=config.findings_trust_mode,
        scan_scope=scan_scope,
        tools=tools,
        attack_graph=attack_graph,
    )
    return apply_trust_layer(findings, ctx)


def resolve_config_with_policy(config: ScanConfig) -> ScanConfig:
    from mcts.governance import load_policy, merge_scan_config_with_policy

    try:
        policy = load_policy(config.governance_policy)
    except FileNotFoundError:
        policy = None
    return merge_scan_config_with_policy(config, policy)


def finding_severity_label(finding: Finding, config: ScanConfig) -> str:
    if config.findings_trust_mode == "off":
        return finding.severity.value
    return effective_severity(finding).value


def merge_scan_config_defaults(
    config: ScanConfig,
    *,
    findings_trust_mode: str = "off",
) -> ScanConfig:
    merged = config.model_copy(update={"findings_trust_mode": findings_trust_mode.lower()})
    return resolve_config_with_policy(merged)
