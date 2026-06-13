"""Governance policy merge into scan config."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.governance.policy import GovernancePolicy, load_policy, merge_scan_config_with_policy
from mcts.reporting.display import summary_for_gates

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")
POLICY_EXAMPLE = Path(".mcts/policy.yaml.example")


def test_merge_policy_applies_trust_mode_when_cli_default() -> None:
    policy = load_policy(POLICY_EXAMPLE)
    base = ScanConfig(target=SINGLE_TOOL)
    merged = merge_scan_config_with_policy(base, policy)
    assert merged.findings_trust_mode == "enforce"
    assert merged.max_critical == 0
    assert merged.min_score == 70


def test_merge_policy_does_not_override_explicit_cli() -> None:
    policy = GovernancePolicy(findings_trust_mode="enforce", max_critical=0)
    base = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="warn",
        fail_on_priority_min=50,
    )
    merged = merge_scan_config_with_policy(base, policy)
    assert merged.findings_trust_mode == "warn"
    assert merged.fail_on_priority_min == 50


def test_merged_policy_enables_trust_on_scan() -> None:
    policy = load_policy(POLICY_EXAMPLE)
    config = merge_scan_config_with_policy(ScanConfig(target=SINGLE_TOOL), policy)
    report = Scanner(config).run()
    assert report.findings_trust_mode == "enforce"
    assert report.display_summary is not None
    assert report.display_summary.critical == 0
    gate_summary = summary_for_gates(report, config)
    assert gate_summary.critical == 0
