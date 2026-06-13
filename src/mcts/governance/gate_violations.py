"""Combined scan + governance policy gate evaluation."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.governance.policy import evaluate_policy, load_policy
from mcts.governance.scan_gates import evaluate_scan_gate_violations
from mcts.reporting.models import ScanReport


def _policy_server_ids(report: ScanReport) -> list[str]:
    """Identifiers checked against YAML allowlist/blocklist."""
    ids: list[str] = []
    name = (report.server.name or "").strip()
    if name:
        ids.append(name)
    target = str(report.target).strip()
    if target and target not in ids:
        ids.append(target)
    return ids or [target]


def collect_gate_violations(report: ScanReport, config: ScanConfig) -> list[str]:
    """Scan gates plus YAML governance policy (allowlist, v2 category mins, etc.)."""
    violations = list(evaluate_scan_gate_violations(report, config))
    if config.ignore_policy:
        return violations
    try:
        policy = load_policy(config.governance_policy)
    except FileNotFoundError:
        policy = None
    if policy is None:
        return violations
    violations.extend(evaluate_policy(policy=policy, servers=_policy_server_ids(report)))
    return violations
