"""Phase 3 runtime and taint-flow evidence validation."""

from __future__ import annotations

from mcts.reporting.models import Finding


def validate_runtime_evidence(findings: list[Finding]) -> list[Finding]:
    """Tag validated taint/live findings and set evidence tier when trust is active."""
    return [_validate_runtime_one(finding) for finding in findings]


def _validate_runtime_one(finding: Finding) -> Finding:
    evidence = dict(finding.evidence or {})
    facts = evidence.get("facts")
    has_facts = isinstance(facts, list) and bool(facts)

    if finding.analyzer == "behavioral_static" and evidence.get("tainted_params") and evidence.get("sinks"):
        evidence["runtime_validation"] = "taint_param_sink"
        evidence["evidence_tier"] = (
            "silver" if has_facts and any(isinstance(row, dict) and row.get("snippet") for row in facts) else "bronze"
        )
        updates: dict[str, object] = {"evidence": evidence}
        if evidence.get("tainted_params"):
            updates["finding_type"] = "validated"
            if finding.confidence is not None and finding.confidence < 0.78:
                updates["confidence"] = 0.78
        return finding.model_copy(update=updates)

    if finding.analyzer == "jailbreak" and evidence.get("analysis_mode") == "live_probe":
        evidence["runtime_validation"] = "live_probe"
        evidence["evidence_tier"] = "silver" if has_facts else "bronze"
        return finding.model_copy(
            update={
                "evidence": evidence,
                "finding_type": "validated",
            }
        )

    return finding
