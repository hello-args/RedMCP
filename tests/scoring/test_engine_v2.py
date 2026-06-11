"""Tests for RiskScoringEngineV2."""

import json
from pathlib import Path
from unittest.mock import patch

from mcts.reporting.models import Finding, Severity
from mcts.scoring.context import scorable_findings_v2
from mcts.scoring.engine_v2 import (
    RiskScoringEngineV2,
    compute_dimension_scores,
    dimension_raw_sums,
    finding_risk,
)
from mcts.scoring.factors import ScoringContext
from mcts.scoring.models import RiskFactorVector
from mcts.scoring.weights import load_weights


def _vector(**kwargs: float) -> RiskFactorVector:
    return RiskFactorVector(**kwargs)


def test_rfc_worked_example_fixture_matches_engine() -> None:
    """Golden test using tests/fixtures/rfc_worked_example.json (RFC §4.1)."""
    fixture = json.loads(
        Path("tests/fixtures/rfc_worked_example.json").read_text(encoding="utf-8")
    )
    weights = load_weights("manual_v1")
    findings = [
        Finding(
            id=row["id"],
            analyzer="prompt_injection" if "injection" in row["id"] else (
                "tool_abuse" if "abuse" in row["id"] else "data_leakage"
            ),
            title="RFC",
            description="d",
            severity=Severity.HIGH if row["severity"] == "high" else Severity.CRITICAL,
            recommendation="fix",
            tool="read_file",
        )
        for row in fixture["findings"]
    ]
    vectors = [
        _vector(exploitability=0.50, reachability=0.35, exposure=0.40),
        _vector(exploitability=0.40, reachability=0.35),
        _vector(exploitability=0.10),
    ]
    ctx = ScoringContext(
        findings=findings,
        tools=[],
        attack_graph={
            "paths": [{"hop_count": 3, "tools_on_path": ["read_file", "run_cmd", "send_webhook"]}]
        },
        scan_scope="repository",
        weights=weights,
        corpus_stats=None,
        chain_factors={f.id: 1.35 for f in findings},
        chain_factor_mode="paths_v1",
    )
    with patch("mcts.scoring.engine_v2.build_factor_vector", side_effect=vectors):
        risks = [finding_risk(f, ctx) for f in findings]
    assert risks == [row["finding_risk"] for row in fixture["findings"]]
    assert sum(risks) == fixture["absolute_risk"]


def test_bracket_matches_rfc_example() -> None:
    """RFC §4.1 worked example: 90/70/110 base × 1.35 chain → 366 absolute."""
    weights = load_weights("manual_v1")
    findings = [
        Finding(
            id="prompt-injection",
            analyzer="prompt_injection",
            title="Injection",
            description="d",
            severity=Severity.HIGH,
            recommendation="fix",
            tool="read_file",
        ),
        Finding(
            id="tool-abuse",
            analyzer="tool_abuse",
            title="Abuse",
            description="d",
            severity=Severity.HIGH,
            recommendation="fix",
            tool="run_cmd",
        ),
        Finding(
            id="data-exfil",
            analyzer="data_leakage",
            title="Exfil",
            description="d",
            severity=Severity.CRITICAL,
            recommendation="fix",
            tool="send_webhook",
        ),
    ]
    vectors = [
        _vector(exploitability=0.50, reachability=0.35, exposure=0.40),
        _vector(exploitability=0.40, reachability=0.35),
        _vector(exploitability=0.10),
    ]
    ctx = ScoringContext(
        findings=findings,
        tools=[],
        attack_graph={
            "paths": [{"hop_count": 3, "tools_on_path": ["read_file", "run_cmd", "send_webhook"]}]
        },
        scan_scope="repository",
        weights=weights,
        corpus_stats=None,
        chain_factors={f.id: 1.35 for f in findings},
        chain_factor_mode="paths_v1",
    )

    with patch("mcts.scoring.engine_v2.build_factor_vector", side_effect=vectors):
        risks = [finding_risk(f, ctx) for f in findings]
    assert risks == [122, 95, 149]
    assert sum(risks) == 366


def test_absolute_risk_invariant_to_confidence() -> None:
    weights = load_weights("manual_v1")
    finding = Finding(
        id="1",
        analyzer="command_execution",
        title="Exec",
        description="d",
        severity=Severity.HIGH,
        recommendation="fix",
        confidence=0.5,
    )
    ctx = ScoringContext(
        findings=[finding],
        tools=[],
        attack_graph={},
        scan_scope="repository",
        weights=weights,
        corpus_stats=None,
        chain_factors={},
    )
    engine = RiskScoringEngineV2()
    score_low = engine.score(ctx, legacy_overall=50)
    finding_high_conf = finding.model_copy(update={"confidence": 1.0})
    ctx_high = ScoringContext(
        findings=[finding_high_conf],
        tools=[],
        attack_graph={},
        scan_scope="repository",
        weights=weights,
        corpus_stats=None,
        chain_factors={},
    )
    score_high = engine.score(ctx_high, legacy_overall=50)
    assert score_low.absolute_risk == score_high.absolute_risk
    assert score_low.confidence_score != score_high.confidence_score


def test_dimension_scores_are_relative_not_flat() -> None:
    """Radar axes must differ when factor loads differ (not all corpus-saturated 100)."""
    weights = load_weights("manual_v1")
    findings = [
        Finding(
            id="exec",
            analyzer="command_execution",
            title="Exec",
            description="d",
            severity=Severity.HIGH,
            recommendation="fix",
            tool="run",
        ),
        Finding(
            id="perm",
            analyzer="permissions",
            title="Perm",
            description="delete all",
            severity=Severity.CRITICAL,
            recommendation="fix",
            tool="wipe",
        ),
    ]
    ctx = ScoringContext(
        findings=findings,
        tools=[],
        attack_graph={},
        scan_scope="entrypoint",
        weights=weights,
        corpus_stats=None,
        chain_factors={},
    )
    raw = dimension_raw_sums(findings, ctx)
    scores = compute_dimension_scores(findings, ctx)
    assert max(scores.values()) == 100
    assert min(scores.values()) < 100
    assert scores["threat_maturity"] < scores["exploitability"]
    assert sum(raw.values()) > 0


def test_attack_chains_excluded_from_scorable() -> None:
    findings = [
        Finding(
            id="chain",
            analyzer="attack_chains",
            title="Chain",
            description="d",
            severity=Severity.CRITICAL,
            recommendation="fix",
        ),
        Finding(
            id="real",
            analyzer="prompt_injection",
            title="PI",
            description="d",
            severity=Severity.HIGH,
            recommendation="fix",
        ),
    ]
    scorable = scorable_findings_v2(findings)
    assert len(scorable) == 1
    assert scorable[0].id == "real"
