"""Tests for risk scoring."""

from pathlib import Path

import pytest

from mcpaudit.core.config import ScanConfig
from mcpaudit.core.scanner import Scanner
from mcpaudit.reporting.models import Finding, ScanReport, Severity
from mcpaudit.scoring.engine import (
    RISK_WEIGHTS,
    RiskScoringEngine,
    security_score_from_raw_risk,
)


def test_perfect_score_no_findings() -> None:
    score = RiskScoringEngine().score([])
    assert score.overall == 100
    assert score.risk_index == 0
    assert score.raw_risk == 0
    assert score.basis.scorable_total == 0


def test_single_critical_exponential_score() -> None:
    findings = [
        Finding(
            id="1",
            analyzer="test",
            title="Critical",
            description="d",
            severity=Severity.CRITICAL,
            recommendation="fix",
        )
    ]
    score = RiskScoringEngine().score(findings)
    expected = security_score_from_raw_risk(25)
    assert score.raw_risk == 25
    assert score.risk_index == 25
    assert score.overall == expected
    assert score.basis.critical == 1
    assert 50 < score.overall < 65


def test_compliance_findings_do_not_affect_score() -> None:
    findings = [
        Finding(
            id="1",
            analyzer="permission_analyzer",
            title="Critical",
            description="d",
            severity=Severity.CRITICAL,
            recommendation="fix",
        ),
        Finding(
            id="2",
            analyzer="compliance",
            title="Quality gate failed",
            description="d",
            severity=Severity.CRITICAL,
            recommendation="fix",
        ),
    ]
    score = RiskScoringEngine().score(findings)
    assert score.raw_risk == 25
    assert score.basis.critical == 1
    assert score.basis.excluded_non_scorable == 1
    assert score.overall == security_score_from_raw_risk(25)


def test_many_criticals_differentiate_scores() -> None:
    engine = RiskScoringEngine()
    four = engine.score(
        [
            Finding(
                id=str(i),
                analyzer="test",
                title="c",
                description="d",
                severity=Severity.CRITICAL,
                recommendation="fix",
            )
            for i in range(4)
        ]
    )
    ten = engine.score(
        [
            Finding(
                id=str(i),
                analyzer="test",
                title="c",
                description="d",
                severity=Severity.CRITICAL,
                recommendation="fix",
            )
            for i in range(10)
        ]
    )
    assert four.overall > ten.overall
    assert four.raw_risk == 100
    assert ten.raw_risk == 250
    assert ten.overall < four.overall


def test_verify_detects_tampered_score() -> None:
    findings = [
        Finding(
            id="1",
            analyzer="test",
            title="High",
            description="d",
            severity=Severity.HIGH,
            recommendation="fix",
        )
    ]
    real = RiskScoringEngine().score(findings)
    tampered = real.model_copy(update={"overall": 99})
    assert RiskScoringEngine.verify(findings, real)
    assert not RiskScoringEngine.verify(findings, tampered)


@pytest.mark.parametrize(
    ("path", "min_score", "max_score", "min_raw", "max_raw"),
    [
        ("examples/safe-mcp-server/server.py", 95, 100, 0, 5),
        ("examples/medium-risk-mcp-server/server.py", 55, 85, 15, 35),
        ("examples/vulnerable-mcp-server/server.py", 1, 20, 100, 200),
    ],
)
def test_real_server_scores_in_expected_bands(
    path: str,
    min_score: int,
    max_score: int,
    min_raw: int,
    max_raw: int,
) -> None:
    """Scores must be computed from real analyzer output, not hardcoded."""
    report = Scanner(ScanConfig(target=Path(path))).run()
    assert RiskScoringEngine.verify(report.findings, report.score)
    assert min_score <= report.score.overall <= max_score
    assert min_raw <= report.score.raw_risk <= max_raw
    assert report.score.raw_risk == (
        report.score.basis.critical * RISK_WEIGHTS[Severity.CRITICAL]
        + report.score.basis.high * RISK_WEIGHTS[Severity.HIGH]
        + report.score.basis.medium * RISK_WEIGHTS[Severity.MEDIUM]
        + report.score.basis.low * RISK_WEIGHTS[Severity.LOW]
    )
    assert report.score.overall == security_score_from_raw_risk(report.score.raw_risk)


def test_json_roundtrip_preserves_verifiable_score(tmp_path: Path) -> None:
    report = Scanner(ScanConfig(target=Path("examples/vulnerable-mcp-server/server.py"))).run()
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json())
    loaded = ScanReport.model_validate_json(path.read_text())
    assert RiskScoringEngine.verify(loaded.findings, loaded.score)


def test_safe_beats_vulnerable() -> None:
    safe = Scanner(ScanConfig(target=Path("examples/safe-mcp-server/server.py"))).run()
    bad = Scanner(ScanConfig(target=Path("examples/vulnerable-mcp-server/server.py"))).run()
    assert safe.score.overall > bad.score.overall
    assert safe.score.raw_risk < bad.score.raw_risk
