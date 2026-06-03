"""Tests for risk scoring."""

from mcpaudit.reporting.models import Finding, Severity
from mcpaudit.scoring.engine import RiskScoringEngine


def test_score_decreases_with_severity() -> None:
    engine = RiskScoringEngine()
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
    score = engine.score(findings)
    assert score.overall == 75
    assert score.penalty == 25
