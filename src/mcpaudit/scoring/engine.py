"""Risk scoring engine."""

from __future__ import annotations

import math

from mcpaudit.reporting.models import Finding, RiskScore, ScanSummary, ScoreBasis, Severity

# Weights for raw risk index (higher = more risk).
RISK_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}

# Exponential decay scale: score = 100 * exp(-raw_risk / RISK_DECAY_SCALE)
RISK_DECAY_SCALE = 50.0

# Meta-findings from compliance checks should not affect scoring.
NON_SCORING_ANALYZERS = frozenset({"compliance"})


class RiskScoringEngine:
    """Computes security score (higher is better) and risk index (higher is worse)."""

    def score(self, findings: list[Finding]) -> RiskScore:
        """Derive all score fields from the findings list — nothing is hardcoded."""
        scorable, excluded = _partition_findings(findings)
        summary = ScanSummary.from_findings(scorable)
        raw_risk = raw_risk_from_summary(summary)
        overall = security_score_from_raw_risk(raw_risk)
        risk_index = min(100, raw_risk)

        return RiskScore(
            overall=overall,
            risk_index=risk_index,
            raw_risk=raw_risk,
            penalty=raw_risk,
            basis=ScoreBasis(
                critical=summary.critical,
                high=summary.high,
                medium=summary.medium,
                low=summary.low,
                scorable_total=summary.total,
                excluded_non_scorable=excluded,
            ),
        )

    @staticmethod
    def verify(findings: list[Finding], computed: RiskScore) -> bool:
        """Return True if ``computed`` matches a fresh calculation from ``findings``."""
        return RiskScoringEngine().score(findings) == computed


def _partition_findings(findings: list[Finding]) -> tuple[list[Finding], int]:
    scorable = [f for f in findings if f.analyzer not in NON_SCORING_ANALYZERS]
    excluded = len(findings) - len(scorable)
    return scorable, excluded


def raw_risk_from_summary(summary: ScanSummary) -> int:
    """Linear risk points from severity counts."""
    return (
        summary.critical * RISK_WEIGHTS[Severity.CRITICAL]
        + summary.high * RISK_WEIGHTS[Severity.HIGH]
        + summary.medium * RISK_WEIGHTS[Severity.MEDIUM]
        + summary.low * RISK_WEIGHTS[Severity.LOW]
    )


def security_score_from_raw_risk(raw_risk: int) -> int:
    """Exponential decay security score."""
    if raw_risk <= 0:
        return 100
    value = 100.0 * math.exp(-raw_risk / RISK_DECAY_SCALE)
    return max(0, min(100, round(value)))
