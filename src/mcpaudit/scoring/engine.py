"""Risk scoring engine."""

from __future__ import annotations

from mcpaudit.reporting.models import Finding, RiskScore, Severity

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
}


class RiskScoringEngine:
    """Computes an overall security score inspired by CVSS and OWASP risk rating."""

    def score(self, findings: list[Finding]) -> RiskScore:
        penalty = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
        overall = max(0, 100 - penalty)
        return RiskScore(overall=overall, penalty=penalty)
