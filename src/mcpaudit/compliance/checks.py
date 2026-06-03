"""Compliance checks against security standards."""

from __future__ import annotations

from mcpaudit.reporting.models import Finding, Severity

OWASP_LLM_CONTROLS = [
    "LLM01 Prompt Injection",
    "LLM02 Sensitive Information Disclosure",
    "LLM06 Excessive Agency",
    "LLM08 Vector and Embedding Weaknesses",
]


class ComplianceChecker:
    """Maps findings to OWASP LLM Top 10 and MCP best-practice controls."""

    def check(self, findings: list[Finding]) -> list[Finding]:
        compliance_findings: list[Finding] = []
        analyzers_present = {f.analyzer for f in findings}

        if "prompt_injection" not in analyzers_present:
            compliance_findings.append(
                Finding(
                    id="compliance-llm01-untested",
                    analyzer="compliance",
                    title="Prompt injection testing incomplete",
                    description="No prompt injection findings recorded; verify live probing is enabled.",
                    severity=Severity.LOW,
                    recommendation="Enable dynamic prompt injection simulation in CI.",
                )
            )

        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        if critical_count > 0:
            compliance_findings.append(
                Finding(
                    id="compliance-critical-gate",
                    analyzer="compliance",
                    title="Quality gate failed: critical findings present",
                    description="Deployment should be blocked when critical findings exist.",
                    severity=Severity.CRITICAL,
                    recommendation="Resolve all critical findings before production deployment.",
                    evidence={"critical_count": critical_count},
                )
            )

        return compliance_findings
