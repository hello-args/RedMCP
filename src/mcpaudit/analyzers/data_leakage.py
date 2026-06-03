"""Sensitive data leakage detection."""

from __future__ import annotations

import re

from mcpaudit.analyzers.base import BaseAnalyzer
from mcpaudit.mcp.models import MCPServerInfo
from mcpaudit.reporting.models import Finding, Severity

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}"), Severity.CRITICAL),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    (
        "Generic Secret Assignment",
        re.compile(r"(?i)(api_key|secret|password|token)\s*=\s*\S+"),
        Severity.HIGH,
    ),
    ("Database URL", re.compile(r"(?i)(postgres|mysql|mongodb)://\S+"), Severity.HIGH),
    (
        "Internal URL",
        re.compile(r"https?://(?:localhost|127\.0\.0\.1|internal|\.local)\S*"),
        Severity.MEDIUM,
    ),
]

SECRET_ENV_VARS = (
    "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL",
    "GITHUB_TOKEN",
    "ANTHROPIC_API_KEY",
)


class DataLeakageAnalyzer(BaseAnalyzer):
    """Scans tool metadata and static hints for exposed secrets."""

    name = "data_leakage"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        corpus = " ".join(f"{tool.name} {tool.description} {tool.input_schema}" for tool in server.tools)

        for label, pattern, severity in SECRET_PATTERNS:
            if pattern.search(corpus):
                findings.append(
                    Finding(
                        id=f"leak-{label.lower().replace(' ', '-')}",
                        analyzer=self.name,
                        title=f"Potential {label} exposure",
                        description=f"Pattern matching {label} found in server metadata.",
                        severity=severity,
                        recommendation="Remove secrets from tool definitions; use secure secret stores.",
                        evidence={"pattern": pattern.pattern},
                    )
                )

        for env_var in SECRET_ENV_VARS:
            if env_var in corpus:
                findings.append(
                    Finding(
                        id=f"leak-env-{env_var.lower()}",
                        analyzer=self.name,
                        title=f"Referenced sensitive env var: {env_var}",
                        description="Tool metadata references environment variables that may leak.",
                        severity=Severity.MEDIUM,
                        recommendation=f"Avoid exposing {env_var} through tool responses.",
                        evidence={"env_var": env_var},
                    )
                )

        return findings
