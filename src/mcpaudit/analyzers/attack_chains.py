"""Multi-step attack chain detection."""

from __future__ import annotations

from mcpaudit.analyzers.base import BaseAnalyzer
from mcpaudit.mcp.models import MCPServerInfo, MCPTool
from mcpaudit.reporting.models import Finding, Severity

READ_HINTS = ("read", "fetch", "get", "list", "email", "query")
EXFIL_HINTS = ("send", "post", "upload", "webhook", "http", "export")
CREDENTIAL_HINTS = ("password", "token", "credential", "secret", "key", "auth")


class AttackChainAnalyzer(BaseAnalyzer):
    """Identifies dangerous combinations of tools that enable attack chains."""

    name = "attack_chains"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        read_tools = [t for t in server.tools if self._matches(t, READ_HINTS)]
        exfil_tools = [t for t in server.tools if self._matches(t, EXFIL_HINTS)]
        cred_tools = [t for t in server.tools if self._matches(t, CREDENTIAL_HINTS)]

        findings: list[Finding] = []

        if read_tools and exfil_tools:
            findings.append(
                Finding(
                    id="chain-read-exfil",
                    analyzer=self.name,
                    title="Read → exfiltration attack chain possible",
                    description="Tools exist to read data and send it externally.",
                    severity=Severity.CRITICAL,
                    recommendation="Isolate read and egress tools; require approval for outbound actions.",
                    evidence={
                        "read_tools": [t.name for t in read_tools],
                        "exfil_tools": [t.name for t in exfil_tools],
                    },
                )
            )

        if read_tools and cred_tools and exfil_tools:
            findings.append(
                Finding(
                    id="chain-credential-theft",
                    analyzer=self.name,
                    title="Credential theft chain possible",
                    description="Read + credential + egress tools enable multi-step credential exfiltration.",
                    severity=Severity.CRITICAL,
                    recommendation="Block credential tools from agent access or add step-up auth.",
                    evidence={
                        "read_tools": [t.name for t in read_tools],
                        "credential_tools": [t.name for t in cred_tools],
                        "exfil_tools": [t.name for t in exfil_tools],
                    },
                )
            )

        return findings

    def _matches(self, tool: MCPTool, hints: tuple[str, ...]) -> bool:
        haystack = f"{tool.name} {tool.description}".lower()
        return any(hint in haystack for hint in hints)
