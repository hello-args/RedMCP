"""Production readiness heuristics for MCP tools (non-security)."""

from __future__ import annotations

from dataclasses import dataclass

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPTool
from mcts.readiness.heuristics import check_tool_readiness, readiness_score
from mcts.readiness.llm_judge import ReadinessLlmJudge
from mcts.readiness.opa import OpaProvider
from mcts.reporting.models import Finding, Severity


@dataclass
class ReadinessReport:
    target: str
    findings: list[Finding]
    tools_checked: int
    readiness_score: int
    production_ready: bool


def run_readiness(config: ScanConfig) -> ReadinessReport:
    server = Scanner(config).client.discover()
    opa = OpaProvider(policies_dir=config.readiness_opa_policies) if config.readiness_opa else None
    llm = ReadinessLlmJudge(model=config.readiness_llm_model) if config.readiness_llm else None
    findings: list[Finding] = []

    for tool in server.tools:
        tool_def = _tool_def(tool)
        findings.extend(check_tool_readiness(tool))
        if opa and opa.is_available():
            findings.extend(opa.evaluate_tool(tool_def, tool.name))
        if llm and llm.is_available():
            findings.extend(llm.analyze_tool(tool_def, tool.name))

    if not server.tools:
        findings.append(
            Finding(
                id="readiness-no-tools-discovered",
                analyzer="readiness",
                title="No MCP tools discovered",
                description=(
                    "Readiness checks apply to MCP tools, but discovery found zero tools. "
                    "Agent repos with only SKILL.md or prompt markdown need a discoverable MCP "
                    "entrypoint, or use live/snapshot discovery before running readiness."
                ),
                severity=Severity.HIGH,
                recommendation=(
                    "Point readiness at an MCP server entrypoint, run static discovery on tool "
                    "sources, or export tools via mcts snapshot for offline scans."
                ),
                technique_id=None,
                confidence=0.9,
                evidence={"readiness_rule": "HEUR-000", "tools_discovered": 0},
            )
        )

    if not server.version or server.version == "0.0.0":
        findings.append(
            Finding(
                id="readiness-server-version",
                analyzer="readiness",
                title="Server version not specified",
                description="MCP server does not expose a meaningful version string.",
                severity=Severity.LOW,
                recommendation="Set server version for operational traceability.",
                technique_id=None,
                confidence=0.6,
                evidence={"readiness_rule": "HEUR-014"},
            )
        )

    score = readiness_score(findings)
    production_ready = (
        bool(server.tools) and score >= 70 and not any(f.severity == Severity.CRITICAL for f in findings)
    )
    for finding in findings:
        finding.evidence.setdefault("readiness_score", score)
        finding.evidence.setdefault("production_ready", production_ready)

    return ReadinessReport(
        target=str(config.target),
        findings=findings,
        tools_checked=len(server.tools),
        readiness_score=score,
        production_ready=production_ready,
    )


def _tool_def(tool: MCPTool) -> dict:
    return {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    }
