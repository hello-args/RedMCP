"""Phase 3 runtime evidence validation tests."""

from __future__ import annotations

from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity
from mcts.reporting.runtime_evidence import validate_runtime_evidence
from mcts.reporting.trust_pipeline import apply_trust_layer, build_trust_context


def test_validate_runtime_evidence_tags_taint_flow() -> None:
    tool = MCPTool(
        name="run_cmd",
        description="Run a command",
        handler_snippet="import subprocess\ndef run_cmd(cmd):\n    subprocess.call(cmd, shell=True)",
        source_file="server.py",
    )
    findings = BehavioralStaticAnalyzer().analyze(MCPServerInfo(tools=[tool], source_files={}))
    taint_rows = [f for f in findings if f.id.startswith("behavioral-taint")]
    assert taint_rows
    validated = validate_runtime_evidence(taint_rows)[0]
    assert validated.evidence.get("runtime_validation") == "taint_param_sink"
    assert validated.finding_type == "validated"
    assert validated.evidence.get("facts")


def test_trust_pipeline_applies_runtime_validation() -> None:
    finding = Finding(
        id="behavioral-taint-demo-subprocess",
        analyzer="behavioral_static",
        title="Untrusted input may reach sink on demo",
        description="Handler parameters ['cmd'] may flow to security-sensitive calls: subprocess",
        severity=Severity.HIGH,
        recommendation="Validate inputs",
        evidence={
            "facts": [
                {
                    "rule_id": "RULE_TAINT_PARAM_SINK",
                    "match": "subprocess",
                    "field": "handler_body",
                    "tool": "demo",
                    "snippet": "subprocess.call(cmd)",
                }
            ],
            "sinks": ["subprocess"],
            "tainted_params": ["cmd"],
        },
    )
    ctx = build_trust_context(mode="enforce", scan_scope="repository")
    out = apply_trust_layer([finding], ctx)[0]
    assert out.evidence.get("runtime_validation") == "taint_param_sink"
    assert out.evidence.get("evidence_tier") == "silver"


def test_collapse_template_severity_on_single_tool_fixture() -> None:
    collapsed = Scanner(
        ScanConfig(
            target="examples/single-tool-agent-server/server.py",
            findings_trust_mode="enforce",
            collapse_template_severity=True,
        )
    ).run()
    chains = [f for f in collapsed.findings if f.analyzer == "attack_chains"]
    assert chains
    assert chains[0].severity == Severity.MEDIUM
    assert chains[0].display_severity == Severity.MEDIUM
    assert collapsed.summary.critical == 0

    raw = Scanner(
        ScanConfig(
            target="examples/single-tool-agent-server/server.py",
            findings_trust_mode="enforce",
            collapse_template_severity=False,
        )
    ).run()
    raw_chains = [f for f in raw.findings if f.analyzer == "attack_chains"]
    assert raw_chains[0].severity == Severity.CRITICAL
    assert raw_chains[0].display_severity == Severity.MEDIUM
    assert raw.summary.critical >= 1
