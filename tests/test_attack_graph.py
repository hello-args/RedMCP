"""Tests for attack graph generation."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.report.data import build_attack_graph


def test_attack_graph_uses_capability_edges(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    graph = build_attack_graph(report)

    assert graph["edges"]
    labels = {edge["label"] for edge in graph["edges"]}
    assert any("exfil" in label or "exec" in label or "chain" in label for label in labels)

    # No synthetic "related" fallback edges
    assert not any(edge["label"] == "related" for edge in graph["edges"])


def test_attack_graph_empty_when_no_chains() -> None:
    from mcts.mcp.models import MCPServerInfo, MCPTool
    from mcts.reporting.models import RiskScore, ScanReport, ScanSummary, ScoreBasis

    report = ScanReport(
        version="0.0.0",
        target="test",
        scanned_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        server=MCPServerInfo(
            tools=[
                MCPTool(name="safe_list", description="List items only"),
            ]
        ),
        findings=[],
        summary=ScanSummary(),
        score=RiskScore(
            overall=100,
            risk_index=0,
            raw_risk=0,
            penalty=0,
            basis=ScoreBasis(critical=0, high=0, medium=0, low=0, scorable_total=0, excluded_non_scorable=0),
        ),
        attack_graph={"nodes": [], "edges": []},
    )
    graph = build_attack_graph(report)
    assert graph["edges"] == []
