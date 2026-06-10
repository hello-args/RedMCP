"""Tests for HTML security dashboard reports."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import CapabilityProfile, MCPServerInfo, MCPTool
from mcts.report.data import (
    build_capability_matrix,
    build_dashboard_payload,
    build_technique_map,
    format_location,
    llm_owasp_mappings,
    mcp_owasp_mappings,
    owasp_ids_for_analyzer,
    risk_rating,
    security_grade,
)
from mcts.report.generators.html_report import write_html_report
from mcts.reporting.html import write_html_report as write_via_reporting
from mcts.reporting.models import SourceLocation


def test_live_scan_no_static_tool_notice(example_server_path: Path) -> None:
    from unittest.mock import patch

    from mcts.mcp.models import MCPServerInfo, MCPTool

    live_server = MCPServerInfo(
        name="live",
        tools=[MCPTool(name="t", description="d", input_schema={})],
        discovery_mode="live",
        initialize_succeeded=True,
    )
    with patch.object(Scanner, "run") as mock_run:
        from datetime import UTC, datetime

        from mcts.reporting.models import RiskScore, ScanReport, ScanSummary, ScoreBasis

        mock_run.return_value = ScanReport(
            version="0.0.0",
            target=str(example_server_path),
            scanned_at=datetime.now(UTC),
            server=live_server,
            findings=[],
            summary=ScanSummary(),
            score=RiskScore(
                overall=100,
                risk_index=0,
                raw_risk=0,
                penalty=0,
                basis=ScoreBasis(
                    critical=0, high=0, medium=0, low=0, scorable_total=0, excluded_non_scorable=0
                ),
            ),
            scan_scope="live",
            tool_discovery_notice=None,
        )
        report = mock_run.return_value
    assert report.tool_discovery_notice is None
    assert report.scan_scope == "live"


def test_html_includes_tool_discovery_banner(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('no mcp')\n")
    report = Scanner(ScanConfig(target=tmp_path)).run()
    out = tmp_path / "report.html"
    write_html_report(report, out)
    html = out.read_text(encoding="utf-8")
    assert "tool-discovery-banner" in html
    payload = build_dashboard_payload(report)
    assert payload["tool_discovery"]["show_banner"] is True
    assert payload["meta"].get("tool_discovery_notice")


def test_build_dashboard_payload_from_scan(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    payload = build_dashboard_payload(report)

    assert payload["score"]["overall"] == report.score.overall
    assert payload["summary"]["critical"] == report.summary.critical
    assert len(payload["findings"]) == len(report.findings)
    assert payload["meta"]["tools_discovered"] == len(report.server.tools)
    assert payload["risk"]["badge"] == risk_rating(report.score.overall)[0]
    assert payload["categories"]
    assert len(payload["categories"]) == 7
    assert payload["techniques"]
    assert payload["score"]["grade"]["letter"] == security_grade(report.score.overall)["letter"]
    assert payload["executive_summary"]["paragraphs"]
    assert payload["executive_summary"]["recommended"]
    assert report.analyzers_executed
    assert payload["checks_summary"]["analyzers_run"] == len(payload["analyzers"])
    assert payload["checks_summary"]["analyzers_passed"] > 0
    passed = [a for a in payload["analyzers"] if a["status"] == "passed"]
    assert passed
    assert any(c["passed"] for c in payload["categories"])


def test_findings_payload_location_and_technique_url(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    payload = build_dashboard_payload(report)
    assert payload["findings"]
    for row in payload["findings"]:
        assert "location" in row
        assert "technique_id" in row
        assert "technique_url" in row
        if row["technique_url"]:
            assert row["technique_id"] != "—"
            assert row["technique_url"].startswith("http")


def test_format_location() -> None:
    assert format_location(None) == "—"
    assert format_location(SourceLocation(file="src/server.py", line=42)) == "src/server.py:42"
    assert format_location(SourceLocation(file="README.md")) == "README.md"


def test_mcp_owasp_mappings_from_scan(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    mcp = mcp_owasp_mappings(report.findings)
    assert "categories" in mcp
    assert "gaps" in mcp
    assert "gap_count" in mcp
    assert mcp["has_scorable_findings"] is True
    finding_rows = [c for c in mcp["categories"] if c["status"] == "findings"]
    assert finding_rows
    assert all(c["id"].startswith("MCP") for c in mcp["categories"])


def test_owasp_llm_catalog_matches_compliance_map() -> None:
    from mcts.compliance.checks import OWASP_LLM_ANALYZER_MAP
    from mcts.report.data import OWASP_CATALOG

    catalog_ids = {row[0] for row in OWASP_CATALOG}
    compliance_ids = {label.split()[0] for label in OWASP_LLM_ANALYZER_MAP.values()}
    assert catalog_ids == compliance_ids


def test_owasp_ids_for_analyzer_uses_compliance_map() -> None:
    assert owasp_ids_for_analyzer("supply_chain") == ["LLM05"]
    assert owasp_ids_for_analyzer("runtime_events") == ["LLM09"]


def test_llm_owasp_mappings_includes_gaps(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    llm = llm_owasp_mappings(report.findings)
    assert "categories" in llm
    assert "gaps" in llm
    assert llm["has_scorable_findings"] is True
    statuses = {row["status"] for row in llm["categories"]}
    assert "findings" in statuses or "gap" in statuses


def test_technique_map_full_catalog(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    technique_map = build_technique_map(report.findings)
    assert technique_map["total"] == 79
    assert len(technique_map["techniques"]) == 79
    assert technique_map["detected_count"] + technique_map["clear_count"] == 79


def test_capability_matrix_and_technique_map(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    payload = build_dashboard_payload(report)
    assert "capability_matrix" in payload
    assert "technique_map" in payload
    assert payload["meta"]["scan_scope_label"]
    assert payload["owasp"]["categories"] is not None
    assert payload["technique_map"]["total"] == 79

    matrix = build_capability_matrix(report)
    assert "dimensions" in matrix
    assert len(matrix["dimensions"]) == 5

    technique_map = build_technique_map(report.findings)
    assert technique_map["techniques"]
    assert all("finding_count" in row for row in technique_map["techniques"])


def test_analyzer_results_include_knowledge(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    payload = build_dashboard_payload(report)
    assert payload["analyzers"]
    passed = [a for a in payload["analyzers"] if a["status"] == "passed"]
    assert passed
    row = passed[0]
    assert row.get("summary")
    assert row.get("looks_for")
    assert "passed_note" in row
    assert row["techniques"] is not None
    report = Scanner(ScanConfig(target=example_server_path)).run()
    payload = build_dashboard_payload(report)
    assert payload["findings"]
    row = payload["findings"][0]
    assert "confidence_display" in row
    assert "evidence" in row
    assert "cwe_id" in row


def test_capability_matrix_with_tools() -> None:
    from datetime import UTC, datetime

    from mcts.reporting.models import RiskScore, ScanReport, ScanSummary, ScoreBasis

    tool = MCPTool(
        name="run_shell",
        description="Execute shell",
        capability=CapabilityProfile(executes_commands=True, egresses_network=True),
    )
    report = ScanReport(
        version="0.0.0",
        target="server.py",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(name="demo", tools=[tool]),
        findings=[],
        summary=ScanSummary(),
        score=RiskScore(
            overall=100,
            risk_index=0,
            raw_risk=0,
            penalty=0,
            basis=ScoreBasis(
                critical=0,
                high=0,
                medium=0,
                low=0,
                scorable_total=0,
                excluded_non_scorable=0,
            ),
        ),
    )
    matrix = build_capability_matrix(report)
    assert matrix["tools"][0]["flags"]["executes_commands"] is True


def test_reporting_module_delegates_to_dashboard(example_server_path: Path, tmp_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    out = tmp_path / "via-reporting.html"
    write_via_reporting(report, out)
    html = out.read_text(encoding="utf-8")
    assert "Risk Score Breakdown" in html
    assert "owasp-mcp-grid" in html
    assert "Location</th>" in html
    assert "Technique</th>" in html
    assert "CWE</th>" in html
    assert "technique-grid" in html
    assert "technique-toolbar" in html
    assert "capability-matrix" in html
    assert "meta-scope" in html


def test_write_html_report_is_self_contained(example_server_path: Path, tmp_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    out = tmp_path / "report.html"
    write_html_report(report, out)

    html = out.read_text(encoding="utf-8")
    assert "MCTS Security Report" in html
    assert "data:image/png;base64," in html
    assert 'alt="MCTS logo"' in html
    assert "&#34;use strict&#34;" not in html
    assert '"use strict"' in html
    assert "Security Posture Summary" in html
    assert "score-info" in html
    assert "Score derived from:" in html
    assert "Security score over time" in html
    assert "trend-chart-wrap" in html
    assert "trend-table-wrap" in html
    assert "not a percentage" in html
    assert "exec-summary-grid" in html
    assert "Scores vs counts" in html
    assert "not a percentage" in html.lower()
    assert "Security Score" in html
    assert "issues-table" in html
    assert "Key results" in html
    assert "chart.js" in html
    assert "Inter" in html
    assert 'id="mcts-report-data"' in html
    assert str(report.score.overall) in html
    assert "checks-summary-row" in html
    assert "analyzer-passed-grid" in html
    assert "Passed Checks" in html
    assert "How to read this report" in html
    assert "data-card-action" in html
    assert 'data-card-action="goto:overview"' in html
    assert "focus-analyzer" in html
    assert "analyzer-modal" in html
    assert "Learn more" not in html
    assert "card-interactive" in html
    assert "Issues to Fix" in html
    assert "overview-split" in html
    assert "fonts.googleapis.com" not in html
    assert "cdn.jsdelivr.net" not in html
    assert "typeof Chart" in html or "Chart.register" in html or "Chart(" in html

    start = html.index('id="mcts-report-data">') + len('id="mcts-report-data">')
    end = html.index("</script>", start)
    embedded = json.loads(html[start:end])
    assert embedded["score"]["overall"] == report.score.overall
    assert embedded["checks_summary"]["analyzers_passed"] > 0
    assert any(a["status"] == "passed" for a in embedded["analyzers"])
    assert "owasp_mcp" in embedded
    assert embedded["technique_map"]["total"] == 79
    assert embedded["findings"][0]["location"] is not None or embedded["findings"][0]["location"] == "—"


def test_legacy_string_input_schema_report_loads(tmp_path: Path) -> None:
    """Older scan JSON stored input_schema as a string; mcts report must still load."""
    from mcts.reporting.models import ScanReport

    legacy = {
        "version": "0.1.0",
        "target": "server.py",
        "scanned_at": "2026-06-04T10:01:38.400766Z",
        "server": {
            "name": "server",
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file.",
                    "input_schema": "{}",
                }
            ],
        },
        "findings": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        "score": {
            "overall": 100,
            "risk_index": 0,
            "raw_risk": 0,
            "penalty": 0,
            "basis": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "scorable_total": 0,
                "excluded_non_scorable": 0,
            },
        },
    }
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")

    report = ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
    assert report.server.tools[0].input_schema == {}

    out = tmp_path / "legacy.html"
    write_via_reporting(report, out)
    assert "MCTS Security Report" in out.read_text(encoding="utf-8")
