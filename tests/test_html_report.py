"""Tests for HTML security dashboard reports."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.report.data import build_dashboard_payload, risk_rating, security_grade
from mcts.report.generators.html_report import write_html_report
from mcts.reporting.html import write_html_report as write_via_reporting


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


def test_write_html_report_is_self_contained(example_server_path: Path, tmp_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    out = tmp_path / "report.html"
    write_html_report(report, out)

    html = out.read_text(encoding="utf-8")
    assert "MCTS Security Report" in html
    assert "data:image/svg+xml;base64," in html
    assert 'alt="MCTS logo"' in html
    assert "&#34;use strict&#34;" not in html
    assert '"use strict"' in html
    assert "Security Posture Summary" in html
    assert "score-info" in html
    assert "Score derived from:" in html
    assert "No Historical Data" in html
    assert "exec-summary-grid" in html
    assert "severity-card--critical" in html
    assert "chart.js" in html
    assert "Inter" in html
    assert 'id="mcts-report-data"' in html
    assert "Overall Risk Score" in html
    assert str(report.score.overall) in html

    start = html.index('id="mcts-report-data">') + len('id="mcts-report-data">')
    end = html.index("</script>", start)
    embedded = json.loads(html[start:end])
    assert embedded["score"]["overall"] == report.score.overall


def test_reporting_module_delegates_to_dashboard(example_server_path: Path, tmp_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    out = tmp_path / "via-reporting.html"
    write_via_reporting(report, out)
    assert "Risk Score Breakdown" in out.read_text(encoding="utf-8")


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
