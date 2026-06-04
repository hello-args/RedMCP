"""Tests for HTML security dashboard reports."""

from __future__ import annotations

import json
from pathlib import Path

from mcpaudit.core.config import ScanConfig
from mcpaudit.core.scanner import Scanner
from mcpaudit.report.data import build_dashboard_payload, risk_rating, security_grade
from mcpaudit.report.generators.html_report import write_html_report
from mcpaudit.reporting.html import write_html_report as write_via_reporting


def test_build_dashboard_payload_from_scan(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    payload = build_dashboard_payload(report)

    assert payload["score"]["overall"] == report.score.overall
    assert payload["summary"]["critical"] == report.summary.critical
    assert len(payload["findings"]) == len(report.findings)
    assert payload["meta"]["tools_discovered"] == len(report.server.tools)
    assert payload["risk"]["badge"] == risk_rating(report.score.overall)[0]
    assert payload["categories"]
    assert len(payload["categories"]) == 5
    assert payload["score"]["grade"]["letter"] == security_grade(report.score.overall)["letter"]
    assert payload["executive_summary"]["paragraphs"]
    assert payload["executive_summary"]["recommended"]


def test_write_html_report_is_self_contained(example_server_path: Path, tmp_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    out = tmp_path / "report.html"
    write_html_report(report, out)

    html = out.read_text(encoding="utf-8")
    assert "MCPAudit Security Report" in html
    assert "data:image/png;base64," in html
    assert 'alt="MCPAudit logo"' in html
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
    assert 'id="mcpaudit-report-data"' in html
    assert "Overall Risk Score" in html
    assert str(report.score.overall) in html

    start = html.index('id="mcpaudit-report-data">') + len('id="mcpaudit-report-data">')
    end = html.index("</script>", start)
    embedded = json.loads(html[start:end])
    assert embedded["score"]["overall"] == report.score.overall


def test_reporting_module_delegates_to_dashboard(example_server_path: Path, tmp_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    out = tmp_path / "via-reporting.html"
    write_via_reporting(report, out)
    assert "Risk Score Breakdown" in out.read_text(encoding="utf-8")
