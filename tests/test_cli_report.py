"""Tests for mcts report CLI validation."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from mcts.cli.main import app
from mcts.reporting.models import Finding, RiskScore, ScanReport, ScanSummary, ScoreBasis, Severity

runner = CliRunner()


def _minimal_report() -> ScanReport:
    from datetime import UTC, datetime

    from mcts.mcp.models import MCPServerInfo

    return ScanReport(
        version="0.0.0",
        target="server.py",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(name="demo"),
        findings=[
            Finding(
                id="f1",
                analyzer="prompt_injection",
                title="test",
                description="d",
                severity=Severity.LOW,
                recommendation="r",
            )
        ],
        summary=ScanSummary(low=1, total=1),
        score=RiskScore(
            overall=95,
            risk_index=5,
            raw_risk=5,
            penalty=5,
            basis=ScoreBasis(
                critical=0,
                high=0,
                medium=0,
                low=1,
                scorable_total=1,
                excluded_non_scorable=0,
            ),
        ),
    )


def test_report_rejects_directory(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", str(tmp_path), "-o", str(tmp_path / "out.html")])
    assert result.exit_code == 2
    assert "not a directory" in result.stdout or "JSON file" in result.stdout


def test_report_missing_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "nope.json"
    result = runner.invoke(app, ["report", str(missing)])
    assert result.exit_code == 2
    assert "not found" in result.stdout.lower()


def test_report_valid_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(_minimal_report().model_dump_json())
    out = tmp_path / "out.html"
    result = runner.invoke(app, ["report", str(report_path), "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
