"""Tests for mcts_analysis/ default output directory."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcts.cli.main import app
from mcts.output.analysis_dir import ANALYSIS_DIR_NAME, analysis_path, resolve_output_path

runner = CliRunner()


def test_resolve_output_path_defaults_to_analysis_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    path = resolve_output_path(None, "scan-report.json")
    assert path == tmp_path / ANALYSIS_DIR_NAME / "scan-report.json"


def test_resolve_output_path_relative_goes_under_analysis_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    path = resolve_output_path(Path("custom.json"), "scan-report.json")
    assert path == tmp_path / ANALYSIS_DIR_NAME / "custom.json"


def test_resolve_output_path_absolute_is_preserved(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    absolute = tmp_path / "elsewhere" / "out.json"
    path = resolve_output_path(absolute, "scan-report.json")
    assert path == absolute


def test_resolve_report_input_path_falls_back_to_analysis_dir(tmp_path: Path, monkeypatch) -> None:
    from mcts.output.analysis_dir import resolve_report_input_path

    monkeypatch.chdir(tmp_path)
    analysis = tmp_path / ANALYSIS_DIR_NAME
    analysis.mkdir()
    report_json = analysis / "report.json"
    report_json.write_text("{}", encoding="utf-8")

    resolved = resolve_report_input_path(Path("report.json"))
    assert resolved == report_json.resolve()


def test_report_cli_resolves_mcts_analysis_json(tmp_path: Path, monkeypatch) -> None:
    from datetime import UTC, datetime

    from mcts.mcp.models import MCPServerInfo
    from mcts.reporting.models import RiskScore, ScanReport, ScanSummary, ScoreBasis

    monkeypatch.chdir(tmp_path)
    report = ScanReport(
        version="0.0.0",
        target="server.py",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(name="demo"),
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
    json_path = analysis_path("report.json")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(report.model_dump_json(), encoding="utf-8")

    result = runner.invoke(app, ["report", "report.json"])
    assert result.exit_code == 0, result.stdout
    assert "Resolved report.json" in result.stdout or "report.json" in result.stdout


def test_scan_writes_default_artifacts(
    example_server_path: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["scan", str(example_server_path), "--no-progress"],
    )
    assert result.exit_code in (0, 1), result.stdout
    analysis = tmp_path / ANALYSIS_DIR_NAME
    assert (analysis / "scan-report.json").exists()
    assert (analysis / "scan-report.html").exists()
    assert (analysis / "scan-report.sarif").exists()
    assert (analysis / "history.json").exists()
    payload = json.loads((analysis / "scan-report.json").read_text(encoding="utf-8"))
    assert payload["target"]
    assert len(payload.get("scan_history", [])) >= 1


def test_scan_no_save_skips_artifacts(
    example_server_path: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["scan", str(example_server_path), "--no-progress", "--no-save"],
    )
    assert result.exit_code in (0, 1), result.stdout
    assert not (tmp_path / ANALYSIS_DIR_NAME).exists()


def test_report_defaults_to_analysis_dir(tmp_path: Path, monkeypatch) -> None:
    from datetime import UTC, datetime

    from mcts.mcp.models import MCPServerInfo
    from mcts.reporting.models import RiskScore, ScanReport, ScanSummary, ScoreBasis

    monkeypatch.chdir(tmp_path)
    report = ScanReport(
        version="0.0.0",
        target="server.py",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(name="demo"),
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
    json_path = analysis_path("scan-report.json")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(report.model_dump_json(), encoding="utf-8")

    result = runner.invoke(app, ["report", str(json_path)])
    assert result.exit_code == 0, result.stdout
    assert (tmp_path / ANALYSIS_DIR_NAME / "report.html").exists()
    assert (tmp_path / ANALYSIS_DIR_NAME / "scan-report.sarif").exists()


def test_scan_history_builds_trend_chart(
    example_server_path: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    for _ in range(2):
        result = runner.invoke(
            app,
            ["scan", str(example_server_path), "--no-progress"],
        )
        assert result.exit_code in (0, 1), result.stdout

    html = (tmp_path / ANALYSIS_DIR_NAME / "scan-report.html").read_text(encoding="utf-8")
    start = html.index('id="mcts-report-data">') + len('id="mcts-report-data">')
    end = html.index("</script>", start)
    payload = json.loads(html[start:end])
    assert len(payload["trend"]) >= 2
    assert payload.get("trend_meta", {}).get("runs", 0) >= 2
    assert "trend-chart-wrap" in html
    assert "trend-sparkline" in html
    assert "trend-table-wrap" in html

    history = json.loads((tmp_path / ANALYSIS_DIR_NAME / "history.json").read_text(encoding="utf-8"))
    assert len(history["runs"]) >= 2
