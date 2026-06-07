"""Tests for SARIF reporting and CI gates."""

import json
from pathlib import Path

from typer.testing import CliRunner

from mcts.cli.main import app
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.reporting.sarif import build_sarif, write_sarif_report

runner = CliRunner()


def test_sarif_report_structure(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    sarif = build_sarif(report)

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "MCTS"
    assert len(sarif["runs"][0]["results"]) == len(report.findings)
    assert sarif["runs"][0]["properties"]["securityScore"] == report.score.overall
    assert "taxa" not in sarif["runs"][0]
    for result in sarif["runs"][0]["results"]:
        for taxon in result.get("taxa", []):
            assert isinstance(taxon, dict)


def test_write_sarif_report_is_valid_json(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    payload = write_sarif_report(report)
    parsed = json.loads(payload)
    assert parsed["runs"][0]["results"]


def test_cli_sarif_output(example_server_path: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.sarif"
    result = runner.invoke(
        app,
        [
            "scan",
            str(example_server_path),
            "--output",
            str(out),
            "--format",
            "sarif",
            "--no-progress",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"


def test_min_score_gate_fails(example_server_path: Path) -> None:
    result = runner.invoke(
        app,
        ["scan", str(example_server_path), "--min-score", "99", "--no-progress"],
    )
    assert result.exit_code == 1


def test_min_score_gate_passes_on_safe_server() -> None:
    safe = Path(__file__).parent.parent / "examples" / "safe-mcp-server" / "server.py"
    result = runner.invoke(
        app,
        ["scan", str(safe), "--min-score", "90", "--no-progress"],
    )
    assert result.exit_code == 0, result.output
