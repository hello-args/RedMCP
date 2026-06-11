"""Tests for unified -o / --no-progress flags on CLI subcommands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from mcts.cli.main import app
from mcts.output.analysis_dir import ANALYSIS_DIR_NAME

runner = CliRunner()


def test_doctor_accepts_output_flag(tmp_path: Path) -> None:
    output = tmp_path / "doctor.json"
    result = runner.invoke(app, ["doctor", str(tmp_path), "-o", str(output)])

    assert result.exit_code == 0, result.stdout
    assert output.is_file()
    assert '"checks"' in output.read_text(encoding="utf-8")


def test_readiness_accepts_no_progress(tmp_path: Path) -> None:
    result = runner.invoke(app, ["readiness", str(tmp_path), "--no-progress"])

    assert result.exit_code in {0, 1}
    assert "No such option" not in result.stdout


def test_fuzz_accepts_no_progress_flag() -> None:
    result = runner.invoke(
        app,
        ["fuzz", ".", "--i-understand-live-risk", "--no-progress"],
    )

    assert "No such option: --no-progress" not in result.stdout


def test_scan_mcp_accepts_no_progress_flag() -> None:
    result = runner.invoke(app, ["scan-mcp", "--no-progress", "https://example.com/mcp"])

    assert "No such option: --no-progress" not in result.stdout


def test_scan_prompts_output_and_no_progress(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "repo"
    target.mkdir()
    (target / "notes.md").write_text("Instructions for testing.\n", encoding="utf-8")
    output = tmp_path / "prompts.json"

    result = runner.invoke(
        app,
        ["scan-prompts", str(target), "-o", str(output), "--no-progress"],
    )

    assert result.exit_code == 0, result.stdout
    assert output.is_file()
    assert (tmp_path / ANALYSIS_DIR_NAME / "prompts.json").is_file() or output.is_file()
