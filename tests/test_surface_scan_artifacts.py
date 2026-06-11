"""Tests for surface scan subcommand artifact paths."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from mcts.cli.main import app
from mcts.output.analysis_dir import ANALYSIS_DIR_NAME

runner = CliRunner()


def test_surface_scans_write_distinct_html_and_sarif(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "repo"
    target.mkdir()
    (target / "notes.md").write_text("Agent instructions for testing.\n", encoding="utf-8")

    prompts = runner.invoke(app, ["scan-prompts", str(target)])
    resources = runner.invoke(app, ["scan-resources", str(target)])
    instructions = runner.invoke(app, ["scan-instructions", str(target)])

    assert prompts.exit_code == 0, prompts.stdout
    assert resources.exit_code == 0, resources.stdout
    assert instructions.exit_code == 0, instructions.stdout

    analysis_dir = tmp_path / ANALYSIS_DIR_NAME
    expected = (
        "scan-prompts-report.json",
        "scan-prompts-report.html",
        "scan-prompts-report.sarif",
        "scan-resources-report.json",
        "scan-resources-report.html",
        "scan-resources-report.sarif",
        "scan-instructions-report.json",
        "scan-instructions-report.html",
        "scan-instructions-report.sarif",
    )
    for name in expected:
        path = analysis_dir / name
        assert path.is_file(), f"missing artifact: {name}"

    prompts_html = (analysis_dir / "scan-prompts-report.html").read_text(encoding="utf-8")
    resources_html = (analysis_dir / "scan-resources-report.html").read_text(encoding="utf-8")
    assert prompts_html != resources_html
