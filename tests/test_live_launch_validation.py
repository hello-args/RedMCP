"""CLI tests for live launch validation ordering (config before consent)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from mcts.cli.main import app

runner = CliRunner()


def test_snapshot_config_error_before_consent(tmp_path: Path) -> None:
    result = runner.invoke(app, ["snapshot", str(tmp_path), "--config", "mcp.json"])
    assert result.exit_code == 2
    assert "--config requires --server" in result.output
    assert "live consent" not in result.output.lower()


def test_snapshot_missing_launch_before_consent(tmp_path: Path) -> None:
    result = runner.invoke(app, ["snapshot", str(tmp_path)])
    assert result.exit_code == 2
    assert "Live scan requires" in result.output
    assert "live consent" not in result.output.lower()


def test_snapshot_consent_required_after_valid_launch(tmp_path: Path) -> None:
    server_py = tmp_path / "server.py"
    server_py.write_text("print('stub')\n", encoding="utf-8")
    result = runner.invoke(app, ["snapshot", str(server_py)])
    assert result.exit_code == 2
    assert "live consent" in result.output.lower()


def test_fuzz_config_error_before_consent(tmp_path: Path) -> None:
    result = runner.invoke(app, ["fuzz", str(tmp_path), "--config", "mcp.json"])
    assert result.exit_code == 2
    assert "--config requires --server" in result.output
    assert "live consent" not in result.output.lower()


def test_fuzz_missing_launch_before_consent(tmp_path: Path) -> None:
    result = runner.invoke(app, ["fuzz", str(tmp_path)])
    assert result.exit_code == 2
    assert "Live scan requires" in result.output
    assert "live consent" not in result.output.lower()
