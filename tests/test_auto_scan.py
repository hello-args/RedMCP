"""Tests for mcts scan --auto resolution."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcts.cli.auto import AutoScanError, resolve_auto_scan
from mcts.cli.main import app
from mcts.core.config import ScanConfig

runner = CliRunner()


def test_auto_picks_single_entrypoint(tmp_path: Path) -> None:
    bridge = tmp_path / "bridge.py"
    bridge.write_text("FastMCP\n@tool\ndef x(): pass\n")
    base = ScanConfig(target=tmp_path)
    resolved = resolve_auto_scan(tmp_path, base)
    assert resolved.target == bridge


def test_auto_multiple_servers_requires_flag(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "a": {"command": "python"},
                    "b": {"command": "python"},
                }
            }
        )
    )
    base = ScanConfig(target=tmp_path)
    with pytest.raises(AutoScanError) as exc:
        resolve_auto_scan(tmp_path, base)
    assert exc.value.multiple_servers == ["a", "b"]


def test_auto_server_flag(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"a": {"command": "python"}, "b": {"command": "python"}}}))
    base = ScanConfig(target=tmp_path, auto=True)
    resolved = resolve_auto_scan(tmp_path, base, auto_server="b")
    assert resolved.config_server == "b"


def test_scan_dot_literal_argument(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hello')\n")
    import os

    prev = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(app, ["scan", ".", "--no-progress", "--no-save"])
    finally:
        os.chdir(prev)
    assert result.exit_code in (0, 1)


def test_scan_dot_allowed_without_config(tmp_path: Path) -> None:
    server = tmp_path / "server.py"
    server.write_text("print('not mcp')\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-progress", "--no-save"])
    assert result.exit_code in (0, 1)
