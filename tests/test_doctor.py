"""Tests for mcts doctor command."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcts.cli.main import app

runner = CliRunner()


def test_doctor_warns_bare_python_without_venv(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"local": {"command": "python", "args": []}}}))
    result = runner.invoke(app, ["doctor", str(tmp_path)])
    assert result.exit_code == 0
    assert "interpreter" in result.stdout.lower() or "python" in result.stdout.lower()


def test_doctor_finds_config_and_entrypoint(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"local": {"command": "python", "args": ["-m", "app"]}}}))
    bridge = tmp_path / "ifd" / "mcp" / "bridge.py"
    bridge.parent.mkdir(parents=True)
    bridge.write_text("from mcp.server import Server\nFastMCP()\n@tool\ndef t(): pass\n")
    result = runner.invoke(app, ["doctor", str(tmp_path)])
    assert result.exit_code == 0
    assert ".mcp.json" in result.stdout
    assert "bridge.py" in result.stdout
