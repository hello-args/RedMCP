"""Tests for MCP config cwd and interpreter resolution."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.discovery.config import load_server_from_config, resolve_interpreter


def test_load_config_sets_cwd(tmp_path: Path) -> None:
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"s": {"command": "python", "args": []}}}))
    live = load_server_from_config(cfg, "s")
    assert live.cwd == str(tmp_path.resolve())


def test_resolves_venv_python(tmp_path: Path) -> None:
    venv_python = tmp_path / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("#!/bin/sh\necho ok\n")
    venv_python.chmod(0o755)
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"s": {"command": "python", "args": ["-m", "app"]}}}))
    live = load_server_from_config(cfg, "s")
    assert live.command == str(venv_python.resolve())
    assert live.cwd == str(tmp_path.resolve())


def test_resolve_interpreter_relative_path(tmp_path: Path) -> None:
    rel = tmp_path / ".venv" / "bin" / "python3.12"
    rel.parent.mkdir(parents=True)
    rel.write_text("#!/bin/sh\n")
    rel.chmod(0o755)
    command, warn = resolve_interpreter(".venv/bin/python3.12", tmp_path)
    assert warn is None
    assert command == str(rel.resolve())


def test_bare_python_warns_without_venv(tmp_path: Path) -> None:
    command, warn = resolve_interpreter("python", tmp_path)
    assert command == "python"
    assert warn is not None
    assert ".venv" in warn
