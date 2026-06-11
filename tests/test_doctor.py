"""Tests for mcts doctor command."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

import mcts.cli.doctor as doctor_module
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


def test_doctor_deep_missing_optional_tools_show_warnings(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(doctor_module.importlib_util, "find_spec", lambda _module: None)
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _executable: None)
    monkeypatch.delenv("MCTS_LLM_API_KEY", raising=False)

    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0
    assert "[mcp] extra: module 'mcp' not found" in result.stdout
    assert "[api] extra: module 'fastapi' not found" in result.stdout
    assert "semgrep CLI: not found on PATH" in result.stdout
    assert "pip-audit CLI: not found on PATH" in result.stdout
    assert "opa CLI: not found on PATH" in result.stdout
    assert "MCTS_LLM_API_KEY: not set" in result.stdout


def test_doctor_deep_present_optional_tools_show_pass_lines(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(doctor_module.importlib_util, "find_spec", lambda _module: SimpleNamespace())
    monkeypatch.setattr(doctor_module.shutil, "which", lambda executable: f"C:\\tools\\{executable}.exe")
    monkeypatch.setenv("MCTS_LLM_API_KEY", "test-key")

    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0
    assert "[mcp] extra: module 'mcp' importable" in result.stdout
    assert "[api] extra: module 'fastapi' importable" in result.stdout
    assert "semgrep CLI: found at C:\\tools\\semgrep.exe" in result.stdout
    assert "pip-audit CLI: found at C:\\tools\\pip-audit.exe" in result.stdout
    assert "opa CLI: found at C:\\tools\\opa.exe" in result.stdout
    assert "MCTS_LLM_API_KEY: set" in result.stdout


def test_doctor_deep_missing_optional_extras_do_not_fail_core_only_install(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        doctor_module.importlib_util,
        "find_spec",
        lambda module: None if module in {"mcp", "fastapi"} else SimpleNamespace(),
    )

    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0
    assert "[mcp] extra: module 'mcp' not found" in result.stdout
    assert "[api] extra: module 'fastapi' not found" in result.stdout


def test_doctor_deep_exits_zero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0


def test_doctor_deep_without_config_shows_skip_message(tmp_path: Path) -> None:
    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0
    assert "Deep checks: skipped — no MCP config found" in result.stdout


def test_doctor_deep_without_module_shows_skip_message(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"local": {"command": "python", "args": ["server.py"]}}}))

    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0
    assert "Deep checks: skipped for 'local' — no -m module in launch args" in result.stdout


def test_doctor_deep_json_includes_skip_status(tmp_path: Path) -> None:
    result = runner.invoke(app, ["doctor", "--deep", "--json", str(tmp_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout.split("Saved")[0].strip())
    deep_checks = [row for row in payload["checks"] if row["label"] == "Deep checks"]
    assert deep_checks
    assert deep_checks[0]["status"] == "warn"
    assert "skipped" in deep_checks[0]["detail"]
