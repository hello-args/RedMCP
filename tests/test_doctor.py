"""Tests for mcts doctor command."""

from __future__ import annotations

import json
from importlib.machinery import ModuleSpec
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcts.cli import doctor as doctor_module
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


@pytest.mark.parametrize(
    ("spec", "expected_status"),
    [
        (ModuleSpec("mcp", loader=None), "pass"),
        (None, "warn"),
    ],
)
def test_doctor_reports_mcp_extra_status(
    monkeypatch: pytest.MonkeyPatch,
    spec: ModuleSpec | None,
    expected_status: str,
) -> None:
    monkeypatch.setattr(
        doctor_module.importlib.util,
        "find_spec",
        lambda name: spec if name == "mcp" else None,
    )

    checks: list[tuple[str, str, str]] = []
    did_warn = doctor_module._append_optional_extra_check(
        checks,
        extra_label="Extra [mcp]",
        module_name="mcp",
        available_detail="installed — live scan / mcts-mcp available",
        missing_detail='missing — install with `pip install "mcp-mcts[mcp]"` or `uv sync --extra mcp`',
    )

    assert did_warn is (expected_status == "warn")
    assert checks == [
        (
            expected_status,
            "Extra [mcp]",
            "installed — live scan / mcts-mcp available"
            if expected_status == "pass"
            else 'missing — install with `pip install "mcp-mcts[mcp]"` or `uv sync --extra mcp`',
        )
    ]
