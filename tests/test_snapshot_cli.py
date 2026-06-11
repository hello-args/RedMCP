"""Tests for snapshot export helpers."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from mcts.cli.main import app
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.snapshot.export import export_snapshot, snapshot_dict_from_server

runner = CliRunner()


def test_snapshot_missing_launch_config_exit_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["snapshot", str(tmp_path), "--i-understand-live-risk"])
    assert result.exit_code == 2
    assert "Live scan requires" in result.output
    assert "Traceback" not in result.output


def test_snapshot_dict_shape() -> None:
    server = MCPServerInfo(
        name="demo",
        tools=[MCPTool(name="greet", description="hi", input_schema={"type": "object"})],
    )
    payload = snapshot_dict_from_server(server, server_name="demo")
    assert payload["version"] == "1"
    assert len(payload["tools"]) == 1
    assert payload["tools"][0]["name"] == "greet"


def test_export_snapshot_requires_tools() -> None:
    from mcts.probe.models import LiveServerConfig

    config = ScanConfig(target="server.py", live=True, live_consent=True)
    empty = MCPServerInfo(name="live", tools=[], discovery_mode="live")
    live_cfg = LiveServerConfig(command="python", args=["server.py"])
    with (
        patch("mcts.snapshot.export.resolve_live_config", return_value=live_cfg),
        patch("mcts.snapshot.export.probe_stdio_sync", return_value=empty),
    ):
        try:
            export_snapshot(config)
        except RuntimeError as exc:
            assert "zero tools" in str(exc).lower()
        else:
            raise AssertionError("expected RuntimeError")


def test_snapshot_scan_no_static_tool_notice(tmp_path: Path) -> None:
    snap = tmp_path / "tools.json"
    snap.write_text(
        json.dumps(
            {
                "tools": [
                    {"name": "a", "description": "b", "inputSchema": {"type": "object"}},
                ]
            }
        )
    )
    report = Scanner(ScanConfig(target=tmp_path, snapshot_path=snap)).run()
    assert len(report.server.tools) == 1
    assert report.tool_discovery_notice is None
    assert report.scan_scope == "snapshot"


def test_snapshot_round_trip_scan(tmp_path: Path) -> None:
    snap = tmp_path / "tools.json"
    snap.write_text(
        json.dumps(
            {
                "version": "1",
                "tools": [
                    {
                        "name": "greet",
                        "description": "Say hi",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ],
            }
        )
    )
    target = tmp_path / "repo"
    target.mkdir()
    report = Scanner(ScanConfig(target=target, snapshot_path=snap)).run()
    assert len(report.server.tools) == 1
    assert report.server.tools[0].name == "greet"
    assert report.scan_scope == "snapshot"
