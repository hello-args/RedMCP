"""Tests for machine-wide scanning."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.inventory.models import InventoryEntry, InventoryReport
from mcts.inventory.targets import entry_to_scan_config, resolve_entrypoint
from mcts.scan.machine_wide import run_machine_wide


def test_resolve_entrypoint_prefers_python_file(tmp_path: Path) -> None:
    server = tmp_path / "server.py"
    server.write_text("print('mcp')\n")
    entry = InventoryEntry(
        client="cursor",
        config_path=str(tmp_path / "mcp.json"),
        server_name="demo",
        command="python",
        args=[str(server)],
    )
    assert resolve_entrypoint(entry) == server


def test_entry_to_scan_config_from_config_file(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"demo": {"command": "python", "args": ["missing.py"]}}}))
    entry = InventoryEntry(
        client="cursor",
        config_path=str(config),
        server_name="demo",
        command="python",
        args=["missing.py"],
    )
    base = ScanConfig(target=tmp_path)
    resolved = entry_to_scan_config(entry, base)
    assert resolved is not None
    assert resolved.config_server == "demo"
    assert resolved.config_path == config


def test_run_machine_wide_scans_discovered_servers(tmp_path: Path, monkeypatch) -> None:
    server = tmp_path / "server.py"
    server.write_text("print('hello')\n")
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"demo": {"command": "python", "args": [str(server)]}}}))
    entry = InventoryEntry(
        client="cursor",
        config_path=str(config),
        server_name="demo",
        command="python",
        args=[str(server)],
    )
    monkeypatch.setattr(
        "mcts.scan.machine_wide.run_inventory",
        lambda: InventoryReport(entries=[entry], clients_scanned=["cursor"], config_files_found=1),
    )

    summary = run_machine_wide(ScanConfig(target=tmp_path))
    assert summary.scanned == 1
    assert summary.results[0].report is not None
