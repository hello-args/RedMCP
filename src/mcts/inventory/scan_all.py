"""Inventory batch full-scan helpers."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.inventory.models import InventoryEntry, InventoryReport
from mcts.inventory.runner import run_inventory
from mcts.inventory.targets import entry_to_scan_config
from mcts.output.analysis_dir import resolve_output_path


def run_inventory_scan_all(base_config: ScanConfig) -> tuple[InventoryReport, list[dict]]:
    """Run a full security scan for each resolvable inventory entry."""
    inventory = run_inventory()
    rows: list[dict] = []
    for entry in inventory.entries:
        scan_config = entry_to_scan_config(entry, base_config)
        if scan_config is None:
            rows.append(_row(entry, error="Could not resolve server entrypoint"))
            continue
        try:
            report = Scanner(scan_config, inventory=inventory.entries).run()
        except Exception as exc:  # noqa: BLE001
            rows.append(_row(entry, error=str(exc)))
            continue
        rows.append(
            _row(
                entry,
                report=report,
                score=report.score.overall,
                findings=len(report.findings),
            )
        )
    return inventory, rows


def write_inventory_scan_all(path: Path, inventory: InventoryReport, rows: list[dict]) -> None:
    payload = {
        "clients_scanned": inventory.clients_scanned,
        "config_files_found": inventory.config_files_found,
        "entries": [entry.model_dump() for entry in inventory.entries],
        "scan_results": rows,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def default_output_path(output: Path | None) -> Path:
    return resolve_output_path(output, "inventory-scan-all.json")


def _row(entry: InventoryEntry, **payload) -> dict:
    row = {
        "client": entry.client,
        "server_name": entry.server_name,
        "config_path": entry.config_path,
    }
    row.update(payload)
    return row
