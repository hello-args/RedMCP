"""Resolve inventory entries to scan targets."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.inventory.models import InventoryEntry


def resolve_entrypoint(entry: InventoryEntry) -> Path | None:
    """Return a filesystem path for static scanning when possible."""
    if not entry.args:
        return None
    for arg in entry.args:
        candidate = Path(arg).expanduser()
        if candidate.suffix == ".py" and candidate.exists():
            return candidate
    for arg in entry.args:
        candidate = Path(arg).expanduser()
        if candidate.exists():
            return candidate
    return None


def entry_to_scan_config(entry: InventoryEntry, base: ScanConfig) -> ScanConfig | None:
    """Build a scan config for one discovered MCP server entry."""
    config_path = Path(entry.config_path)
    entrypoint = resolve_entrypoint(entry)

    if entrypoint and entrypoint.exists():
        target = entrypoint if entrypoint.is_dir() else entrypoint.parent
        return base.model_copy(
            update={
                "target": target,
                "config_path": config_path,
                "config_server": entry.server_name,
            }
        )

    if config_path.exists():
        return base.model_copy(
            update={
                "target": config_path.parent,
                "config_path": config_path,
                "config_server": entry.server_name,
            }
        )

    return None
