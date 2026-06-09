"""Inventory runner."""

from __future__ import annotations

from pathlib import Path

from mcts.inventory.discoverers import discover_config_paths, parse_config_file
from mcts.inventory.models import InventoryEntry, InventoryReport
from mcts.inventory.skills import discover_skills
from mcts.inventory.targets import resolve_entrypoint


def run_inventory(*, skills: bool = False) -> InventoryReport:
    entries: list[InventoryEntry] = []
    clients: set[str] = set()
    files_found = 0

    for client, path in discover_config_paths():
        files_found += 1
        clients.add(client)
        entries.extend(parse_config_file(client, path))

    skill_entries = discover_skills(project_root=Path.cwd()) if skills else []

    return InventoryReport(
        entries=entries,
        clients_scanned=sorted(clients),
        config_files_found=files_found,
        skills=skill_entries,
    )


def enrich_with_tool_names(entries: list[InventoryEntry]) -> list[InventoryEntry]:
    """Optionally static-scan each server command target to list tool names."""
    from mcts.core.config import ScanConfig
    from mcts.core.scanner import Scanner

    enriched: list[InventoryEntry] = []
    for entry in entries:
        updated = entry.model_copy()
        target = resolve_entrypoint(entry)
        if target and target.exists():
            report = Scanner(ScanConfig(target=target)).run()
            updated.tools = [tool.name for tool in report.server.tools]
        enriched.append(updated)
    return enriched


def _resolve_target(entry: InventoryEntry) -> Path | None:
    return resolve_entrypoint(entry)
