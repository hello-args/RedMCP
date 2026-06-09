"""Machine-wide MCP scanning across local client configs."""

from __future__ import annotations

from dataclasses import dataclass, field

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.inventory.models import InventoryEntry
from mcts.inventory.runner import run_inventory
from mcts.inventory.targets import entry_to_scan_config
from mcts.reporting.models import ScanReport


@dataclass
class MachineScanResult:
    entry: InventoryEntry
    report: ScanReport | None = None
    error: str | None = None


@dataclass
class MachineScanSummary:
    scanned: int = 0
    skipped: int = 0
    failed: int = 0
    results: list[MachineScanResult] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(len(row.report.findings) for row in self.results if row.report is not None)

    @property
    def worst_score(self) -> int | None:
        scores = [row.report.score.overall for row in self.results if row.report is not None]
        return min(scores) if scores else None

    def has_high_severity(self) -> bool:
        for row in self.results:
            if row.report is None:
                continue
            if row.report.summary.critical or row.report.summary.high:
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "scanned": self.scanned,
            "skipped": self.skipped,
            "failed": self.failed,
            "total_findings": self.total_findings,
            "worst_score": self.worst_score,
            "servers": [
                {
                    "client": row.entry.client,
                    "server_name": row.entry.server_name,
                    "config_path": row.entry.config_path,
                    "target": str(row.report.target) if row.report else None,
                    "score": row.report.score.overall if row.report else None,
                    "findings": len(row.report.findings) if row.report else 0,
                    "critical": row.report.summary.critical if row.report else 0,
                    "high": row.report.summary.high if row.report else 0,
                    "error": row.error,
                    "report": row.report.model_dump(mode="json") if row.report else None,
                }
                for row in self.results
            ],
        }


def run_machine_wide(base_config: ScanConfig) -> MachineScanSummary:
    """Scan every resolvable MCP server from local client inventory."""
    inventory = run_inventory()
    summary = MachineScanSummary()

    for entry in inventory.entries:
        scan_config = entry_to_scan_config(entry, base_config)
        if scan_config is None:
            summary.skipped += 1
            summary.results.append(
                MachineScanResult(entry=entry, error="Could not resolve server entrypoint")
            )
            continue

        try:
            report = Scanner(scan_config).run()
        except Exception as exc:  # noqa: BLE001 — collect per-server failures for machine audit
            summary.failed += 1
            summary.results.append(MachineScanResult(entry=entry, error=str(exc)))
            continue

        summary.scanned += 1
        summary.results.append(MachineScanResult(entry=entry, report=report))

    return summary
