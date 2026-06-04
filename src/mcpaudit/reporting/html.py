"""HTML report generation (delegates to premium dashboard)."""

from __future__ import annotations

from pathlib import Path

from mcpaudit.report.generators.html_report import write_html_report as _write_dashboard

from mcpaudit.reporting.models import ScanReport


def write_html_report(report: ScanReport, output: Path) -> None:
    """Write a standalone HTML security dashboard report."""
    _write_dashboard(report, output)
