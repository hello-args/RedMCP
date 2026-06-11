"""Write the standard scan artifact trio (JSON, HTML, SARIF)."""

from __future__ import annotations

from pathlib import Path

from mcts.output.analysis_dir import resolve_output_path
from mcts.output.history import record_scan_run, trend_points_for_target
from mcts.report.generators.html_report import write_html_report
from mcts.reporting.models import ScanReport
from mcts.reporting.sarif import write_sarif_report


def _report_with_scan_history(report: ScanReport) -> ScanReport:
    """Attach trend points from ``history.json`` so JSON/HTML work from any folder."""
    points = trend_points_for_target(report.target)
    if not points:
        scanned = report.scanned_at
        if scanned.tzinfo is None:
            from datetime import UTC

            scanned = scanned.replace(tzinfo=UTC)
        points = [
            {
                "date": scanned.strftime("%b %d"),
                "score": report.score.overall,
                "scanned_at": scanned.isoformat(),
            }
        ]
    return report.model_copy(update={"scan_history": points})


def persist_scan_artifacts(
    report: ScanReport,
    *,
    json_path: Path | None = None,
    html_path: Path | None = None,
    sarif_path: Path | None = None,
    record_history: bool = True,
    write_json: bool = True,
) -> tuple[Path, Path, Path]:
    """Write JSON + HTML + SARIF under ``mcts_analysis/`` and update trend history."""
    if record_history:
        record_scan_run(report)
    report = _report_with_scan_history(report)

    json_out = resolve_output_path(json_path, "scan-report.json")
    if html_path is None:
        html_out = json_out.with_suffix(".html")
    else:
        html_out = resolve_output_path(html_path, "scan-report.html")
    if sarif_path is None:
        sarif_out = json_out.with_suffix(".sarif")
    else:
        sarif_out = resolve_output_path(sarif_path, "scan-report.sarif")

    if write_json:
        json_out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    write_html_report(report, html_out)
    sarif_out.write_text(write_sarif_report(report), encoding="utf-8")
    return json_out, html_out, sarif_out
