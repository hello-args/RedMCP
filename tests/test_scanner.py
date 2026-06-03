"""Integration tests for the scanner."""

from pathlib import Path

from mcpaudit.core.config import ScanConfig
from mcpaudit.core.scanner import Scanner
from mcpaudit.reporting.models import Severity


def test_scan_finds_critical_issues(example_server_path: Path) -> None:
    config = ScanConfig(target=example_server_path)
    report = Scanner(config).run()

    assert report.summary.total > 0
    assert report.summary.critical >= 1
    assert report.score.overall < 100
    assert any(f.severity == Severity.CRITICAL for f in report.findings)
