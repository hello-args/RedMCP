"""Tests for pip-audit dependency scanning."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from mcts.analyzers.vulnerable_package import VulnerablePackageAnalyzer
from mcts.mcp.models import MCPServerInfo


def test_pip_audit_skip_when_cli_missing(tmp_path: Path) -> None:
    with patch("mcts.analyzers.vulnerable_package.shutil.which", return_value=None):
        findings = VulnerablePackageAnalyzer(tmp_path).analyze(MCPServerInfo(name="x"))
    assert len(findings) == 1
    assert findings[0].id == "pip-audit-skipped"
    assert "not found on PATH" in findings[0].description


def test_pip_audit_skip_when_no_manifest(tmp_path: Path) -> None:
    with patch("mcts.analyzers.vulnerable_package.shutil.which", return_value="/usr/bin/pip-audit"):
        findings = VulnerablePackageAnalyzer(tmp_path).analyze(MCPServerInfo(name="x"))
    assert len(findings) == 1
    assert findings[0].id == "pip-audit-skipped"
    assert "requirements.txt" in findings[0].description


def test_pip_audit_reports_cve_findings(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    audit_payload = [
        {
            "name": "requests",
            "version": "2.0.0",
            "vulns": [{"id": "CVE-TEST-1", "description": "Test vulnerability"}],
        }
    ]

    class FakeProc:
        returncode = 1
        stdout = json.dumps(audit_payload)
        stderr = ""

    with (
        patch("mcts.analyzers.vulnerable_package.shutil.which", return_value="/usr/bin/pip-audit"),
        patch("mcts.analyzers.vulnerable_package.subprocess.run", return_value=FakeProc()),
    ):
        findings = VulnerablePackageAnalyzer(tmp_path).analyze(MCPServerInfo(name="x"))

    assert any(f.id.startswith("pip-audit-requests-") for f in findings)
    assert not any(f.id == "pip-audit-skipped" for f in findings)
