"""Tests for Semgrep SAST adapter."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from mcts.analyzers.semgrep_adapter import (
    SemgrepAdapterAnalyzer,
    _findings_from_payload,
    run_semgrep_scan,
)
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Severity


def test_findings_from_semgrep_payload() -> None:
    payload = {
        "results": [
            {
                "check_id": "mcts-python-subprocess-shell",
                "path": "server.py",
                "start": {"line": 12, "col": 4},
                "extra": {
                    "message": "Shell command execution via subprocess with shell=True",
                    "severity": "ERROR",
                    "metadata": {"technique_id": "MCTS-T-1003", "category": "command_execution"},
                },
            }
        ]
    }
    findings = _findings_from_payload(payload, analyzer="semgrep_sast")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.analyzer == "semgrep_sast"
    assert finding.severity == Severity.HIGH
    assert finding.technique_id == "MCTS-T-1003"
    assert finding.location is not None
    assert finding.location.file == "server.py"
    assert finding.location.line == 12


def test_semgrep_analyzer_uses_mocked_cli(tmp_path: Path) -> None:
    target = tmp_path / "proj"
    target.mkdir()
    (target / "bad.py").write_text("import subprocess\nsubprocess.run('ls', shell=True)\n", encoding="utf-8")
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")

    mock_payload = {
        "results": [
            {
                "check_id": "mcts-python-subprocess-shell",
                "path": str(target / "bad.py"),
                "start": {"line": 2, "col": 1},
                "extra": {"message": "shell=True", "severity": "ERROR", "metadata": {}},
            }
        ]
    }

    with patch("mcts.analyzers.semgrep_adapter.run_semgrep_scan", return_value=mock_payload):
        analyzer = SemgrepAdapterAnalyzer(target=target, rules_path=rules)
        findings = analyzer.analyze(MCPServerInfo(name="test"))

    assert len(findings) == 1
    assert findings[0].title.startswith("Semgrep:")


def test_run_semgrep_scan_missing_cli(tmp_path: Path) -> None:
    with patch("mcts.analyzers.semgrep_adapter.shutil.which", return_value=None):
        payload = run_semgrep_scan(tmp_path, tmp_path / "rules.yaml")
    assert payload["results"] == []
    assert payload["errors"]


def test_findings_from_payload_reports_semgrep_skip_reason() -> None:
    payload = {
        "results": [],
        "errors": [{"message": "semgrep CLI not found on PATH"}],
    }
    findings = _findings_from_payload(payload, analyzer="semgrep_sast")
    assert len(findings) == 1
    assert findings[0].id == "semgrep-skipped"
    assert "not found on PATH" in findings[0].description


def test_run_semgrep_scan_parses_json(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    payload_text = json.dumps({"results": [], "errors": []})

    class FakeProc:
        returncode = 0
        stdout = payload_text
        stderr = ""

    with (
        patch("mcts.analyzers.semgrep_adapter.shutil.which", return_value="/usr/bin/semgrep"),
        patch("mcts.analyzers.semgrep_adapter.subprocess.run", return_value=FakeProc()),
    ):
        payload = run_semgrep_scan(tmp_path, rules)

    assert payload == {"results": [], "errors": []}
