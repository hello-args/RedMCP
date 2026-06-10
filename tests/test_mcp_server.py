"""Tests for mcts-mcp server tools."""

from __future__ import annotations

import asyncio
import builtins
import json

import pytest

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp_server.server import compare_baselines, explain_finding, scan_mcp_target


def test_mcp_server_tools_registered() -> None:
    pytest.importorskip("mcp")
    from mcts.mcp_server.server import create_server

    app = create_server()
    tools = asyncio.run(app.list_tools())
    names = {tool.name for tool in tools}
    assert {
        "scan_mcp_target",
        "scan_mcp_server",
        "list_techniques",
        "explain_finding",
        "compare_baselines",
    }.issubset(names)


def test_list_techniques_tool() -> None:
    pytest.importorskip("mcp")
    from mcts.mcp_server.server import list_techniques

    payload = __import__("json").loads(list_techniques())
    assert payload["count"] >= 79


def test_scan_mcp_target_runs_on_example() -> None:
    raw = scan_mcp_target("examples/vulnerable-mcp-server/server.py", live=False)
    payload = json.loads(raw)
    assert "findings" in payload
    assert payload.get("summary") is not None


def test_explain_finding_tool() -> None:
    report = Scanner(ScanConfig(target="examples/vulnerable-mcp-server/server.py")).run()
    report_json = json.dumps(report.model_dump(mode="json"))
    finding_id = report.findings[0].id

    raw = explain_finding(finding_id, report_json)
    payload = json.loads(raw)
    assert payload["id"] == finding_id
    assert payload["recommendation"]


def test_compare_baselines_tool() -> None:
    baseline = Scanner(ScanConfig(target="examples/baseline-mcp-server/server.py")).run()
    current = Scanner(ScanConfig(target="examples/vulnerable-mcp-server/server.py")).run()

    raw = compare_baselines(
        json.dumps(baseline.model_dump(mode="json")),
        json.dumps(current.model_dump(mode="json")),
    )
    payload = json.loads(raw)
    assert "score_delta" in payload
    assert payload["finding_delta"] >= 0


def test_create_server_reports_missing_mcp_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "mcp.server.fastmcp":
            raise ImportError("No module named 'mcp'")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    from mcts.mcp_server.server import create_server

    with pytest.raises(RuntimeError) as excinfo:
        create_server()

    assert "requires the [mcp] extra" in str(excinfo.value)
    assert 'pip install "mcp-mcts[mcp]"' in str(excinfo.value)
    assert "mcts doctor ." in str(excinfo.value)
