"""MCTS MCP server tools for IDE agents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcts.taxonomy.mapper import load_taxonomy


def scan_mcp_target(target: str, live: bool = False) -> str:
    """Run an MCTS security scan on an MCP server path or repository."""
    from mcts.core.config import ScanConfig
    from mcts.core.scanner import Scanner

    config = ScanConfig(
        target=Path(target),
        live=live,
        live_consent=live,
    )
    report = Scanner(config).run()
    return json.dumps(report.model_dump(mode="json"), indent=2)


def scan_mcp_server(target: str, live: bool = False) -> str:
    """Alias for scan_mcp_target — run an MCTS security scan on an MCP server."""
    return scan_mcp_target(target, live=live)


def list_techniques() -> str:
    """List bundled MCTS-T techniques and default analyzers."""
    data = load_taxonomy()
    rows = []
    for technique_id in sorted(data.get("techniques", {})):
        row = data["techniques"][technique_id]
        rows.append(
            {
                "technique_id": technique_id,
                "name": row.get("name"),
                "severity_default": row.get("severity_default"),
                "analyzers": row.get("analyzers") or [],
            }
        )
    return json.dumps({"techniques": rows, "count": len(rows)}, indent=2)


def explain_finding(finding_id: str, report_json: str) -> str:
    """Explain a finding from a scan report JSON payload by finding ID."""
    payload = json.loads(report_json)
    findings = payload.get("findings") or []
    match = next((row for row in findings if row.get("id") == finding_id), None)
    if match is None:
        return json.dumps({"error": f"Finding not found: {finding_id}"})

    explanation = {
        "id": match.get("id"),
        "title": match.get("title"),
        "severity": match.get("severity"),
        "analyzer": match.get("analyzer"),
        "technique_id": match.get("technique_id"),
        "description": match.get("description"),
        "recommendation": match.get("recommendation"),
        "evidence": match.get("evidence") or {},
        "tool": match.get("tool"),
    }
    return json.dumps(explanation, indent=2)


def compare_baselines(baseline_report_json: str, current_report_json: str) -> str:
    """Compare two scan reports and summarize score and finding deltas."""
    baseline = _report_summary(json.loads(baseline_report_json))
    current = _report_summary(json.loads(current_report_json))
    delta = {
        "baseline": baseline,
        "current": current,
        "score_delta": current["overall_score"] - baseline["overall_score"],
        "finding_delta": current["finding_count"] - baseline["finding_count"],
        "new_findings": _new_finding_ids(baseline, current),
    }
    return json.dumps(delta, indent=2)


def create_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError(
            "MCP server mode requires the [mcp] extra.\n"
            'Install with: pip install "mcp-mcts[mcp]"\n'
            "Or, from a repo checkout: uv sync --extra mcp\n"
            "Run `mcts doctor .` to verify optional extras."
        ) from exc

    app = FastMCP("mcts")
    app.tool()(scan_mcp_target)
    app.tool()(scan_mcp_server)
    app.tool()(list_techniques)
    app.tool()(explain_finding)
    app.tool()(compare_baselines)
    return app


def _report_summary(payload: dict[str, Any]) -> dict[str, Any]:
    score = payload.get("score") or {}
    findings = payload.get("findings") or []
    return {
        "overall_score": int(score.get("overall") or 0),
        "finding_count": len(findings),
        "finding_ids": sorted(str(row.get("id")) for row in findings if row.get("id")),
        "critical": int((payload.get("summary") or {}).get("critical") or 0),
        "high": int((payload.get("summary") or {}).get("high") or 0),
    }


def _new_finding_ids(baseline: dict[str, Any], current: dict[str, Any]) -> list[str]:
    old = set(baseline.get("finding_ids") or [])
    return sorted(fid for fid in current.get("finding_ids") or [] if fid not in old)
