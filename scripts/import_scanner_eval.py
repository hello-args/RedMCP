#!/usr/bin/env python3
"""Scan MCP Scanner behavioral eval tree and report MCTS detection recall."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.sast.extract_tool import extract_first_tool


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate MCTS against MCP Scanner behavioral corpus")
    parser.add_argument(
        "data_dir",
        type=Path,
        help="Path to mcp-scanner evals/behavioral-analysis/data",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when any scanned file is missed (for CI gates)",
    )
    parser.add_argument(
        "--min-recall",
        type=float,
        default=None,
        metavar="RATIO",
        help="Exit 1 when recall is below this ratio (0.0–1.0, for CI gates)",
    )
    args = parser.parse_args()

    if args.min_recall is not None and not 0.0 <= args.min_recall <= 1.0:
        print("--min-recall must be between 0.0 and 1.0", file=sys.stderr)
        return 2

    if not args.data_dir.is_dir():
        print(f"Data directory not found: {args.data_dir}", file=sys.stderr)
        return 2

    analyzer = BehavioralStaticAnalyzer()
    rows: list[dict] = []
    for py_file in sorted(args.data_dir.rglob("*.py")):
        source = py_file.read_text(encoding="utf-8", errors="replace")
        extracted = extract_first_tool(source)
        if not extracted:
            rows.append({"file": str(py_file), "status": "skipped", "reason": "no @tool handler"})
            continue
        tool = MCPTool(
            name=extracted.name,
            description=extracted.description,
            handler_snippet=extracted.handler_snippet,
            source_file=str(py_file),
            source_line=extracted.source_line,
        )
        findings = analyzer.analyze(MCPServerInfo(tools=[tool]))
        detected = bool(findings)
        rows.append(
            {
                "file": str(py_file.relative_to(args.data_dir)),
                "status": "detected" if detected else "missed",
                "findings": [f.title for f in findings],
            }
        )

    scanned = [row for row in rows if row.get("status") in {"detected", "missed"}]
    detected_count = sum(1 for row in scanned if row["status"] == "detected")
    missed_count = sum(1 for row in scanned if row["status"] == "missed")
    recall = (detected_count / len(scanned)) if scanned else 1.0

    if args.json:
        print(
            json.dumps(
                {
                    "total_files": len(rows),
                    "scanned": len(scanned),
                    "detected": detected_count,
                    "missed": missed_count,
                    "recall": round(recall, 4),
                    "results": rows,
                },
                indent=2,
            )
        )
    else:
        print(f"MCP Scanner behavioral parity: {detected_count}/{len(scanned)} detected ({recall:.1%})")
        for row in rows:
            if row.get("status") == "missed":
                print(f"  MISS {row['file']}")
            elif row.get("status") == "skipped":
                print(f"  SKIP {row['file']} ({row['reason']})")

    if args.strict and missed_count > 0:
        return 1
    if args.min_recall is not None and recall < args.min_recall:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
