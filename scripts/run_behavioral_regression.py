#!/usr/bin/env python3
"""Batch behavioral static regression on example MCP servers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcts.sast.behavioral_regression import (
    DEFAULT_TARGETS,
    parse_finding_band,
    parse_score_band,
    run_behavioral_regression,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run behavioral static regression on MCP example servers",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        type=Path,
        help="Server entrypoints to analyze (default: bundled example servers)",
    )
    parser.add_argument(
        "--expect-band",
        action="append",
        default=[],
        metavar="SPEC",
        help=(
            "Expected full-scan score band: PATH:MIN_SCORE:MAX_SCORE or "
            "PATH:MIN_SCORE:MAX_SCORE:MIN_RAW:MAX_RAW (repeatable)"
        ),
    )
    parser.add_argument(
        "--expect-findings",
        action="append",
        default=[],
        metavar="SPEC",
        help="Expected behavioral-static finding count: PATH:MIN:MAX (repeatable)",
    )
    parser.add_argument(
        "--gate-defaults",
        action="store_true",
        help="Apply default score and behavioral-finding bands for bundled examples",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    try:
        score_bands = [parse_score_band(spec) for spec in args.expect_band]
        finding_bands = [parse_finding_band(spec) for spec in args.expect_findings]
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    targets = args.targets or list(DEFAULT_TARGETS)
    gating = bool(args.gate_defaults or score_bands or finding_bands)

    report = run_behavioral_regression(
        targets,
        score_bands=score_bands,
        finding_bands=finding_bands,
        gate_defaults=args.gate_defaults,
    )

    if args.json:
        payload = {
            "total": report.total,
            "passed": report.passed,
            "failed": report.failed,
            "gating_enabled": gating,
            "results": [
                {
                    "path": row.path,
                    "exists": row.exists,
                    "behavioral_findings": row.behavioral_findings,
                    "finding_titles": row.finding_titles,
                    "score_overall": row.score_overall,
                    "score_raw": row.score_raw,
                    "passed": row.passed,
                    "failures": row.failures,
                }
                for row in report.results
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"Behavioral regression: {report.passed}/{report.total} passed")
        total_findings = 0
        for row in report.results:
            total_findings += row.behavioral_findings
            status = "PASS" if row.passed else "FAIL"
            print(f"  [{status}] {Path(row.path).name}: {row.behavioral_findings} behavioral finding(s)")
            if row.score_overall is not None:
                print(f"         score={row.score_overall} raw_risk={row.score_raw}")
            for title in row.finding_titles:
                print(f"         - {title}")
            for failure in row.failures:
                print(f"         ! {failure}")
        print(f"Total behavioral findings: {total_findings}")

    if gating and report.failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
