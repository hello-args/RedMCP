"""Tests for behavioral example-server regression runner."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcts.sast.behavioral_regression import (
    DEFAULT_TARGETS,
    parse_finding_band,
    parse_score_band,
    run_behavioral_regression,
)

_REPO = Path(__file__).resolve().parents[1]


def test_default_targets_exist() -> None:
    for path in DEFAULT_TARGETS:
        assert path.exists(), path


def test_parse_score_band_short_form() -> None:
    band = parse_score_band("examples/safe-mcp-server/server.py:90:100", repo_root=_REPO)
    assert band.min_score == 90
    assert band.max_score == 100
    assert band.min_raw is None


def test_parse_score_band_with_raw_risk() -> None:
    band = parse_score_band(
        "examples/vulnerable-mcp-server/server.py:0:5:180:290",
        repo_root=_REPO,
    )
    assert band.min_raw == 180
    assert band.max_raw == 290


def test_parse_finding_band() -> None:
    band = parse_finding_band("examples/safe-mcp-server/server.py:0:0", repo_root=_REPO)
    assert band.min_findings == 0
    assert band.max_findings == 0


def test_gate_defaults_passes_for_example_servers() -> None:
    report = run_behavioral_regression(gate_defaults=True)
    assert report.failed == 0
    assert report.passed == len(DEFAULT_TARGETS)
    vulnerable = next(
        row for row in report.results if "vulnerable-mcp-server" in row.path
    )
    assert vulnerable.behavioral_findings >= 4
    safe = next(row for row in report.results if "safe-mcp-server" in row.path)
    assert safe.behavioral_findings == 0
    assert safe.score_overall is not None and safe.score_overall >= 95


def test_custom_score_band_failure() -> None:
    safe = _REPO / "examples/safe-mcp-server/server.py"
    report = run_behavioral_regression(
        [safe],
        score_bands=[parse_score_band(f"{safe}:0:10", repo_root=_REPO)],
    )
    assert report.failed == 1
    assert report.results[0].failures


def test_invalid_band_spec_raises() -> None:
    with pytest.raises(ValueError):
        parse_score_band("bad-spec")
