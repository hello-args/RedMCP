"""Technique regression fixtures against MCTS analyzers."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcts.analyzers.sigma_dedupe import dedupe_sigma_findings
from mcts.reporting.models import Finding, Severity
from mcts.testing.regression_harness import (
    REGRESSION_TECHNIQUES,
    REGRESSION_THRESHOLD,
    evaluate_technique,
    regression_summary,
    write_regression_report,
)


@pytest.mark.parametrize("technique_id", REGRESSION_TECHNIQUES)
def test_technique_scenario_parity_meets_threshold(technique_id: str) -> None:
    result = evaluate_technique(technique_id)
    assert result.total > 0, f"No parity cases loaded for {technique_id}"
    assert result.accuracy_pct >= REGRESSION_THRESHOLD, (
        f"{technique_id} parity {result.accuracy_pct}% "
        f"(FP={result.false_positives}, FN={result.false_negatives})"
    )


def test_regression_summary_covers_all_fixture_techniques() -> None:
    summary = regression_summary()
    ids = {row.technique_id for row in summary}
    assert set(REGRESSION_TECHNIQUES).issubset(ids)
    for row in summary:
        assert row.accuracy_pct >= REGRESSION_THRESHOLD


def test_parity_report_artifact(tmp_path: Path) -> None:
    report_path = tmp_path / "regression-report.json"
    summary = write_regression_report(report_path)
    assert report_path.exists()
    assert len(summary) == len(REGRESSION_TECHNIQUES)


def test_sigma_dedupe_suppresses_redundant_sigma_on_metadata_hit() -> None:
    metadata = Finding(
        id="meta-1",
        analyzer="metadata_integrity",
        title="poison",
        description="d",
        severity=Severity.HIGH,
        recommendation="r",
        tool="read_file",
    )
    sigma = Finding(
        id="sigma-1",
        analyzer="sigma_metadata",
        title="sigma",
        description="d",
        severity=Severity.HIGH,
        recommendation="r",
        tool="read_file",
        evidence={"corpus_field": "description"},
    )
    deduped = dedupe_sigma_findings([metadata, sigma])
    assert len(deduped) == 1
    assert deduped[0].analyzer == "metadata_integrity"
