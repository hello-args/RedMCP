"""Category gate parsing and CLI integration tests."""

from __future__ import annotations

from mcts.report.data import category_gate_failures, parse_category_gates
from mcts.reporting.models import Finding, Severity


def test_parse_category_gates_accepts_comma_and_repeatable() -> None:
    gates = parse_category_gates(["permissions:10", "injection:5,execution:3"])
    assert gates == {"permissions": 10, "injection": 5, "execution": 3}


def test_category_gate_failures_when_score_meets_limit() -> None:
    findings = [
        Finding(
            id="p1",
            analyzer="permission_analyzer",
            title="perm",
            description="d",
            severity=Severity.HIGH,
            recommendation="r",
        ),
        Finding(
            id="p2",
            analyzer="permission_analyzer",
            title="perm2",
            description="d",
            severity=Severity.HIGH,
            recommendation="r",
        ),
    ]
    failures = category_gate_failures(findings, {"permissions": 10})
    assert failures
    assert "Excessive Permissions" in failures[0]


def test_category_gate_passes_below_limit() -> None:
    findings = [
        Finding(
            id="p1",
            analyzer="permission_analyzer",
            title="perm",
            description="d",
            severity=Severity.LOW,
            recommendation="r",
        )
    ]
    assert not category_gate_failures(findings, {"permissions": 10})


def test_category_gate_boundary_score_equals_limit() -> None:
    """score == limit should FAIL with inclusive message."""
    failures = category_gate_failures([], {"permissions": 0})
    assert len(failures) == 1
    assert "inclusive gate" in failures[0]
    assert ">=" in failures[0]
    assert "0" in failures[0]


def test_category_gate_score_zero_limit_one_passes() -> None:
    """score=0, limit=1 should NOT fail — score is below limit."""
    failures = category_gate_failures([], {"permissions": 1})
    assert len(failures) == 0


def test_category_gate_failure_message_never_says_passed_alone() -> None:
    """Failure message must not imply CI pass when gate fails."""
    failures = category_gate_failures([], {"permissions": 0})
    assert len(failures) == 1
    message = failures[0]
    assert "inclusive gate" in message
    assert ">=" in message
