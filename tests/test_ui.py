"""Tests for terminal UI helpers."""

from mcpaudit.reporting.models import Finding, Severity
from mcpaudit.ui.dashboard import compute_owasp_counts, sort_findings
from mcpaudit.ui.theme import ThemeName, get_theme


def test_get_theme_cyber() -> None:
    theme = get_theme("cyber")
    assert theme.name == ThemeName.CYBER
    assert theme.palette.cyan == "#00bfff"


def test_get_theme_invalid() -> None:
    try:
        get_theme("neon")
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "neon" in str(exc)


def test_score_rating_critical() -> None:
    theme = get_theme("cyber")
    label, color = theme.score_rating(5)
    assert label == "CRITICAL"
    assert color == theme.palette.red


def test_risk_index_color() -> None:
    theme = get_theme("cyber")
    assert theme.risk_index_color(90) == theme.palette.red
    assert theme.risk_index_color(10) == theme.palette.green


def test_score_rating_low_risk() -> None:
    theme = get_theme("cyber")
    label, _ = theme.score_rating(95)
    assert label == "LOW"


def test_sort_findings_by_severity() -> None:
    findings = [
        Finding(
            id="1",
            analyzer="tool_abuse",
            title="Low issue",
            description="d",
            severity=Severity.LOW,
            recommendation="r",
        ),
        Finding(
            id="2",
            analyzer="permission_analyzer",
            title="Critical issue",
            description="d",
            severity=Severity.CRITICAL,
            recommendation="r",
        ),
    ]
    sorted_findings = sort_findings(findings)
    assert sorted_findings[0].severity == Severity.CRITICAL


def test_compute_owasp_counts() -> None:
    findings = [
        Finding(
            id="1",
            analyzer="prompt_injection",
            title="inj",
            description="d",
            severity=Severity.HIGH,
            recommendation="r",
        ),
        Finding(
            id="2",
            analyzer="prompt_injection",
            title="inj2",
            description="d",
            severity=Severity.HIGH,
            recommendation="r",
        ),
        Finding(
            id="3",
            analyzer="data_leakage",
            title="leak",
            description="d",
            severity=Severity.MEDIUM,
            recommendation="r",
        ),
    ]
    counts = compute_owasp_counts(findings)
    llm01 = next(item for item in counts if item[0] == "LLM01")
    assert llm01[2] == 2
