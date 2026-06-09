"""Tests for live MCP startup error classification."""

from __future__ import annotations

from pathlib import Path

from mcts.probe.startup_errors import MCPStartupError, StartupCategory, classify_startup_failure

_FIXTURES = Path(__file__).parent / "fixtures" / "startup_stderr"


def test_classify_import_error() -> None:
    stderr = ["Traceback...", "ModuleNotFoundError: No module named 'ifd'"]
    err = classify_startup_failure("process exited", stderr, command="python")
    assert isinstance(err, MCPStartupError)
    assert err.category == StartupCategory.IMPORT_ERROR
    assert "ifd" in err.detected_line


def test_classify_missing_credentials() -> None:
    stderr = ["ERROR: Could not load credentials from SSO profile"]
    err = classify_startup_failure("", stderr)
    assert err is not None
    assert err.category == StartupCategory.MISSING_CREDENTIALS


def test_classify_timeout() -> None:
    err = classify_startup_failure("Timed out connecting after 30s", [])
    assert err is not None
    assert err.category == StartupCategory.TIMEOUT


def test_classify_import_error_fixture() -> None:
    stderr = (_FIXTURES / "import_error.txt").read_text().splitlines()
    err = classify_startup_failure("", stderr)
    assert err is not None
    assert err.category == StartupCategory.IMPORT_ERROR


def test_classify_clean_stderr_returns_none_or_unknown() -> None:
    stderr = (_FIXTURES / "clean.txt").read_text().splitlines()
    err = classify_startup_failure("", stderr)
    assert err is None or err.category.value == "unknown"


def test_classify_credentials_fixture() -> None:
    stderr = (_FIXTURES / "missing_credentials.txt").read_text().splitlines()
    err = classify_startup_failure("", stderr)
    assert err is not None
    assert err.category == StartupCategory.MISSING_CREDENTIALS
