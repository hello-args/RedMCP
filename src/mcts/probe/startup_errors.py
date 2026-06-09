"""Classify MCP server subprocess startup failures."""

from __future__ import annotations

import re
from enum import StrEnum

from mcts.probe.errors import MCPProbeError

_IMPORT_RE = re.compile(r"ModuleNotFoundError:\s*No module named\s+['\"]?(\w+)", re.I)
_CREDENTIAL_RE = re.compile(
    r"(could not load credentials|credentials not found|sso|missing secret|SECRET_)",
    re.I,
)
_PROCESS_RE = re.compile(r"(ENOENT|Permission denied|No such file|command not found)", re.I)


class StartupCategory(StrEnum):
    IMPORT_ERROR = "import_error"
    MISSING_CREDENTIALS = "missing_credentials"
    PROCESS_EXIT = "process_exit"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


_CATEGORY_LABELS: dict[StartupCategory, str] = {
    StartupCategory.IMPORT_ERROR: "Python Import Error",
    StartupCategory.MISSING_CREDENTIALS: "Missing Credentials",
    StartupCategory.PROCESS_EXIT: "Process Exit / Command Error",
    StartupCategory.TIMEOUT: "Connection Timeout",
    StartupCategory.UNKNOWN: "Unknown Startup Failure",
}


class MCPStartupError(MCPProbeError):
    """Raised when the MCP server subprocess fails before handshake."""

    def __init__(
        self,
        message: str,
        *,
        category: StartupCategory,
        detected_line: str,
        suggestion: str,
        stderr_tail: list[str],
    ) -> None:
        super().__init__(message)
        self.category = category
        self.detected_line = detected_line
        self.suggestion = suggestion
        self.stderr_tail = stderr_tail

    @property
    def category_label(self) -> str:
        return _CATEGORY_LABELS[self.category]


def read_stderr_tail(path: str | None, *, max_lines: int = 50) -> list[str]:
    if not path:
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return []
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return lines[-max_lines:]


def classify_startup_failure(
    error_text: str,
    stderr_lines: list[str],
    *,
    command: str = "",
) -> MCPStartupError | None:
    """Return a structured startup error when stderr/error text matches known patterns."""
    combined = "\n".join(stderr_lines + [error_text])
    detected = ""
    category = StartupCategory.UNKNOWN
    suggestion = "Check server logs with --stderr-file PATH and verify --command / --args."

    for line in reversed(stderr_lines):
        match = _IMPORT_RE.search(line)
        if match:
            category = StartupCategory.IMPORT_ERROR
            detected = line.strip()
            mod = match.group(1)
            suggestion = (
                f"Use the project virtualenv interpreter, e.g. "
                f'--command .venv/bin/python --args "-m,{mod},..."'
            )
            break
        if _CREDENTIAL_RE.search(line):
            category = StartupCategory.MISSING_CREDENTIALS
            detected = line.strip()
            suggestion = (
                "Configure required secrets/SSO for this server, or run a static scan "
                "without --live: mcts scan path/to/bridge.py -o report.json"
            )
            break
        if _PROCESS_RE.search(line):
            category = StartupCategory.PROCESS_EXIT
            detected = line.strip()
            suggestion = f"Verify the launch command exists and is executable: {command or '(unknown)'}"
            break

    if category == StartupCategory.UNKNOWN:
        if _IMPORT_RE.search(combined):
            category = StartupCategory.IMPORT_ERROR
            detected = _IMPORT_RE.search(combined).group(0)  # type: ignore[union-attr]
            suggestion = "Use --command .venv/bin/python with the correct module args."
        elif "timed out" in error_text.lower() or "timeout" in error_text.lower():
            category = StartupCategory.TIMEOUT
            detected = error_text.strip()[:200]
            suggestion = "Increase --timeout or pass --stderr-file to capture server output."

    if category == StartupCategory.UNKNOWN and not stderr_lines and not error_text.strip():
        return None

    label = _CATEGORY_LABELS[category]
    message = (
        f"MCP server failed to start ({label}).\n"
        f"Detected: {detected or error_text[:200]}\n"
        f"Suggested fix: {suggestion}"
    )
    return MCPStartupError(
        message,
        category=category,
        detected_line=detected or error_text.strip()[:200],
        suggestion=suggestion,
        stderr_tail=stderr_lines,
    )
