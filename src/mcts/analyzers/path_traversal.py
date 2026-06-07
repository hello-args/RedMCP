"""Path traversal payload catalog and runtime path detection (MCTS-T-1002)."""

from __future__ import annotations

import re

FILE_TOOL_NAMES = frozenset(
    {
        "file_reader",
        "file_writer",
        "directory_browser",
        "file_manager",
        "read_file",
        "write_file",
        "list_directory",
    }
)

# Representative traversal and encoding variants from MCTS-T-1002 detection-rule.yml
TRAVERSAL_PAYLOADS: tuple[str, ...] = (
    "../../etc/passwd",
    "../../../.env",
    "~/.aws/credentials",
    "/etc/shadow",
    "../../../../../../etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%2fpasswd",
    "%c0%ae%c0%ae%2f%c0%ae%c0%ae%2f%c0%ae%c0%ae%2fetc%2fpasswd",
    "../../../../.ssh/id_rsa",
    "../config/.env",
    "../../../etc/passwd%00",
    "..%2F..%2F..%2Fetc%2Fshadow",
)

SENSITIVE_PATH_TARGETS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/shadow",
    "/.ssh/id_rsa",
    "/.env",
    "/config.json",
    "/secrets.yaml",
    "/credentials",
)

_TRAVERSAL_SIGMA_PATTERNS: tuple[str, ...] = (
    r".*\.\./.*",
    r".*\\\.\.\\.*",
    r".*\.\.%2f.*",
    r".*%2e%2e%2f.*",
    r".*%252e%252e%252f.*",
    r".*%252e%252e%5c.*",
    r".*%c0%ae%c0%ae.*",
    r".*%c0%ae%c0%ae%2f.*",
    r".*%c0%ae%c0%ae%5c.*",
    r".*\.\.%2f\.\.%2f.*",
    r".*%2e%2e%2f%2e%2e%2f.*",
    r".*%00.*",
    r".*\.\./.*%00.*",
    r".*\.\.%2F.*",
    r".*%2E%2E%2F.*",
    r".*%2e%2E%2f.*",
)

_SENSITIVE_SIGMA_PATTERNS: tuple[str, ...] = (
    r".*/etc/passwd.*",
    r".*/etc/shadow.*",
    r".*/etc/hosts.*",
    r".*/etc/ssh.*",
    r".*/proc/.*",
    r".*/sys/.*",
    r".*/\.ssh/id_rsa.*",
    r".*/\.ssh/id_rsa\.pub.*",
    r".*/\.ssh/known_hosts.*",
    r".*/\.ssh/config.*",
    r".*/\.env.*",
    r".*/config\.json.*",
    r".*/secrets\.yaml.*",
    r".*/database\.yml.*",
    r".*/credentials.*",
    r".*/home/.*/\.bash_history.*",
    r".*/home/.*/\.profile.*",
    r".*/root/\.bash_history.*",
    r".*/root/\.profile.*",
)

_LEGITIMATE_PATH_FILTERS: tuple[str, ...] = (
    r".*/src/.*",
    r".*/docs/.*",
    r".*/tests/.*",
    r".*/config/app/.*",
    r".*/data/legitimate/.*",
    r".*/uploads/approved/.*",
    r".*/config/app/database\.yml.*",
)


def _matches_any_pattern(value: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, value, re.IGNORECASE) for pattern in patterns)


def is_file_tool_name(tool_name: str) -> bool:
    return tool_name in FILE_TOOL_NAMES


def is_traversal_path(path: str) -> bool:
    """Return True when a path matches MCTS-T-1002 traversal or sensitive targets."""
    if not path:
        return False
    normalized = path.replace("\\", "/")
    if normalized in {"config/app/database.yml", "config/app/settings.json"}:
        return False
    if _matches_any_pattern(normalized, _LEGITIMATE_PATH_FILTERS):
        return False
    return _matches_any_pattern(normalized, _TRAVERSAL_SIGMA_PATTERNS) or _matches_any_pattern(
        normalized, _SENSITIVE_SIGMA_PATTERNS
    )


def detect_path_traversal_event(
    *,
    tool_name: str,
    path: str,
    result: str | None = None,
    treat_blocked_as_benign: bool = True,
) -> bool:
    """Detect path traversal in MCP file-access log events (MCTS-T-1002 parity shape)."""
    if not is_file_tool_name(tool_name):
        return False
    if treat_blocked_as_benign and result == "error":
        return False
    return is_traversal_path(path)
