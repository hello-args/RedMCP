"""Command injection detection in tool invocation parameters (MCTS-T-1023)."""

from __future__ import annotations

import json
import re
from typing import Any

METACHARACTERS: tuple[str, ...] = (
    ";",
    "|",
    "&&",
    "||",
    "$(",
    "`",
    "\n",
    "\r",
    ">",
    "<",
    ">>",
    "2>",
    "&",
)

SUSPICIOUS_COMMANDS: tuple[str, ...] = (
    "cat /etc/passwd",
    "cat /etc/shadow",
    "wget ",
    "curl ",
    "nc ",
    "ncat ",
    "/bin/bash",
    "/bin/sh",
    "cmd.exe",
    "powershell",
    "python -c",
    "perl -e",
    "ruby -e",
    "php -r",
    "chmod +x",
    "chmod 777",
    "rm -rf /",
    "mkfifo",
    "telnet ",
    "ssh-keygen",
    "net user",
)

ENCODED_PATTERNS: tuple[str, ...] = (
    "base64 -d",
    "base64 --decode",
    "iex(",
    "-encodedcommand",
)

REVERSE_SHELL_PATTERNS: tuple[str, ...] = (
    "/dev/tcp/",
    "/dev/udp/",
    "bash -i",
    "sh -i",
    "exec 5<>",
    "/inet/tcp/",
)

ENV_PATTERNS: tuple[str, ...] = (
    "$path",
    "$ld_preload",
    "$ld_library_path",
    "export ",
    "unset ",
    "env ",
)

PROCESS_DISCOVERY: tuple[str, ...] = (
    "ps aux",
    "ps -ef",
    "tasklist",
    "systeminfo",
    "uname -a",
    "whoami",
    "hostname",
    "ifconfig",
    "ip addr",
    "netstat",
    "ss -tulpn",
)

SSRF_PATTERNS: tuple[str, ...] = (
    "169.254.169.254",
    "metadata.google.internal",
)

OPTION_INJECTION = re.compile(
    r"(?:^|[\s\"'])(?:-[a-zA-Z]|--[a-zA-Z])",
)

LEGITIMATE_PATH = re.compile(r"^[a-zA-Z0-9/_.\-]+$")


def _parameter_blob(parameters: Any) -> str:
    if parameters is None:
        return ""
    if isinstance(parameters, str):
        return parameters
    try:
        return json.dumps(parameters)
    except TypeError:
        return str(parameters)


def detect_command_injection(
    *,
    tool_name: str,
    tool_parameters: Any,
) -> bool:
    """Return True when tool parameters match MCTS-T-1023 injection indicators."""
    blob = _parameter_blob(tool_parameters)
    if not blob:
        return False
    lowered = blob.lower()

    if (
        tool_name.startswith("git_")
        and not _contains_any(
            lowered,
            SUSPICIOUS_COMMANDS + ENCODED_PATTERNS + REVERSE_SHELL_PATTERNS + ENV_PATTERNS,
        )
        and not any(marker in blob for marker in (";", "|", "`", "$("))
    ):
        return False

    if tool_name.startswith("git_") and any(
        token in lowered for token in ("git config", "git log", "git status", "--oneline")
    ):
        return False

    if (
        LEGITIMATE_PATH.match(blob.strip('"'))
        and not any(marker in lowered for marker in SUSPICIOUS_COMMANDS)
        and not any(marker in blob for marker in METACHARACTERS)
    ):
        return False

    checks = (
        _contains_any(lowered, SUSPICIOUS_COMMANDS),
        _contains_any(lowered, ENCODED_PATTERNS),
        _contains_any(lowered, REVERSE_SHELL_PATTERNS),
        _contains_any(lowered, ENV_PATTERNS),
        _contains_any(lowered, PROCESS_DISCOVERY),
        _contains_any(lowered, SSRF_PATTERNS),
        bool(OPTION_INJECTION.search(blob)),
    )
    if any(checks):
        return True

    return any(marker in blob for marker in METACHARACTERS)


def _contains_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(pattern in text for pattern in patterns)
