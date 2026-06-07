"""Sigma wildcard pattern matching for static metadata scans."""

from __future__ import annotations

import contextlib
import re


def convert_sigma_pattern_to_regex(pattern: str) -> str:
    """Convert a Sigma wildcard pattern to a case-insensitive regex."""
    if "\\u" in pattern:
        with contextlib.suppress(UnicodeDecodeError):
            pattern = pattern.encode("utf-8").decode("unicode_escape")

    escaped = re.escape(pattern)
    return escaped.replace(r"\*", ".*")


def match_sigma_pattern(value: str, pattern: str) -> bool:
    if not is_substantive_pattern(pattern):
        return False
    regex = convert_sigma_pattern_to_regex(pattern)
    return bool(re.search(regex, value, re.IGNORECASE | re.DOTALL))


def is_substantive_pattern(pattern: str) -> bool:
    """Ignore catch-all Sigma wildcards unsuitable for static metadata scans."""
    core = pattern.replace("*", "").replace("?", "").strip()
    if pattern in {"*", "**", "*.*"}:
        return False
    return len(core) >= 3
