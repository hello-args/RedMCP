"""Prompt injection in MCP tool outputs (MCTS-T-1007)."""

from __future__ import annotations

import re

from mcts.analyzers.tpa_patterns import has_hidden_unicode

_OUTPUT_PATTERNS = (
    "system:",
    "<!-- system",
    "[system]",
    "###system###",
    "ignore previous instructions",
    "disregard all prior",
    "forget everything above",
    "override system prompt",
    "###assistant:",
    "[inst]",
    "<|im_start|>",
    "</data>system",
    '"}*{"*system',
)

_TAG_RE = re.compile(r"(?i)(system\s*:|ignore\s+previous|override\s+system)")


def detect_tool_output_injection(*, tool_output: str = "", tool_name: str = "") -> bool:
    """Detect MCTS-T-1007 indicators in tool response content."""
    del tool_name
    text = tool_output or ""
    if not text.strip():
        return False
    lowered = text.lower()
    if has_hidden_unicode(text):
        return True
    if _TAG_RE.search(text):
        return True
    return any(pattern in lowered for pattern in _OUTPUT_PATTERNS)
