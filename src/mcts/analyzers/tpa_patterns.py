"""Shared TPA / metadata poisoning patterns (aligned with MCTS-T-1001, MCTS-T-1041, MCTS-T-1001.002)."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from mcts.reporting.models import Severity

INVISIBLE_CHAR_PATTERN = re.compile(r"[\u200b-\u200f\ufeff\u202a-\u202e\u2060-\u206f\u206a-\u206f]")

# Cyrillic homoglyphs that visually mimic Latin letters (MCTS-T-1001 PoC values only)
_HOMOGLYPH_CHARS = frozenset("аАсСеЕоОрРхХуУвВнНкКмМтТ")

_UNICODE_TAG_RANGE = range(0xE0000, 0xE0080)

_TEMPLATE_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("html_system_comment", re.compile(r"<!--\s*SYSTEM:", re.I), Severity.CRITICAL),
    ("system_tag", re.compile(r"<\|system\|>", re.I), Severity.CRITICAL),
    ("inst_marker", re.compile(r"\[INST\]", re.I), Severity.CRITICAL),
    ("system_bracket", re.compile(r"\[SYSTEM:", re.I), Severity.CRITICAL),
    ("instruction_header", re.compile(r"### Instruction:", re.I), Severity.CRITICAL),
    ("system_header", re.compile(r"### System:", re.I), Severity.HIGH),
]

_POISON_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    (
        "instruction_override",
        re.compile(r"(?i)\b(ignore (all )?(previous|prior) instructions|disregard (the )?system)\b"),
        Severity.CRITICAL,
    ),
    (
        "credential_request",
        re.compile(r"(?i)\b(read|load|fetch|send|upload).{0,40}(mcp\.json|\.env|id_rsa|credentials)\b"),
        Severity.CRITICAL,
    ),
    (
        "hidden_system_prompt",
        re.compile(r"(?i)\b(system prompt|hidden prompt|developer message)\b"),
        Severity.HIGH,
    ),
    (
        "authority_claim",
        re.compile(r"(?i)\b(you are (now )?an? (admin|root|unrestricted|superuser))\b"),
        Severity.HIGH,
    ),
]

_DANGEROUS_DEFAULT = re.compile(r"(?i)(drop|delete|exec|system|\.\./|/\.\.)")

SUSPICIOUS_SCHEMA_DEFAULTS = re.compile(r"(?i)(admin|root|/\.\.|https?://|0\.0\.0\.0|\*)")


def has_unicode_tags(text: str) -> bool:
    return any(chr(codepoint) in text for codepoint in _UNICODE_TAG_RANGE)


def has_control_chars(text: str) -> bool:
    """Detect Cc/Cf control/format characters excluding common whitespace."""
    for char in text:
        if char in "\t\n\r":
            continue
        category = unicodedata.category(char)
        if category in {"Cc", "Cf"}:
            return True
    return False


def find_control_chars(text: str) -> list[str]:
    found: list[str] = []
    for char in text:
        if char in "\t\n\r":
            continue
        category = unicodedata.category(char)
        if category in {"Cc", "Cf"}:
            found.append(f"U+{ord(char):04X}")
    return found


def has_hidden_unicode(text: str) -> bool:
    return bool(INVISIBLE_CHAR_PATTERN.search(text)) or has_unicode_tags(text) or has_control_chars(text)


def find_homoglyphs(text: str) -> list[str]:
    return [char for char in text if char in _HOMOGLYPH_CHARS]


def has_mixed_scripts(text: str) -> bool:
    scripts: set[str] = set()
    for char in text:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        if name:
            scripts.add(name.split()[0])
    return len(scripts) > 1


def scan_text_templates(text: str) -> list[tuple[str, Severity]]:
    hits: list[tuple[str, Severity]] = []
    for label, pattern, severity in _TEMPLATE_PATTERNS:
        if pattern.search(text):
            hits.append((label, severity))
    return hits


def scan_text_poison(text: str) -> list[tuple[str, Severity]]:
    hits: list[tuple[str, Severity]] = []
    for label, pattern, severity in _POISON_PATTERNS:
        if pattern.search(text):
            hits.append((label, severity))
    return hits


def scan_schema_surface(schema: Any, path: str = "inputSchema") -> list[tuple[str, str, Severity]]:
    """Recursively scan JSON schema fields for FSP / poisoning indicators."""
    if not isinstance(schema, dict):
        return []

    hits: list[tuple[str, str, Severity]] = []

    default = schema.get("default")
    if default is not None and _DANGEROUS_DEFAULT.search(str(default)):
        hits.append(("suspicious_default", path, Severity.CRITICAL))

    for index, enum_val in enumerate(schema.get("enum", [])):
        enum_hits = scan_text_poison(str(enum_val)) + scan_text_templates(str(enum_val))
        for label, severity in enum_hits:
            hits.append((f"enum_{label}", f"{path}.enum[{index}]", severity))

    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        for prop_name, prop_schema in properties.items():
            prop_path = f"{path}.properties.{prop_name}"
            for label, severity in scan_text_poison(prop_name):
                hits.append((f"param_name_{label}", prop_path, severity))
            for label, severity in scan_text_templates(prop_name):
                hits.append((f"param_name_{label}", prop_path, severity))

            if isinstance(prop_schema, dict):
                description = prop_schema.get("description", "")
                if isinstance(description, str):
                    for label, severity in scan_text_poison(description):
                        hits.append((label, f"{prop_path}.description", severity))
                    for label, severity in scan_text_templates(description):
                        hits.append((label, f"{prop_path}.description", severity))
                hits.extend(scan_schema_surface(prop_schema, prop_path))

    return hits
