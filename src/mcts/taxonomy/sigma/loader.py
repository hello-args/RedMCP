"""Load MCTS Sigma rules applicable to static metadata scanning."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from mcts.taxonomy.sigma.matcher import is_substantive_pattern

_BUNDLED_RULES = Path(__file__).with_name("metadata_rules.json")

METADATA_FIELDS = frozenset(
    {
        "tool_description",
        "description",
        "tool_name",
        "name",
        "path",
        "query",
        "command",
        "url",
        "message",
        "filename",
        "file",
    }
)


@dataclass(frozen=True)
class MetadataSigmaRule:
    technique_id: str
    rule_id: str
    title: str
    level: str
    tags: tuple[str, ...] = field(default_factory=tuple)
    patterns: tuple[tuple[str, str], ...] = field(default_factory=tuple)


def load_metadata_rules(extra_root: Path | None = None) -> list[MetadataSigmaRule]:
    rules = _load_bundled_rules()
    if extra_root is not None:
        rules.extend(_load_rules_from_directory(extra_root))
    return _dedupe_rules(rules)


@lru_cache(maxsize=4)
def _load_bundled_rules_cached(extra_root_str: str | None) -> tuple[MetadataSigmaRule, ...]:
    extra = Path(extra_root_str) if extra_root_str else None
    return tuple(_dedupe_rules(_load_bundled_rules() + (_load_rules_from_directory(extra) if extra else [])))


def cached_metadata_rules(extra_root: Path | None = None) -> list[MetadataSigmaRule]:
    return list(_load_bundled_rules_cached(str(extra_root) if extra_root else None))


def _load_bundled_rules() -> list[MetadataSigmaRule]:
    if not _BUNDLED_RULES.exists():
        return []
    payload = json.loads(_BUNDLED_RULES.read_text(encoding="utf-8"))
    return [_rule_from_dict(row) for row in payload if isinstance(row, dict)]


def _load_rules_from_directory(root: Path) -> list[MetadataSigmaRule]:
    if not root.exists():
        return []

    rules: list[MetadataSigmaRule] = []
    search_roots = [root]
    if root.name == "techniques" or any(root.glob("MCTS-T*/detection-rule.yml")):
        search_roots = [root]
    elif (root / "techniques").exists():
        search_roots = [root / "techniques"]

    for base in search_roots:
        for rule_path in sorted(base.glob("MCTS-T*/detection-rule.yml")):
            rules.extend(_parse_rule_file(rule_path))
    return rules


def _parse_rule_file(rule_path: Path) -> list[MetadataSigmaRule]:
    technique_id = rule_path.parent.name
    text = rule_path.read_text(encoding="utf-8")
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return []

    parsed: list[MetadataSigmaRule] = []
    for doc in documents:
        if not isinstance(doc, dict):
            continue
        patterns = _extract_patterns(doc.get("detection") or {})
        if not patterns:
            continue
        parsed.append(
            MetadataSigmaRule(
                technique_id=technique_id,
                rule_id=str(doc.get("id", technique_id)),
                title=str(doc.get("title", technique_id)),
                level=str(doc.get("level", "medium")),
                tags=tuple(str(tag) for tag in (doc.get("tags") or []) if isinstance(tag, str)),
                patterns=tuple(patterns),
            )
        )
    return parsed


def _extract_patterns(detection: dict[str, Any]) -> list[tuple[str, str]]:
    patterns: list[tuple[str, str]] = []
    for key, val in detection.items():
        if key == "condition" or key.startswith("filter"):
            continue
        if not isinstance(val, dict):
            continue
        for meta_field, pats in val.items():
            base_field = meta_field.split("|")[0]
            if base_field not in METADATA_FIELDS:
                continue
            if isinstance(pats, str):
                patterns.append((base_field, pats))
            elif isinstance(pats, list):
                for item in pats:
                    if isinstance(item, str):
                        patterns.append((base_field, item))
    return [(field, pattern) for field, pattern in patterns if is_substantive_pattern(pattern)]


def _rule_from_dict(row: dict[str, Any]) -> MetadataSigmaRule:
    patterns = [
        (str(item["field"]), str(item["pattern"]))
        for item in row.get("patterns", [])
        if isinstance(item, dict)
        and "field" in item
        and "pattern" in item
        and is_substantive_pattern(str(item["pattern"]))
    ]
    return MetadataSigmaRule(
        technique_id=str(row.get("technique_id", "MCTS-T-0000")),
        rule_id=str(row.get("rule_id", row.get("technique_id", "unknown"))),
        title=str(row.get("title", "Sigma rule")),
        level=str(row.get("level", "medium")),
        tags=tuple(str(tag) for tag in row.get("tags", [])),
        patterns=tuple(patterns),
    )


def _dedupe_rules(rules: list[MetadataSigmaRule]) -> list[MetadataSigmaRule]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[MetadataSigmaRule] = []
    for rule in rules:
        key = (rule.technique_id, rule.rule_id, rule.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(rule)
    return unique
