#!/usr/bin/env python3
"""Compile MCTS Sigma YAML fixtures into metadata_rules.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcts.taxonomy.sigma.loader import MetadataSigmaRule

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "tests" / "fixtures" / "sigma_fixtures"
DEFAULT_OUTPUT = ROOT / "src" / "mcts" / "taxonomy" / "sigma" / "metadata_rules.json"

_SKIP_TAGS = frozenset({"saf-mcp", "safemcp", "mcts-mcp"})


def _sanitize_rule_row(row: dict) -> dict:
    tags: list[str] = []
    for tag in row.get("tags", []):
        lowered = str(tag).lower()
        if lowered in _SKIP_TAGS or lowered.startswith("saf-t") or lowered.startswith("safe.t"):
            continue
        tags.append(str(tag))
    row["tags"] = tags

    rule_id = str(row.get("rule_id", ""))
    if rule_id.startswith("saf-"):
        row["rule_id"] = "mcts-" + rule_id[4:]

    technique_id = str(row.get("technique_id", ""))
    if technique_id.startswith("SAF-T"):
        row["technique_id"] = "MCTS-S-" + technique_id.split("-T", 1)[1]

    title = str(row.get("title", ""))
    for prefix in ("SAF-T", "SAF-"):
        title = title.replace(prefix, "MCTS-")
    row["title"] = title
    return row


def rules_to_json(rules: list[MetadataSigmaRule]) -> str:
    payload = [
        _sanitize_rule_row(
            {
                "technique_id": rule.technique_id,
                "rule_id": rule.rule_id,
                "title": rule.title,
                "level": rule.level,
                "tags": list(rule.tags),
                "patterns": [{"field": field, "pattern": pattern} for field, pattern in rule.patterns],
            }
        )
        for rule in rules
    ]
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def compile_rules(source: Path, *, merge_bundled: bool = True) -> list[MetadataSigmaRule]:
    from mcts.taxonomy.sigma.loader import _dedupe_rules, _load_bundled_rules, _load_rules_from_directory

    compiled = _load_rules_from_directory(source)
    if merge_bundled:
        compiled = _dedupe_rules(_load_bundled_rules() + compiled)
    return _dedupe_rules(compiled)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when output would change",
    )
    parser.add_argument(
        "--no-merge-bundled",
        action="store_true",
        help="Compile only from source YAML, do not merge existing bundled rules",
    )
    parser.add_argument(
        "--validate-min",
        type=int,
        default=0,
        help="Exit non-zero when fewer than N rules compile from source",
    )
    args = parser.parse_args()

    if not args.source.exists():
        print(f"Sigma source directory missing: {args.source}", file=sys.stderr)
        return 1

    compiled = compile_rules(args.source, merge_bundled=not args.no_merge_bundled)
    if args.validate_min and len(compiled) < args.validate_min:
        print(
            f"Expected at least {args.validate_min} rules, compiled {len(compiled)}",
            file=sys.stderr,
        )
        return 1

    rendered = rules_to_json(compiled)
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if current != rendered:
            print(f"Sigma bundle out of date: {args.output}", file=sys.stderr)
            return 1
        print(f"Sigma bundle OK ({len(compiled)} rules)")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"Wrote {len(compiled)} rules to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
