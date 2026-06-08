"""Map analyzer findings to MCTS-T technique and mitigation IDs."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from mcts.reporting.models import Finding

_TECHNIQUES_PATH = Path(__file__).with_name("techniques.json")
_CROSSWALK_PATH = Path(__file__).with_name("crosswalk.json")


@lru_cache(maxsize=1)
def load_crosswalk() -> dict[str, Any]:
    if not _CROSSWALK_PATH.exists():
        return {}
    return json.loads(_CROSSWALK_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_taxonomy() -> dict[str, Any]:
    if not _TECHNIQUES_PATH.exists():
        return {"techniques": {}, "mitigations": {}}
    return json.loads(_TECHNIQUES_PATH.read_text(encoding="utf-8"))


def enrich_finding(finding: Finding) -> Finding:
    """Attach technique_id, cwe_id, and mitigation_ids when missing."""
    taxonomy = load_taxonomy()
    techniques: dict[str, Any] = taxonomy.get("techniques", {})
    mitigations: dict[str, Any] = taxonomy.get("mitigations", {})

    if finding.technique_id is None:
        for tech_id, meta in techniques.items():
            if finding.analyzer in meta.get("analyzers", []):
                finding.technique_id = tech_id
                if finding.cwe_id is None and meta.get("cwe"):
                    finding.cwe_id = meta["cwe"]
                break

    if not finding.mitigation_ids and finding.technique_id:
        finding.mitigation_ids = [
            mid for mid, meta in mitigations.items() if finding.technique_id in meta.get("techniques", [])
        ]

    crosswalk = load_crosswalk()
    if finding.technique_id and finding.technique_id in crosswalk:
        entry = crosswalk[finding.technique_id]
        if finding.evidence is None:
            finding.evidence = {}
        finding.evidence.setdefault("aitech", entry.get("aitech"))
        finding.evidence.setdefault("aisubtech", entry.get("aisubtech"))
        finding.evidence.setdefault("saf_mcp", entry.get("saf_mcp"))

    return finding


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    return [enrich_finding(f) for f in findings]


def technique_catalog() -> list[dict[str, Any]]:
    taxonomy = load_taxonomy()
    rows: list[dict[str, Any]] = []
    for tech_id, meta in taxonomy.get("techniques", {}).items():
        rows.append(
            {
                "id": tech_id,
                "name": meta.get("name", tech_id),
                "tactic": meta.get("tactic"),
                "owasp": meta.get("owasp"),
                "cwe": meta.get("cwe"),
                "analyzers": meta.get("analyzers", []),
            }
        )
    rows.sort(key=lambda row: row["id"])
    return rows
