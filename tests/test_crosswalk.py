"""SAF-MCP / AITech crosswalk coverage tests."""

from __future__ import annotations

from mcts.reporting.models import Finding, Severity
from mcts.taxonomy.mapper import enrich_finding, load_crosswalk, load_taxonomy


def test_crosswalk_covers_all_mcts_techniques() -> None:
    taxonomy = load_taxonomy()
    crosswalk = load_crosswalk()
    technique_ids = set(taxonomy.get("techniques", {}))
    assert technique_ids
    assert technique_ids.issubset(set(crosswalk))
    for tech_id, entry in crosswalk.items():
        assert entry.get("saf_mcp", "").startswith("SAF-T"), tech_id
        assert entry.get("aitech"), tech_id


def test_enrich_finding_attaches_saf_mcp_id() -> None:
    finding = Finding(
        id="test-1",
        analyzer="prompt_injection",
        title="Test",
        description="Test",
        severity=Severity.HIGH,
        recommendation="Fix",
        technique_id="MCTS-T-1001",
    )
    enriched = enrich_finding(finding)
    assert enriched.evidence.get("saf_mcp") == "SAF-T1001"
    assert enriched.evidence.get("aitech") == "AITech-PAI"
