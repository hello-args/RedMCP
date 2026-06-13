"""SARIF 2.1.0 report generation."""

from __future__ import annotations

from typing import Any

from mcts.reporting.display import effective_impact, effective_severity
from mcts.reporting.models import Finding, ScanReport, Severity
from mcts.taxonomy.mapper import load_taxonomy

MCTS_TAXONOMY_NAME = "MCTS"
MCTS_TAXONOMY_GUID = "7c4e9f2a-1b3d-4e5f-9a8b-0c1d2e3f4a5b"

SARIF_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# GitHub Code Scanning expects numeric strings in the 0.1–10.0 range on rule properties.
SARIF_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}


def write_sarif_report(report: ScanReport) -> str:
    """Serialize a scan report as SARIF 2.1.0 JSON."""
    import json

    payload = build_sarif(report)
    return json.dumps(payload, indent=2)


def build_sarif(report: ScanReport) -> dict[str, Any]:
    rules = _build_rules(report.findings)
    results = [_finding_to_result(finding, rules, report.target) for finding in report.findings]
    taxonomies = _build_taxonomies(report.findings)

    driver: dict[str, Any] = {
        "name": "MCTS",
        "informationUri": "https://github.com/MCP-Audit/MCTS",
        "version": report.version,
        "rules": list(rules.values()),
    }
    if taxonomies:
        driver["supportedTaxonomies"] = [{"name": MCTS_TAXONOMY_NAME, "guid": MCTS_TAXONOMY_GUID}]

    run_props: dict[str, Any] = {
        "target": report.target,
        "securityScore": report.score.overall,
        "riskIndex": report.score.risk_index,
        "mcts/scanMode": report.scan_scope,
    }
    if report.scan_notes:
        run_props["mcts/scanNotes"] = list(report.scan_notes)
    if report.score_breakdown is not None:
        run_props["mcts/scoreBreakdown"] = report.score_breakdown.model_dump()
    if report.tool_discovery_notice:
        run_props["mcts/toolDiscoveryNotice"] = report.tool_discovery_notice
    if report.score_v2 is not None:
        run_props["mcts/scoreV2"] = {
            "absoluteRisk": report.score_v2.absolute_risk,
            "securityScore": report.score_v2.security_score,
            "riskLevel": report.score_v2.risk_level,
        }

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
        "properties": run_props,
    }
    if taxonomies:
        run["taxonomies"] = taxonomies

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def _build_taxonomies(findings: list[Finding]) -> list[dict[str, Any]]:
    taxonomy = load_taxonomy()
    techniques: dict[str, Any] = taxonomy.get("techniques", {})
    seen: set[str] = set()
    taxa: list[dict[str, Any]] = []

    for finding in findings:
        if not finding.technique_id or finding.technique_id in seen:
            continue
        seen.add(finding.technique_id)
        meta = techniques.get(finding.technique_id, {})
        name = meta.get("name", finding.technique_id)
        taxa.append(
            {
                "id": finding.technique_id,
                "name": name,
                "shortDescription": {"text": name},
            }
        )

    if not taxa:
        return []

    return [
        {
            "name": MCTS_TAXONOMY_NAME,
            "guid": MCTS_TAXONOMY_GUID,
            "informationUri": "https://github.com/MCP-Audit/MCTS",
            "taxa": taxa,
        }
    ]


def _taxonomy_reference(taxon_id: str) -> dict[str, Any]:
    return {
        "id": taxon_id,
        "toolComponent": {"name": MCTS_TAXONOMY_NAME, "guid": MCTS_TAXONOMY_GUID},
    }


def _sarif_security_severity(finding: Finding) -> str:
    """Align GitHub security-severity with display when trust adjusted severity is set."""
    if finding.display_severity is not None:
        return SARIF_SECURITY_SEVERITY[effective_severity(finding)]
    return SARIF_SECURITY_SEVERITY[effective_impact(finding)]


def _build_rules(findings: list[Finding]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rule_id = finding.id
        if rule_id in rules:
            continue
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "helpUri": "https://github.com/MCP-Audit/MCTS",
            "properties": {
                "analyzer": finding.analyzer,
                "technique_id": finding.technique_id,
                "security-severity": _sarif_security_severity(finding),
            },
        }
    return rules


def _finding_to_result(finding: Finding, rules: dict[str, dict[str, Any]], target: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": SARIF_SEVERITY[effective_severity(finding)],
        "message": {"text": finding.description},
        "locations": [_result_location(finding, target)],
        "properties": {
            "severity": finding.severity.value,
            "display_severity": effective_severity(finding).value,
            "analyzer": finding.analyzer,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence,
        },
    }
    if finding.evidence_type:
        result["properties"]["evidence_type"] = finding.evidence_type
    evidence = finding.evidence or {}
    facts = evidence.get("facts")
    if isinstance(facts, list) and facts:
        result["properties"]["mcts/factCount"] = len(facts)
        result["properties"]["mcts/facts"] = facts[:5]
    factors = evidence.get("confidence_factors")
    if isinstance(factors, list) and factors:
        result["properties"]["mcts/confidenceFactors"] = factors
    if finding.rule_stability:
        result["properties"]["mcts/ruleStability"] = finding.rule_stability
    taxa = _result_taxa(finding)
    if taxa:
        result["taxa"] = taxa
    attack_tags = finding.evidence.get("attack_tags")
    if isinstance(attack_tags, list) and attack_tags:
        result["properties"]["attack_tags"] = [str(tag) for tag in attack_tags if isinstance(tag, str)]
    if finding.tool:
        result["properties"]["tool"] = finding.tool
    if finding.technique_id:
        result["properties"]["technique_id"] = finding.technique_id
    if finding.mitigation_ids:
        result["properties"]["mitigation_ids"] = finding.mitigation_ids
    if finding.id not in rules:
        rules[finding.id] = {
            "id": finding.id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "properties": {
                "security-severity": _sarif_security_severity(finding),
            },
        }
    return result


def _result_location(finding: Finding, target: str) -> dict[str, Any]:
    if finding.location and finding.location.file:
        uri = finding.location.file
        line = finding.location.line or 1
    else:
        uri = target
        line = 1
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line},
        }
    }


def _result_taxa(finding: Finding) -> list[dict[str, Any]]:
    if not finding.technique_id:
        return []
    return [_taxonomy_reference(finding.technique_id)]
