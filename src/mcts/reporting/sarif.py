"""SARIF 2.1.0 report generation."""

from __future__ import annotations

from typing import Any

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

SARIF_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
}


def write_sarif_report(report: ScanReport) -> str:
    """Serialize a scan report as SARIF 2.1.0 JSON."""
    import json

    payload = build_sarif(report)
    return json.dumps(payload, indent=2)


def build_sarif(report: ScanReport) -> dict[str, Any]:
    rules = _build_rules(report.findings)
    results = [_finding_to_result(finding, rules) for finding in report.findings]
    taxonomies = _build_taxonomies(report.findings)

    driver: dict[str, Any] = {
        "name": "MCTS",
        "informationUri": "https://github.com/MCP-Audit/MCTS",
        "version": report.version,
        "rules": list(rules.values()),
    }
    if taxonomies:
        driver["supportedTaxonomies"] = [
            {"name": MCTS_TAXONOMY_NAME, "guid": MCTS_TAXONOMY_GUID}
        ]

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
        "properties": {
            "target": report.target,
            "securityScore": report.score.overall,
            "riskIndex": report.score.risk_index,
        },
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
            },
        }
    return rules


def _finding_to_result(finding: Finding, rules: dict[str, dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": SARIF_SEVERITY[finding.severity],
        "message": {"text": finding.description},
        "properties": {
            "severity": finding.severity.value,
            "security-severity": SARIF_SECURITY_SEVERITY[finding.severity],
            "analyzer": finding.analyzer,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence,
        },
    }
    taxa = _result_taxa(finding)
    if taxa:
        result["taxa"] = taxa
    attack_tags = finding.evidence.get("attack_tags")
    if isinstance(attack_tags, list) and attack_tags:
        result["properties"]["attack_tags"] = [
            str(tag) for tag in attack_tags if isinstance(tag, str)
        ]
    if finding.tool:
        result["properties"]["tool"] = finding.tool
    if finding.technique_id:
        result["properties"]["technique_id"] = finding.technique_id
    if finding.mitigation_ids:
        result["properties"]["mitigation_ids"] = finding.mitigation_ids
    if finding.location:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.file},
                    "region": {"startLine": finding.location.line or 1},
                }
            }
        ]
    if finding.id not in rules:
        rules[finding.id] = {
            "id": finding.id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
        }
    return result


def _result_taxa(finding: Finding) -> list[dict[str, Any]]:
    if not finding.technique_id:
        return []
    return [_taxonomy_reference(finding.technique_id)]
