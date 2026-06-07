"""Transform ScanReport models into dashboard JSON payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from mcts.reporting.models import Finding, ScanReport, ScanSummary, Severity
from mcts.scoring.engine import RISK_WEIGHTS
from mcts.taxonomy.mapper import technique_catalog
from mcts.taxonomy.mitigation_urls import mitigation_links, technique_url

OWASP_CATALOG: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "LLM01",
        "Prompt Injection",
        ("prompt_injection", "metadata_integrity", "schema_surface", "cross_server"),
    ),
    ("LLM02", "Sensitive Information Disclosure", ("data_leakage", "path_validation")),
    ("LLM04", "Model Denial of Service", ("tool_abuse",)),
    (
        "LLM06",
        "Excessive Agency",
        ("attack_chains", "permission_analyzer", "command_execution", "compliance"),
    ),
    ("LLM07", "System Prompt Leakage", ("jailbreak",)),
)

CATEGORY_DEFS: tuple[tuple[str, str, int, tuple[str, ...]], ...] = (
    ("permissions", "Excessive Permissions", 20, ("permission_analyzer",)),
    ("injection", "Injection & Metadata", 20, ("prompt_injection", "metadata_integrity", "schema_surface")),
    ("execution", "Execution & Path Risk", 15, ("command_execution", "path_validation", "tool_abuse")),
    ("data_leakage", "Data Leakage Risk", 15, ("data_leakage",)),
    ("attack_chains", "Attack Chain Risk", 15, ("attack_chains",)),
    ("shadowing", "Cross-Server Shadowing", 5, ("cross_server",)),
    ("jailbreak", "Jailbreak Resistance", 10, ("jailbreak",)),
)

ANALYZER_LABELS: dict[str, str] = {
    "permission_analyzer": "Permission Analyzer",
    "prompt_injection": "Prompt Injection",
    "tool_abuse": "Tool Abuse",
    "data_leakage": "Data Leakage",
    "schema_surface": "Schema Surface",
    "command_execution": "Command Execution",
    "path_validation": "Path Validation",
    "metadata_integrity": "Metadata Integrity",
    "cross_server": "Cross-Server Shadowing",
    "jailbreak": "Jailbreak",
    "attack_chains": "Attack Chains",
    "fuzz": "Protocol Fuzzing",
    "compliance": "Compliance",
    "sigma_metadata": "Sigma Metadata Rules",
    "oauth_config": "OAuth Configuration",
    "metadata_diff": "Metadata Baseline Diff",
    "supply_chain": "Supply Chain",
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

INDUSTRY_BENCHMARK: dict[str, float] = {
    "permissions": 8,
    "injection": 6,
    "execution": 5,
    "data_leakage": 5,
    "attack_chains": 4,
    "shadowing": 2,
    "jailbreak": 3,
}

RISK_GUIDE = (
    {
        "key": "critical",
        "label": "Critical",
        "range": "0–25",
        "badge": "CRITICAL RISK",
        "color": "#ef4444",
        "description": "Immediate remediation required. Severe exposure to exploitation.",
    },
    {
        "key": "high",
        "label": "High",
        "range": "26–50",
        "badge": "HIGH RISK",
        "color": "#f97316",
        "description": "Significant weaknesses present. Prioritize fixes this sprint.",
    },
    {
        "key": "medium",
        "label": "Medium",
        "range": "51–75",
        "badge": "MEDIUM RISK",
        "color": "#facc15",
        "description": "Moderate risk posture. Schedule hardening within 30 days.",
    },
    {
        "key": "low",
        "label": "Low",
        "range": "76–100",
        "badge": "LOW RISK",
        "color": "#22c55e",
        "description": "Strong security posture. Maintain monitoring and regression scans.",
    },
)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.title))


def risk_rating(score: int) -> tuple[str, str]:
    if score <= 25:
        return "CRITICAL RISK", "critical"
    if score <= 50:
        return "HIGH RISK", "high"
    if score <= 75:
        return "MEDIUM RISK", "medium"
    return "LOW RISK", "low"


def _score_brief(score: int) -> str:
    if score <= 25:
        return "Critical security posture detected"
    if score <= 50:
        return "Elevated risk — urgent remediation advised"
    if score <= 75:
        return "Moderate risk — schedule hardening activities"
    return "Strong security posture maintained"


def risk_description(score: int) -> str:
    if score <= 25:
        return "Your MCP server has critical security issues that require immediate attention."
    if score <= 50:
        return "Your MCP server has high-severity issues that should be remediated urgently."
    if score <= 75:
        return "Your MCP server has moderate security gaps worth addressing soon."
    return "Your MCP server shows a strong security posture with minor or no issues."


def security_grade(score: int) -> dict[str, str]:
    """Letter grade and posture label for executive reporting."""
    if score >= 90:
        return {"letter": "A", "label": "Excellent", "posture": "Low Risk"}
    if score >= 80:
        return {"letter": "B", "label": "Good", "posture": "Low Risk"}
    if score >= 70:
        return {"letter": "C", "label": "Fair", "posture": "Medium Risk"}
    if score >= 60:
        return {"letter": "D", "label": "Poor", "posture": "High Risk"}
    return {"letter": "F", "label": "Critical", "posture": "Critical"}


def build_executive_summary(findings: list[Finding], summary: ScanSummary) -> dict[str, Any]:
    """Executive narrative and prioritized actions derived from findings."""
    paragraphs: list[str] = []
    bullets: list[str] = []

    chain_findings = [f for f in findings if f.analyzer == "attack_chains"]
    if chain_findings:
        paragraphs.append("Critical attack chains were detected.")
    elif summary.critical:
        paragraphs.append("Critical-severity findings require immediate remediation.")

    shell_findings = [
        f
        for f in findings
        if (f.tool and "shell" in f.tool.lower())
        or "shell" in f.title.lower()
        or "run_shell" in (f.tool or "")
    ]
    if shell_findings:
        paragraphs.append("Multiple tools enable arbitrary command execution on the host.")

    exfil_findings = [
        f
        for f in findings
        if "exfil" in f.title.lower() or "webhook" in f.title.lower() or "send_webhook" in (f.tool or "")
    ]
    if exfil_findings or any("exfil_tools" in f.evidence for f in findings if f.analyzer == "attack_chains"):
        paragraphs.append("Sensitive data exfiltration paths were identified.")

    file_findings = [
        f
        for f in findings
        if f.analyzer in ("tool_abuse", "permission_analyzer")
        and ("file" in f.title.lower() or "path" in f.title.lower() or "read" in f.title.lower())
    ]
    if file_findings:
        paragraphs.append("File and environment access controls are insufficiently restricted.")

    if not paragraphs:
        if summary.total == 0:
            paragraphs.append("No significant security issues were detected in this scan.")
        else:
            paragraphs.append(f"The scan identified {summary.total} finding(s) across severity levels.")

    recs = build_recommendations(findings)
    action_map = [
        ("shell", "Remove unrestricted shell access"),
        ("exfil", "Restrict outbound requests and webhook egress"),
        ("webhook", "Restrict outbound requests and webhook egress"),
        ("path", "Harden file access controls and path validation"),
        ("traversal", "Harden file access controls and path validation"),
        ("destructive", "Require confirmation for destructive operations"),
        ("credential", "Block credential tools from autonomous agent access"),
        ("injection", "Sanitize tool inputs and enforce instruction boundaries"),
    ]
    seen_bullets: set[str] = set()
    for rec in recs:
        text = rec["recommendation"]
        if text not in seen_bullets and len(bullets) < 5:
            seen_bullets.add(text)
            bullets.append(text)
    for _keyword, action in action_map:
        if len(bullets) >= 3:
            break
        if action in seen_bullets:
            continue
        if any(_keyword in f.title.lower() or _keyword in f.recommendation.lower() for f in findings):
            bullets.append(action)
            seen_bullets.add(action)

    if not bullets and recs:
        bullets = [r["recommendation"] for r in recs[:3]]

    return {"paragraphs": paragraphs, "recommended": bullets[:3]}


def _finding_risk_points(finding: Finding) -> int:
    return RISK_WEIGHTS[finding.severity]


def category_scores(findings: list[Finding]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, label, maximum, analyzers in CATEGORY_DEFS:
        matched = [f for f in findings if f.analyzer in analyzers]
        points = sum(_finding_risk_points(f) for f in matched)
        score = min(maximum, points)
        rows.append(
            {
                "key": key,
                "label": label,
                "maximum": maximum,
                "score": score,
                "display": f"{score}/{maximum}",
                "findings_count": len(matched),
                "benchmark": INDUSTRY_BENCHMARK.get(key, 0),
            }
        )
    return rows


def category_gate_keys() -> frozenset[str]:
    return frozenset(key for key, _, _, _ in CATEGORY_DEFS)


def parse_category_gates(raw_values: list[str] | None) -> dict[str, int]:
    """Parse `--fail-on-category permissions:10` style thresholds."""
    gates: dict[str, int] = {}
    if not raw_values:
        return gates
    valid = category_gate_keys()
    for raw in raw_values:
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if ":" not in part:
                raise ValueError(f"Invalid --fail-on-category value {part!r}. Use category:max_score.")
            category, limit_text = part.split(":", 1)
            category = category.strip()
            if category not in valid:
                valid_list = ", ".join(sorted(valid))
                raise ValueError(f"Unknown category {category!r}. Valid categories: {valid_list}")
            limit = int(limit_text.strip())
            if limit < 0:
                raise ValueError(f"Category limit must be >= 0, got {limit}")
            gates[category] = limit
    return gates


def category_gate_failures(findings: list[Finding], gates: dict[str, int]) -> list[str]:
    """Return human-readable failures when a category score meets/exceeds its gate."""
    if not gates:
        return []
    by_key = {row["key"]: row for row in category_scores(findings)}
    failures: list[str] = []
    for category, limit in gates.items():
        row = by_key.get(category)
        if not row:
            continue
        if row["score"] >= limit:
            failures.append(f"{row['label']} scored {row['display']} (limit {limit})")
    return failures


def owasp_mappings(findings: list[Finding]) -> list[dict[str, Any]]:
    tools_by_analyzer: dict[str, set[str]] = {}
    for finding in findings:
        tools_by_analyzer.setdefault(finding.analyzer, set())
        if finding.tool:
            tools_by_analyzer[finding.analyzer].add(finding.tool)

    rows: list[dict[str, Any]] = []
    for owasp_id, label, analyzers in OWASP_CATALOG:
        matched = [f for f in findings if f.analyzer in analyzers]
        if not matched:
            continue
        max_sev = min(SEVERITY_ORDER[f.severity] for f in matched)
        severity = next(s for s in Severity if SEVERITY_ORDER[s] == max_sev)
        affected: set[str] = set()
        for f in matched:
            if f.tool:
                affected.add(f.tool)
        rows.append(
            {
                "id": owasp_id,
                "label": label,
                "finding_count": len(matched),
                "risk_level": severity.value,
                "affected_tools": sorted(affected),
            }
        )
    rows.sort(key=lambda r: (-r["finding_count"], r["id"]))
    return rows


def analyzer_summaries(findings: list[Finding]) -> list[dict[str, Any]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.analyzer, []).append(finding)

    rows: list[dict[str, Any]] = []
    for name, items in sorted(grouped.items()):
        counts = {s.value: 0 for s in Severity}
        for item in items:
            counts[item.severity.value] += 1
        rows.append(
            {
                "name": name,
                "label": ANALYZER_LABELS.get(name, name.replace("_", " ").title()),
                "finding_count": len(items),
                "severity_counts": counts,
            }
        )
    return rows


def build_recommendations(findings: list[Finding]) -> list[dict[str, Any]]:
    priority_map = {
        Severity.CRITICAL: "P1",
        Severity.HIGH: "P2",
        Severity.MEDIUM: "P3",
        Severity.LOW: "P4",
    }
    effort_map = {
        Severity.CRITICAL: "High",
        Severity.HIGH: "Medium",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
    }
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for finding in sort_findings(findings):
        key = finding.recommendation.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "priority": priority_map[finding.severity],
                "title": finding.title,
                "recommendation": finding.recommendation,
                "impact": finding.severity.value.title(),
                "effort": effort_map[finding.severity],
                "analyzer": finding.analyzer,
                "tool": finding.tool,
                "mitigation_links": mitigation_links(finding.mitigation_ids),
                "technique_url": technique_url(finding.technique_id) if finding.technique_id else None,
            }
        )
    return rows


def build_attack_graph(report: ScanReport) -> dict[str, Any]:
    if report.attack_graph.get("edges") or report.attack_graph.get("nodes"):
        return report.attack_graph

    nodes: dict[str, dict[str, str]] = {}
    edges: list[dict[str, str]] = []

    for tool in report.server.tools:
        nodes[tool.name] = {"id": tool.name, "label": tool.name, "type": "tool"}

    for finding in report.findings:
        if finding.analyzer != "attack_chains":
            continue
        evidence = finding.evidence
        read_tools = evidence.get("read_tools", [])
        exfil_tools = evidence.get("exfil_tools", [])
        cred_tools = evidence.get("credential_tools", [])
        exec_tools = evidence.get("exec_tools", [])

        for name in read_tools + exfil_tools + cred_tools + exec_tools:
            nodes[name] = {"id": name, "label": name, "type": "tool"}

        for src in read_tools:
            for dst in exfil_tools:
                edges.append({"from": src, "to": dst, "label": "exfil"})
        for src in cred_tools:
            for dst in exfil_tools:
                edges.append({"from": src, "to": dst, "label": "credential → exfil"})
        for src in read_tools:
            for dst in cred_tools:
                edges.append({"from": src, "to": dst, "label": "read → cred"})
        for src in read_tools:
            for dst in exec_tools:
                edges.append({"from": src, "to": dst, "label": "read → exec"})

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
    }


def score_trend(report: ScanReport) -> list[dict[str, Any]]:
    label = report.scanned_at.strftime("%b %d")
    return [{"date": label, "score": report.score.overall}]


def build_dashboard_payload(report: ScanReport) -> dict[str, Any]:
    scanned_at: datetime = report.scanned_at
    badge, level = risk_rating(report.score.overall)
    analyzers = {f.analyzer for f in report.findings}
    analyzers_run = max(len(analyzers), 6)

    findings_rows = []
    for finding in sort_findings(report.findings):
        owasp_ids = [oid for oid, _, names in OWASP_CATALOG if finding.analyzer in names]
        findings_rows.append(
            {
                "id": finding.id,
                "severity": finding.severity.value,
                "title": finding.title,
                "description": finding.description,
                "category": ANALYZER_LABELS.get(finding.analyzer, finding.analyzer),
                "analyzer": finding.analyzer,
                "owasp": ", ".join(owasp_ids) if owasp_ids else "—",
                "tool": finding.tool or "—",
                "recommendation": finding.recommendation,
                "technique_id": finding.technique_id or "—",
                "technique_url": technique_url(finding.technique_id) if finding.technique_id else None,
                "mitigation_links": mitigation_links(finding.mitigation_ids),
                "cwe_id": finding.cwe_id or "—",
            }
        )

    return {
        "meta": {
            "version": report.version,
            "target": report.target,
            "scanned_at": scanned_at.isoformat(),
            "scan_date": scanned_at.strftime("%Y-%m-%d"),
            "scan_time": scanned_at.strftime("%H:%M:%S UTC"),
            "tools_discovered": len(report.server.tools),
            "analyzers_run": analyzers_run,
            "server_name": report.server.name,
        },
        "score": {
            "overall": report.score.overall,
            "risk_index": report.score.risk_index,
            "raw_risk": report.score.raw_risk,
            "basis": report.score.basis.model_dump(),
            "grade": security_grade(report.score.overall),
        },
        "summary": report.summary.model_dump(),
        "risk": {
            "badge": badge,
            "level": level,
            "description": risk_description(report.score.overall),
            "brief": _score_brief(report.score.overall),
        },
        "executive_summary": build_executive_summary(report.findings, report.summary),
        "score_help": {
            "title": "Score derived from:",
            "items": [
                "Critical, High, Medium, and Low findings (severity-weighted)",
                "Attack chain detections",
                "OWASP LLM risk mapping",
                "Exponential decay: higher raw risk lowers the security score",
            ],
        },
        "categories": category_scores(report.findings),
        "trend": score_trend(report),
        "findings": findings_rows,
        "tools": [{"name": t.name, "description": t.description} for t in report.server.tools],
        "analyzers": analyzer_summaries(report.findings),
        "attack_graph": build_attack_graph(report),
        "owasp": owasp_mappings(report.findings),
        "recommendations": build_recommendations(report.findings),
        "techniques": technique_catalog(),
        "risk_guide": list(RISK_GUIDE),
        "raw_report": report.model_dump(mode="json"),
    }
