"""Transform ScanReport models into dashboard JSON payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from mcts.compliance.checks import MCP_ANALYZER_MAP, OWASP_LLM_ANALYZER_MAP, OWASP_MCP_TOP10
from mcts.mcp.models import CapabilityProfile
from mcts.report.analyzer_catalog import analyzer_info
from mcts.report.scan_meta import tool_discovery_context
from mcts.reporting.models import Finding, ScanReport, ScanSummary, Severity, SourceLocation
from mcts.scoring.engine import RISK_WEIGHTS
from mcts.taxonomy.mapper import technique_catalog
from mcts.taxonomy.mitigation_urls import mitigation_links, technique_url

CAPABILITY_DIMS: tuple[tuple[str, str], ...] = (
    ("reads_untrusted_input", "Reads Input"),
    ("accesses_sensitive_data", "Sensitive Data"),
    ("mutates_state", "Mutates State"),
    ("egresses_network", "Network Egress"),
    ("executes_commands", "Executes Commands"),
)

SCAN_SCOPE_LABELS: dict[str, str] = {
    "repository": "Static repository",
    "entrypoint": "Entrypoint static",
    "live": "Live probe",
    "snapshot": "Snapshot",
}


def _llm_owasp_catalog() -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Build LLM Top 10 catalog from compliance analyzer map."""
    grouped: dict[str, tuple[str, set[str]]] = {}
    for analyzer, full_label in OWASP_LLM_ANALYZER_MAP.items():
        owasp_id = full_label.split()[0]
        short_label = full_label[len(owasp_id) + 1 :]
        if owasp_id not in grouped:
            grouped[owasp_id] = (short_label, set())
        grouped[owasp_id][1].add(analyzer)
    return tuple(
        (owasp_id, grouped[owasp_id][0], tuple(sorted(grouped[owasp_id][1])))
        for owasp_id in sorted(grouped.keys())
    )


OWASP_CATALOG = _llm_owasp_catalog()

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
    "live_discovery": "Live Discovery",
    "surface_metadata": "Surface Metadata",
    "prompt_defense": "Prompt Defense",
    "behavioral_static": "Behavioral Static",
    "embedding_secrets": "Embedding Secrets",
    "runtime_events": "Runtime Events",
    "vulnerable_package": "Vulnerable Packages",
    "npm_audit": "npm Audit",
    "semgrep_sast": "Semgrep SAST",
    "llm_metadata_triage": "LLM Metadata Triage",
    "llm_judge": "LLM Judge",
    "toxic_flows": "Toxic Flows",
    "tool_shadowing": "Tool Shadowing",
    "line_jumping": "Line Jumping",
    "yara_metadata": "YARA Metadata",
    "skill_md": "Skill / Instruction Files",
    "cloud_inspect": "Cloud Inspect",
    "virustotal": "VirusTotal",
    "protocol_probe": "Protocol Probe",
    "discovery_meta": "Discovery Metadata",
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


def format_location(location: SourceLocation | None) -> str:
    """Human-readable file:line for dashboard tables."""
    if location is None:
        return "—"
    if location.line is not None:
        return f"{location.file}:{location.line}"
    return location.file


def format_confidence(confidence: float) -> str:
    pct = round(confidence * 100)
    return f"{pct}%"


def format_evidence_summary(evidence: dict[str, Any]) -> str:
    """One-line preview for findings table."""
    if not evidence:
        return ""
    parts: list[str] = []
    for key in ("rule_id", "matched", "missing_mcp_categories", "read_tools", "exfil_tools"):
        if key in evidence and evidence[key]:
            value = evidence[key]
            if isinstance(value, list):
                text = ", ".join(str(item) for item in value[:3])
                if len(value) > 3:
                    text += f" (+{len(value) - 3})"
            else:
                text = str(value)
            parts.append(f"{key}: {text}")
    if parts:
        return "; ".join(parts)
    return f"{len(evidence)} field(s)"


def owasp_ids_for_analyzer(analyzer: str) -> list[str]:
    full = OWASP_LLM_ANALYZER_MAP.get(analyzer)
    if full:
        return [full.split()[0]]
    return [oid for oid, _, names in OWASP_CATALOG if analyzer in names]


def _mcp_catalog() -> tuple[tuple[str, str, str, tuple[str, ...]], ...]:
    """MCP Top 10 rows: (id, short label, full label, mapped analyzers)."""
    rows: list[tuple[str, str, str, tuple[str, ...]]] = []
    for full_label in OWASP_MCP_TOP10:
        mcp_id = full_label.split()[0]
        short_label = full_label[len(mcp_id) + 1 :]
        analyzers = tuple(
            analyzer for analyzer, category in MCP_ANALYZER_MAP.items() if category == full_label
        )
        rows.append((mcp_id, short_label, full_label, analyzers))
    return tuple(rows)


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


def _append_passed_checks_summary(
    paragraphs: list[str],
    *,
    analyzers_executed: list[str],
    analyzer_results: list[dict[str, Any]],
) -> None:
    if not analyzers_executed or not analyzer_results:
        return
    passed = sum(1 for row in analyzer_results if row.get("status") == "passed")
    total = len(analyzer_results)
    if passed <= 0:
        return
    lead = f"{passed} of {total} security analyzers completed with no findings."
    if paragraphs and lead in paragraphs[0]:
        return
    paragraphs.insert(0, lead)


def _finding_risk_points(finding: Finding) -> int:
    return RISK_WEIGHTS[finding.severity]


def category_scores(findings: list[Finding]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, label, maximum, analyzers in CATEGORY_DEFS:
        matched = [f for f in findings if f.analyzer in analyzers]
        points = sum(_finding_risk_points(f) for f in matched)
        score = min(maximum, points)
        passed = len(matched) == 0
        rows.append(
            {
                "key": key,
                "label": label,
                "maximum": maximum,
                "score": score,
                "display": "Passed" if passed else f"{score}/{maximum}",
                "findings_count": len(matched),
                "passed": passed,
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
    """Backward-compatible list of LLM categories with findings only."""
    return [row for row in llm_owasp_mappings(findings)["categories"] if row["status"] == "findings"]


def llm_owasp_mappings(findings: list[Finding]) -> dict[str, Any]:
    """OWASP LLM Top 10 coverage — mirrors compliance meta-findings."""
    scorable = [f for f in findings if f.analyzer != "compliance"]
    covered = {OWASP_LLM_ANALYZER_MAP[f.analyzer] for f in scorable if f.analyzer in OWASP_LLM_ANALYZER_MAP}
    expected = set(OWASP_LLM_ANALYZER_MAP.values())
    missing = sorted(expected - covered)

    for finding in findings:
        if finding.analyzer != "compliance":
            continue
        evidence = finding.evidence
        if evidence.get("owasp_llm_gaps"):
            missing = sorted(evidence["owasp_llm_gaps"])
            break

    rows: list[dict[str, Any]] = []
    for owasp_id, label, analyzers in OWASP_CATALOG:
        full_label = next(
            (value for value in OWASP_LLM_ANALYZER_MAP.values() if value.startswith(owasp_id)),
            f"{owasp_id} {label}",
        )
        matched = [f for f in scorable if f.analyzer in analyzers]
        if matched:
            max_sev = min(SEVERITY_ORDER[f.severity] for f in matched)
            severity = next(s for s in Severity if SEVERITY_ORDER[s] == max_sev)
            affected: set[str] = set()
            for finding in matched:
                if finding.tool:
                    affected.add(finding.tool)
            rows.append(
                {
                    "id": owasp_id,
                    "label": label,
                    "full_label": full_label,
                    "status": "findings",
                    "finding_count": len(matched),
                    "risk_level": severity.value,
                    "affected_tools": sorted(affected),
                }
            )
        elif scorable and full_label in missing:
            rows.append(
                {
                    "id": owasp_id,
                    "label": label,
                    "full_label": full_label,
                    "status": "gap",
                    "finding_count": 0,
                    "risk_level": "low",
                    "affected_tools": [],
                }
            )

    rows.sort(key=lambda r: (0 if r["status"] == "findings" else 1, -r["finding_count"], r["id"]))
    return {
        "categories": rows,
        "gaps": missing,
        "gap_count": len(missing),
        "has_scorable_findings": bool(scorable),
    }


def mcp_owasp_mappings(findings: list[Finding]) -> dict[str, Any]:
    """OWASP MCP Top 10 coverage — mirrors compliance meta-findings."""
    scorable = [f for f in findings if f.analyzer != "compliance"]
    covered = {MCP_ANALYZER_MAP[f.analyzer] for f in scorable if f.analyzer in MCP_ANALYZER_MAP}
    missing = sorted(set(OWASP_MCP_TOP10) - covered)

    for finding in findings:
        if finding.analyzer != "compliance":
            continue
        evidence = finding.evidence
        if evidence.get("missing_mcp_categories"):
            missing = sorted(evidence["missing_mcp_categories"])
            break
        if evidence.get("owasp_mcp_gaps"):
            missing = sorted(evidence["owasp_mcp_gaps"])
            break

    rows: list[dict[str, Any]] = []
    for mcp_id, short_label, full_label, analyzers in _mcp_catalog():
        matched = [f for f in scorable if f.analyzer in analyzers]
        if matched:
            max_sev = min(SEVERITY_ORDER[f.severity] for f in matched)
            severity = next(s for s in Severity if SEVERITY_ORDER[s] == max_sev)
            affected: set[str] = set()
            for finding in matched:
                if finding.tool:
                    affected.add(finding.tool)
            rows.append(
                {
                    "id": mcp_id,
                    "label": short_label,
                    "full_label": full_label,
                    "status": "findings",
                    "finding_count": len(matched),
                    "risk_level": severity.value,
                    "affected_tools": sorted(affected),
                }
            )
        elif scorable and full_label in missing:
            rows.append(
                {
                    "id": mcp_id,
                    "label": short_label,
                    "full_label": full_label,
                    "status": "gap",
                    "finding_count": 0,
                    "risk_level": "low",
                    "affected_tools": [],
                }
            )

    rows.sort(key=lambda r: (0 if r["status"] == "findings" else 1, -r["finding_count"], r["id"]))
    return {
        "categories": rows,
        "gaps": missing,
        "gap_count": len(missing),
        "has_scorable_findings": bool(scorable),
    }


def build_capability_matrix(report: ScanReport) -> dict[str, Any]:
    """Tool × capability grid from inferred CapabilityProfile."""
    tools: list[dict[str, Any]] = []
    for tool in report.server.tools:
        cap = tool.capability or CapabilityProfile()
        tools.append(
            {
                "name": tool.name,
                "description": tool.description,
                "flags": {key: bool(getattr(cap, key)) for key, _ in CAPABILITY_DIMS},
            }
        )
    return {
        "dimensions": [{"key": key, "label": label} for key, label in CAPABILITY_DIMS],
        "tools": tools,
        "tool_count": len(tools),
    }


def build_technique_map(findings: list[Finding]) -> dict[str, Any]:
    """Full MCTS-T catalog annotated with finding counts from this scan."""
    by_technique: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.analyzer == "compliance" or not finding.technique_id:
            continue
        by_technique.setdefault(finding.technique_id, []).append(finding)

    rows: list[dict[str, Any]] = []
    for entry in technique_catalog():
        tech_id = entry["id"]
        matched = by_technique.get(tech_id, [])
        row: dict[str, Any] = {
            **entry,
            "technique_url": technique_url(tech_id),
            "finding_count": len(matched),
            "status": "detected" if matched else "clear",
        }
        if matched:
            max_sev = min(SEVERITY_ORDER[f.severity] for f in matched)
            severity = next(s for s in Severity if SEVERITY_ORDER[s] == max_sev)
            row["risk_level"] = severity.value
        else:
            row["risk_level"] = None
        rows.append(row)

    catalog_ids = {entry["id"] for entry in technique_catalog()}
    for tech_id, matched in sorted(by_technique.items()):
        if tech_id in catalog_ids:
            continue
        max_sev = min(SEVERITY_ORDER[f.severity] for f in matched)
        severity = next(s for s in Severity if SEVERITY_ORDER[s] == max_sev)
        rows.append(
            {
                "id": tech_id,
                "name": tech_id,
                "tactic": None,
                "owasp": None,
                "cwe": matched[0].cwe_id,
                "analyzers": sorted({f.analyzer for f in matched}),
                "technique_url": technique_url(tech_id),
                "finding_count": len(matched),
                "status": "detected",
                "risk_level": severity.value,
            }
        )

    rows.sort(key=lambda r: (0 if r["finding_count"] else 1, -r["finding_count"], r["id"]))
    detected_count = sum(1 for row in rows if row["finding_count"] > 0)
    return {
        "techniques": rows,
        "total": len(rows),
        "detected_count": detected_count,
        "clear_count": len(rows) - detected_count,
    }


def analyzer_summaries(findings: list[Finding]) -> list[dict[str, Any]]:
    """Backward-compatible wrapper — only analyzers with findings."""
    executed = sorted({f.analyzer for f in findings})
    return build_analyzer_results(findings, executed)


def _enrich_analyzer_row(
    name: str,
    items: list[Finding],
    *,
    status: str,
    report: ScanReport | None = None,
) -> dict[str, Any]:
    counts = {s.value: 0 for s in Severity}
    for item in items:
        counts[item.severity.value] += 1
    info = analyzer_info(name)
    llm_full = OWASP_LLM_ANALYZER_MAP.get(name)
    mcp_full = MCP_ANALYZER_MAP.get(name)
    scope_bits: list[str] = []
    if report is not None:
        scope_bits.append(
            SCAN_SCOPE_LABELS.get(report.scan_scope, report.scan_scope.replace("_", " ").title())
        )
        tool_count = len(report.server.tools)
        scope_bits.append(f"{tool_count} tool{'s' if tool_count != 1 else ''}")
    scope_text = ", ".join(scope_bits) if scope_bits else "current scan scope"
    passed_note = (
        f"No issues matched this check's patterns ({scope_text}). "
        "A pass lowers risk in this area but does not prove the server is fully secure — "
        "try --live, broader surfaces, or optional analyzers for deeper coverage."
    )
    return {
        "name": name,
        "label": ANALYZER_LABELS.get(name, name.replace("_", " ").title()),
        "status": status,
        "finding_count": len(items),
        "severity_counts": counts,
        "summary": info["summary"],
        "looks_for": info["looks_for"],
        "techniques": info["techniques"],
        "technique_urls": [
            {"id": tid, "url": technique_url(tid)} for tid in info["techniques"] if technique_url(tid)
        ],
        "owasp_llm": llm_full.split()[0] if llm_full else None,
        "owasp_mcp": mcp_full.split()[0] if mcp_full else None,
        "passed_note": passed_note if status == "passed" else None,
        "finding_titles": [f.title for f in sort_findings(items)[:5]],
    }


def build_analyzer_results(
    findings: list[Finding],
    executed: list[str],
    *,
    report: ScanReport | None = None,
) -> list[dict[str, Any]]:
    """Full analyzer roster with passed vs issues status for HTML dashboard."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.analyzer, []).append(finding)

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in executed:
        if name in seen:
            continue
        seen.add(name)
        items = grouped.get(name, [])
        rows.append(
            _enrich_analyzer_row(
                name,
                items,
                status="passed" if not items else "issues",
                report=report,
            )
        )

    for name, items in sorted(grouped.items()):
        if name in seen:
            continue
        rows.append(_enrich_analyzer_row(name, items, status="issues", report=report))

    rows.sort(key=lambda row: (0 if row["status"] == "issues" else 1, row["label"]))
    return rows


def build_checks_summary(
    analyzer_results: list[dict[str, Any]],
    categories: list[dict[str, Any]],
) -> dict[str, int]:
    analyzers_passed = sum(1 for row in analyzer_results if row.get("status") == "passed")
    categories_passed = sum(1 for row in categories if row.get("passed"))
    return {
        "analyzers_run": len(analyzer_results),
        "analyzers_passed": analyzers_passed,
        "analyzers_with_findings": len(analyzer_results) - analyzers_passed,
        "categories_total": len(categories),
        "categories_passed": categories_passed,
        "categories_with_findings": len(categories) - categories_passed,
    }


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
    if report.scan_history:
        return list(report.scan_history)
    from mcts.output.history import trend_points_for_target

    points = trend_points_for_target(report.target)
    if points:
        return points
    label = report.scanned_at.strftime("%b %d")
    return [{"date": label, "score": report.score.overall}]


def trend_meta(report: ScanReport, points: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [int(row.get("score", 0)) for row in points]
    unique_scores = sorted(set(scores))
    return {
        "runs": len(points),
        "unique_scores": len(unique_scores),
        "latest_score": scores[-1] if scores else report.score.overall,
        "score_unchanged": len(unique_scores) <= 1 and len(points) > 1,
    }


def build_dashboard_payload(report: ScanReport) -> dict[str, Any]:
    scanned_at: datetime = report.scanned_at
    badge, level = risk_rating(report.score.overall)
    executed = list(report.analyzers_executed) or sorted({f.analyzer for f in report.findings})
    analyzer_results = build_analyzer_results(report.findings, executed, report=report)
    categories = category_scores(report.findings)
    checks_summary = build_checks_summary(analyzer_results, categories)
    analyzers_run = checks_summary["analyzers_run"] or max(len({f.analyzer for f in report.findings}), 6)
    executive = build_executive_summary(report.findings, report.summary)
    _append_passed_checks_summary(
        executive["paragraphs"],
        analyzers_executed=executed,
        analyzer_results=analyzer_results,
    )

    findings_rows = []
    for finding in sort_findings(report.findings):
        owasp_ids = owasp_ids_for_analyzer(finding.analyzer)
        tid = finding.technique_id
        evidence = finding.evidence or {}
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
                "location": format_location(finding.location),
                "cwe_id": finding.cwe_id or "—",
                "confidence": finding.confidence,
                "confidence_display": format_confidence(finding.confidence),
                "evidence": evidence,
                "evidence_summary": format_evidence_summary(evidence),
                "has_evidence": bool(evidence),
                "recommendation": finding.recommendation,
                "technique_id": tid or "—",
                "technique_url": technique_url(tid) if tid else None,
                "mitigation_links": mitigation_links(finding.mitigation_ids),
            }
        )

    live = report.scan_scope == "live"
    snapshot = report.scan_scope == "snapshot"
    tool_ctx = tool_discovery_context(report, live=live, snapshot=snapshot)
    breakdown_payload = None
    if report.score_breakdown is not None:
        breakdown_payload = report.score_breakdown.model_dump()

    trend_points = score_trend(report)
    scope_label = SCAN_SCOPE_LABELS.get(
        report.scan_scope,
        report.scan_scope.replace("_", " ").title(),
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
            "scan_scope": report.scan_scope,
            "scan_scope_label": scope_label,
            "tool_discovery_notice": report.tool_discovery_notice,
        },
        "scan_notes": list(report.scan_notes),
        "tool_discovery": tool_ctx,
        "score": {
            "overall": report.score.overall,
            "risk_index": report.score.risk_index,
            "raw_risk": report.score.raw_risk,
            "basis": report.score.basis.model_dump(),
            "grade": security_grade(report.score.overall),
            "breakdown": breakdown_payload,
        },
        "summary": report.summary.model_dump(),
        "risk": {
            "badge": badge,
            "level": level,
            "description": risk_description(report.score.overall),
            "brief": _score_brief(report.score.overall),
        },
        "executive_summary": executive,
        "checks_summary": checks_summary,
        "score_help": {
            "title": "Score derived from:",
            "items": [
                "Security points from 0–100 (not a percentage of tests passed)",
                "Critical, High, Medium, and Low findings (severity-weighted)",
                "Attack chain detections",
                "Exponential decay: more severe findings lower the score",
            ],
        },
        "categories": categories,
        "trend": trend_points,
        "trend_meta": trend_meta(report, trend_points),
        "findings": findings_rows,
        "tools": [{"name": t.name, "description": t.description} for t in report.server.tools],
        "analyzers": analyzer_results,
        "attack_graph": build_attack_graph(report),
        "owasp": llm_owasp_mappings(report.findings),
        "owasp_mcp": mcp_owasp_mappings(report.findings),
        "technique_map": build_technique_map(report.findings),
        "capability_matrix": build_capability_matrix(report),
        "recommendations": build_recommendations(report.findings),
        "techniques": technique_catalog(),
        "risk_guide": list(RISK_GUIDE),
        "raw_report": report.model_dump(mode="json"),
    }
