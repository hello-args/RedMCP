"""Remove Sigma metadata findings superseded by other analyzers."""

from __future__ import annotations

from mcts.reporting.models import Finding

_METADATA_ANALYZERS = frozenset({"prompt_injection", "metadata_integrity", "schema_surface"})
_PATH_ANALYZERS = frozenset({"path_validation", "tool_abuse"})
_COMMAND_ANALYZERS = frozenset({"command_execution"})

_TPA_TECHNIQUES = frozenset(
    {
        "MCTS-T-1001",
        "MCTS-T-1021",
        "MCTS-T-1041",
        "MCTS-T-1001.002",
    }
)
_PATH_TECHNIQUES = frozenset({"MCTS-T-1002"})
_COMMAND_TECHNIQUES = frozenset({"MCTS-T-1023"})

_TEXT_CORPUS_MARKERS = ("description", ".name", "tool_name")


def dedupe_sigma_findings(findings: list[Finding]) -> list[Finding]:
    """Drop sigma_metadata hits already covered by primary analyzers on the same tool."""
    if not any(f.analyzer == "sigma_metadata" for f in findings):
        return findings

    tools_with_metadata = _tools_with_analyzer(findings, _METADATA_ANALYZERS)
    tools_with_path = _tools_with_analyzer(findings, _PATH_ANALYZERS)
    tools_with_command = _tools_with_analyzer(findings, _COMMAND_ANALYZERS)

    kept: list[Finding] = []
    for finding in findings:
        if finding.analyzer != "sigma_metadata":
            kept.append(finding)
            continue
        if _sigma_is_redundant(finding, tools_with_metadata, tools_with_path, tools_with_command):
            continue
        kept.append(finding)
    return kept


def _tools_with_analyzer(findings: list[Finding], analyzers: frozenset[str]) -> set[str]:
    return {f.tool for f in findings if f.analyzer in analyzers and f.tool}


def _sigma_is_redundant(
    finding: Finding,
    tools_with_metadata: set[str],
    tools_with_path: set[str],
    tools_with_command: set[str],
) -> bool:
    tool = finding.tool
    if not tool:
        return False

    rule_technique = finding.technique_id or ""
    corpus = str(finding.evidence.get("corpus_field", ""))

    if tool in tools_with_path and finding.analyzer == "sigma_metadata":
        return True

    if tool in tools_with_metadata:
        if rule_technique in _TPA_TECHNIQUES:
            return True
        if any(marker in corpus for marker in _TEXT_CORPUS_MARKERS):
            return True

    if tool in tools_with_path and rule_technique in _PATH_TECHNIQUES:
        return True

    return bool(tool in tools_with_command and rule_technique in _COMMAND_TECHNIQUES)
