"""Human-readable analyzer metadata for HTML dashboard cards."""

from __future__ import annotations

from typing import Any

# summary, what it inspects, primary technique IDs
ANALYZER_CATALOG: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "permission_analyzer": (
        "Flags destructive or privileged tool names and descriptions.",
        "Tool names/descriptions for delete, shell, admin, upload, and similar high-risk verbs.",
        ("MCTS-T-1006",),
    ),
    "surface_metadata": (
        "Scans prompts, resources, and server instructions for poisoning patterns.",
        "All MCP surfaces beyond tools — prompts, resources, system instructions.",
        ("MCTS-T-1001",),
    ),
    "metadata_integrity": (
        "Detects manipulative or poisoned tool metadata.",
        "Description length, hidden instructions, and template injection in tool text.",
        ("MCTS-T-1001",),
    ),
    "prompt_injection": (
        "Finds injection patterns in tool and surface metadata.",
        "Unicode tricks, homoglyphs, fake system delimiters, instruction-like payloads.",
        ("MCTS-T-1001",),
    ),
    "tool_shadowing": (
        "Detects tools that impersonate or hijack other tools.",
        "Duplicate or deceptive tool names within the same server.",
        ("MCTS-T-1020",),
    ),
    "line_jumping": (
        "Finds context precedence attacks in metadata.",
        "Fake system markers and delimiter tricks that override agent instructions.",
        ("MCTS-T-1021",),
    ),
    "tool_abuse": (
        "Checks file tools for path traversal exposure.",
        "Path parameters and file-read tools lacking traversal guards.",
        ("MCTS-T-1002",),
    ),
    "schema_surface": (
        "Analyzes JSON schemas for full schema poisoning (FSP).",
        "Schema fields, credential parameters, and unsafe defaults.",
        ("MCTS-T-1001.002",),
    ),
    "data_leakage": (
        "Hunts secrets and sensitive data in metadata and source.",
        "API keys, tokens, passwords in descriptions and handler code.",
        ("MCTS-T-1004",),
    ),
    "command_execution": (
        "Finds shell and code execution in tool handlers.",
        "subprocess, os.system, eval, exec, and similar calls in implementations.",
        ("MCTS-T-1003",),
    ),
    "path_validation": (
        "Checks whether file tools validate paths safely.",
        "Missing canonicalization, symlink checks, and jail roots on file paths.",
        ("MCTS-T-1002",),
    ),
    "runtime_events": (
        "Evaluates runtime telemetry for live attack patterns.",
        "50+ sub-detectors: rug-pull, injection, credential relay, flooding, etc.",
        ("MCTS-T-1023",),
    ),
    "sigma_metadata": (
        "Matches bundled Sigma rules against tool metadata.",
        "YAML rule corpus for known MCP metadata attack patterns.",
        ("MCTS-T-1010",),
    ),
    "oauth_config": (
        "Reviews OAuth and auth configuration posture.",
        "Broad scopes, typosquat issuers, rogue redirect patterns.",
        ("MCTS-T-1011",),
    ),
    "supply_chain": (
        "Heuristic supply-chain risk in dependencies and install paths.",
        "Unpinned deps, install scripts, floating container tags.",
        ("MCTS-T-1014",),
    ),
    "metadata_diff": (
        "Compares current metadata against a saved baseline.",
        "Rug-pull and drift — description or schema changes since baseline.",
        ("MCTS-T-1013", "MCTS-T-1040"),
    ),
    "embedding_secrets": (
        "Semantic detection of embedded credentials.",
        "High-entropy and semantic secret patterns beyond regex.",
        ("MCTS-T-1022",),
    ),
    "jailbreak": (
        "Measures manipulation resistance of the agent surface.",
        "Tools and prompts that weaken instruction boundaries.",
        ("MCTS-T-1007",),
    ),
    "cross_server": (
        "Finds tool name collisions across MCP client configs.",
        "Shadow tools that confuse agents across servers (requires inventory).",
        ("MCTS-T-1008",),
    ),
    "attack_chains": (
        "Builds multi-step attack paths from tool capabilities.",
        "Read → exfil, read → exec, and credential chain combinations.",
        ("MCTS-T-1005",),
    ),
    "prompt_defense": (
        "Checks for missing defensive language in prompts.",
        "System prompts lacking boundaries, confirmations, or scope limits.",
        ("MCTS-T-1001",),
    ),
    "behavioral_static": (
        "Compares tool descriptions to handler behavior.",
        "Description vs implementation mismatch and static taint flows.",
        ("MCTS-T-1001",),
    ),
    "vulnerable_package": (
        "Reports known CVEs from pip-audit.",
        "Python dependency vulnerabilities in the scan target.",
        ("MCTS-T-1014",),
    ),
    "npm_audit": (
        "Reports known CVEs from npm audit.",
        "JavaScript dependency vulnerabilities in the scan target.",
        ("MCTS-T-1014",),
    ),
    "yara_metadata": (
        "YARA pattern matching on tool metadata.",
        "Custom and bundled YARA rules on names and descriptions.",
        ("MCTS-T-1010",),
    ),
    "llm_judge": (
        "Opt-in LLM semantic review of metadata.",
        "Model-assisted review of suspicious descriptions (requires API key).",
        ("MCTS-T-1001",),
    ),
    "llm_metadata_triage": (
        "LLM triage of metadata as malicious, safe, or suspect.",
        "Semantic classification of tool and surface text.",
        ("MCTS-T-1001",),
    ),
    "semgrep_sast": (
        "Semgrep static analysis on server source code.",
        "Bundled Semgrep rules for MCP-relevant SAST patterns.",
        ("MCTS-T-1003",),
    ),
    "cloud_inspect": (
        "Cloud ML API inspection of scan artifacts.",
        "Optional cloud-side semantic analysis.",
        ("MCTS-T-1001",),
    ),
    "virustotal": (
        "VirusTotal hash lookup for binaries in scope.",
        "Known-malware signatures on discovered files.",
        ("MCTS-T-1038",),
    ),
    "toxic_flows": (
        "Cross-server toxic capability flows.",
        "Dangerous read/write chains across configured MCP servers.",
        ("MCTS-T-1005",),
    ),
    "compliance": (
        "OWASP LLM and MCP Top 10 coverage meta-checks.",
        "Framework coverage gaps — informational, not scored.",
        (),
    ),
    "live_discovery": (
        "Live probe discovery warnings and metadata.",
        "Tool discovery failures, partial lists, and probe errors.",
        (),
    ),
    "fuzz": (
        "Protocol fuzzing findings from MCP probes.",
        "Malformed requests, protocol violations, unexpected responses.",
        (),
    ),
    "skill_md": (
        "Security review of SKILL.md instruction files.",
        "Poisoning and excessive agency in agent skill definitions.",
        ("MCTS-T-1001",),
    ),
    "discovery_meta": (
        "Static discovery limitations and warnings.",
        "Scope gaps when tools could not be fully discovered.",
        (),
    ),
    "protocol_probe": (
        "HTTP/SSE protocol security probes.",
        "Transport and protocol-level MCP weaknesses (MCPS-001–009).",
        (),
    ),
}


def analyzer_info(name: str) -> dict[str, Any]:
    """Return dashboard metadata for an analyzer key."""
    entry = ANALYZER_CATALOG.get(name)
    if entry is None:
        label = name.replace("_", " ").title()
        return {
            "summary": f"{label} security check.",
            "looks_for": "Analyzer-specific patterns in the current scan scope.",
            "techniques": [],
        }
    summary, looks_for, techniques = entry
    return {
        "summary": summary,
        "looks_for": looks_for,
        "techniques": list(techniques),
    }
