"""Runtime telemetry analyzers wired into the main scan pipeline."""

from __future__ import annotations

from typing import Any

from mcts.analyzers.autonomous_loop import detect_autonomous_loop_event
from mcts.analyzers.backdoored_install import detect_backdoored_install_event
from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.behavioral_extraction import detect_behavioral_extraction
from mcts.analyzers.command_injection import detect_command_injection
from mcts.analyzers.context_memory_implant import detect_context_memory_implant
from mcts.analyzers.credential_access import detect_credential_file_access
from mcts.analyzers.cross_server_registry import detect_cross_server_shadowing
from mcts.analyzers.dns_poisoning import detect_dns_poisoning_event
from mcts.analyzers.exposed_endpoint import detect_exposed_endpoint
from mcts.analyzers.fake_tool_invocation import detect_fake_tool_invocation
from mcts.analyzers.inspector_rce import detect_inspector_rce_event
from mcts.analyzers.instruction_steganography import detect_instruction_steganography
from mcts.analyzers.oauth_escalation_runtime import (
    detect_confused_deputy_event,
    detect_rogue_as_event,
    detect_scope_substitution_event,
)
from mcts.analyzers.oauth_mixup import detect_oauth_mixup_event
from mcts.analyzers.oauth_token_persistence import detect_oauth_token_persistence_event
from mcts.analyzers.over_privileged import detect_over_privileged_process
from mcts.analyzers.privilege_tool_abuse import detect_privilege_tool_abuse
from mcts.analyzers.rug_pull import detect_rug_pull_event
from mcts.analyzers.sampling_abuse import detect_sampling_abuse
from mcts.analyzers.sandbox_escape import detect_sandbox_escape
from mcts.analyzers.suspicious_registration import detect_suspicious_tool_registration
from mcts.analyzers.tool_output_injection import detect_tool_output_injection
from mcts.analyzers.tool_redefinition import (
    detect_tool_definition_file_event,
    detect_tool_redefinition_baseline,
)
from mcts.analyzers.vector_poisoning import detect_vector_poisoning
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity, SourceLocation


class RuntimeEventsAnalyzer(BaseAnalyzer):
    """Analyze runtime/probe telemetry and schema-derived invocation surfaces."""

    name = "runtime_events"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        if server.runtime_events and detect_autonomous_loop_event({"events": server.runtime_events}):
            findings.append(
                _finding(
                    "runtime-autonomous-loop",
                    "Repeated identical MCP tool invocations (loop exploit)",
                    None,
                    "MCTS-T-1035",
                    Severity.HIGH,
                    {"type": "autonomous_loop", "event_count": len(server.runtime_events)},
                )
            )
        for index, event in enumerate(server.runtime_events):
            findings.extend(self._analyze_event(event, index))
        for tool in server.tools:
            findings.extend(self._analyze_tool_schema(tool))
        return findings

    def _analyze_event(self, event: dict[str, Any], index: int) -> list[Finding]:
        findings: list[Finding] = []

        tool_name = str(event.get("tool_name", "unknown"))
        params = event.get("tool_parameters")
        if params and detect_command_injection(tool_name=tool_name, tool_parameters=params):
            findings.append(
                _finding(
                    f"runtime-cmd-inject-{index}",
                    "Command injection pattern in tool invocation",
                    tool_name,
                    "MCTS-T-1023",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "command_injection"},
                )
            )

        log = event.get("log_entry", event)
        if isinstance(log, dict) and detect_rug_pull_event(log):
            findings.append(
                _finding(
                    f"runtime-rug-pull-{index}",
                    f"Rug pull behavioral change on {log.get('tool_name', 'tool')}",
                    str(log.get("tool_name", tool_name)),
                    "MCTS-T-1013",
                    Severity.HIGH,
                    {"event_index": index, "type": "rug_pull"},
                )
            )

        if detect_oauth_mixup_event(event):
            findings.append(
                _finding(
                    f"runtime-oauth-mixup-{index}",
                    "OAuth Authorization Server mix-up indicator",
                    None,
                    "MCTS-T-1012",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "oauth_mixup"},
                )
            )

        if detect_sampling_abuse(event):
            findings.append(
                _finding(
                    f"runtime-sampling-abuse-{index}",
                    "Sampling API abuse pattern",
                    str(event.get("server_name", tool_name)),
                    "MCTS-T-1016",
                    Severity.HIGH,
                    {"event_index": index, "type": "sampling_abuse"},
                )
            )

        file_path = str(event.get("file_path") or event.get("path") or "")
        if file_path and detect_credential_file_access(tool_name=tool_name, file_path=file_path):
            findings.append(
                _finding(
                    f"runtime-credential-access-{index}",
                    f"Sensitive credential file access: {file_path}",
                    tool_name,
                    "MCTS-T-1024",
                    Severity.CRITICAL,
                    {"event_index": index, "path": file_path},
                )
            )

        if detect_tool_definition_file_event(event):
            findings.append(
                _finding(
                    f"runtime-tool-redef-{index}",
                    "MCP tool definition file modification",
                    None,
                    "MCTS-T-1040",
                    Severity.HIGH,
                    {"event_index": index, "path": file_path or event.get("name")},
                )
            )

        if detect_tool_redefinition_baseline(
            baseline_tools=list(event.get("baseline_tools") or []),
            current_tools=list(event.get("current_tools") or []),
            metadata_changed=bool(event.get("metadata_changed", False)),
        ):
            findings.append(
                _finding(
                    f"runtime-tool-baseline-{index}",
                    "Tool manifest differs from saved baseline",
                    None,
                    "MCTS-T-1040",
                    Severity.HIGH,
                    {"event_index": index, "type": "baseline_diff"},
                )
            )

        if detect_over_privileged_process(event):
            findings.append(
                _finding(
                    f"runtime-over-priv-{index}",
                    "Over-privileged MCP tool process activity",
                    tool_name,
                    "MCTS-T-1006",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "over_privileged"},
                )
            )

        if detect_behavioral_extraction(event):
            findings.append(
                _finding(
                    f"runtime-behavioral-{index}",
                    "System prompt extraction attempt",
                    None,
                    "MCTS-T-1026",
                    Severity.HIGH,
                    {"event_index": index, "type": "behavioral_extraction"},
                )
            )

        if detect_exposed_endpoint(event):
            findings.append(
                _finding(
                    f"runtime-exposed-endpoint-{index}",
                    "Exposed MCP endpoint access pattern",
                    None,
                    "MCTS-T-1027",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "exposed_endpoint"},
                )
            )

        if detect_dns_poisoning_event(event):
            findings.append(
                _finding(
                    f"runtime-dns-poison-{index}",
                    "DNS or certificate poisoning indicator",
                    None,
                    "MCTS-T-1028",
                    Severity.HIGH,
                    {"event_index": index, "type": "dns_poisoning"},
                )
            )

        tool_output = str(event.get("tool_output") or "")
        if tool_output and detect_tool_output_injection(tool_output=tool_output, tool_name=tool_name):
            findings.append(
                _finding(
                    f"runtime-tool-output-{index}",
                    "Prompt injection pattern in tool output",
                    tool_name,
                    "MCTS-T-1007",
                    Severity.HIGH,
                    {"event_index": index, "type": "tool_output_injection"},
                )
            )

        if detect_cross_server_shadowing(event):
            findings.append(
                _finding(
                    f"runtime-cross-server-{index}",
                    "Cross-server tool shadowing registration",
                    str(event.get("tool_name")),
                    "MCTS-T-1029",
                    Severity.HIGH,
                    {"event_index": index, "type": "cross_server_shadowing"},
                )
            )

        if detect_privilege_tool_abuse(event):
            findings.append(
                _finding(
                    f"runtime-privilege-tool-{index}",
                    "High-privilege MCP tool execution",
                    str(event.get("tool_name", tool_name)),
                    "MCTS-T-1030",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "privilege_tool_abuse"},
                )
            )

        if detect_suspicious_tool_registration(event):
            findings.append(
                _finding(
                    f"runtime-suspicious-reg-{index}",
                    "Suspicious MCP tool registration",
                    None,
                    "MCTS-T-1031",
                    Severity.HIGH,
                    {"event_index": index, "type": "suspicious_registration"},
                )
            )

        if detect_fake_tool_invocation(event):
            findings.append(
                _finding(
                    f"runtime-fake-tool-{index}",
                    "Fake or spoofed MCP tool invocation",
                    str(event.get("tool_name", tool_name)),
                    "MCTS-T-1032",
                    Severity.HIGH,
                    {"event_index": index, "type": "fake_tool_invocation"},
                )
            )

        if detect_sandbox_escape(event):
            findings.append(
                _finding(
                    f"runtime-sandbox-escape-{index}",
                    "Container sandbox escape via runc exec",
                    None,
                    "MCTS-T-1033",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "sandbox_escape"},
                )
            )

        if detect_rogue_as_event(event):
            findings.append(
                _finding(
                    f"runtime-rogue-as-{index}",
                    "Rogue OAuth Authorization Server indicator",
                    None,
                    "MCTS-T-1017",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "rogue_authorization_server"},
                )
            )

        if detect_confused_deputy_event(event):
            findings.append(
                _finding(
                    f"runtime-confused-deputy-{index}",
                    "OAuth confused deputy / token forwarding",
                    None,
                    "MCTS-T-1018",
                    Severity.HIGH,
                    {"event_index": index, "type": "confused_deputy"},
                )
            )

        if detect_scope_substitution_event(event):
            findings.append(
                _finding(
                    f"runtime-scope-substitution-{index}",
                    "OAuth token scope substitution pattern",
                    None,
                    "MCTS-T-1019",
                    Severity.HIGH,
                    {"event_index": index, "type": "scope_substitution"},
                )
            )

        if detect_instruction_steganography(event):
            tool = str(event.get("tool_name") or event.get("tool_id") or tool_name)
            findings.append(
                _finding(
                    f"runtime-steganography-{index}",
                    "Hidden instructions in tool metadata",
                    tool,
                    "MCTS-T-1041",
                    Severity.HIGH,
                    {"event_index": index, "type": "instruction_steganography"},
                )
            )

        if detect_vector_poisoning(event):
            findings.append(
                _finding(
                    f"runtime-vector-poison-{index}",
                    "Vector store embedding metadata contamination",
                    None,
                    "MCTS-T-1034",
                    Severity.HIGH,
                    {"event_index": index, "type": "vector_poisoning"},
                )
            )

        if detect_inspector_rce_event(event):
            findings.append(
                _finding(
                    f"runtime-inspector-rce-{index}",
                    "MCP Inspector remote code execution attempt",
                    None,
                    "MCTS-T-1036",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "inspector_rce"},
                )
            )

        if detect_oauth_token_persistence_event(event):
            findings.append(
                _finding(
                    f"runtime-token-persist-{index}",
                    "OAuth token persistence after logout or rotation",
                    None,
                    "MCTS-T-1037",
                    Severity.HIGH,
                    {"event_index": index, "type": "oauth_token_persistence"},
                )
            )

        if detect_backdoored_install_event(event):
            findings.append(
                _finding(
                    f"runtime-backdoored-install-{index}",
                    "Install-time persistence during MCP package setup",
                    None,
                    "MCTS-T-1038",
                    Severity.HIGH,
                    {"event_index": index, "type": "backdoored_install"},
                )
            )

        if detect_context_memory_implant(event):
            findings.append(
                _finding(
                    f"runtime-memory-implant-{index}",
                    "Context memory implant in vector store",
                    None,
                    "MCTS-T-1039",
                    Severity.HIGH,
                    {"event_index": index, "type": "context_memory_implant"},
                )
            )

        return findings

    def _analyze_tool_schema(self, tool: MCPTool) -> list[Finding]:
        defaults = _schema_default_values(tool.input_schema)
        if not defaults:
            return []
        if not detect_command_injection(tool_name=tool.name, tool_parameters=defaults):
            return []
        return [
            _finding(
                f"schema-cmd-inject-{tool.name}",
                f"Command injection pattern in {tool.name} schema defaults",
                tool.name,
                "MCTS-T-1023",
                Severity.HIGH,
                {"type": "schema_default_injection", "defaults": defaults},
                tool=tool,
            )
        ]


def _schema_default_values(schema: Any, prefix: str = "") -> dict[str, str]:
    values: dict[str, str] = {}
    if not isinstance(schema, dict):
        return values
    default = schema.get("default")
    if isinstance(default, str) and default:
        key = prefix or "default"
        values[key] = default
    for prop_name, prop_schema in schema.get("properties", {}).items():
        if isinstance(prop_schema, dict):
            nested = _schema_default_values(prop_schema, prop_name)
            values.update(nested)
    return values


def _finding(
    finding_id: str,
    title: str,
    tool: str | None,
    technique_id: str,
    severity: Severity,
    evidence: dict[str, Any],
    *,
    mcp_tool: MCPTool | None = None,
) -> Finding:
    loc = SourceLocation(
        file=(mcp_tool.source_file if mcp_tool else "") or "",
        line=mcp_tool.source_line if mcp_tool else None,
    )
    return Finding(
        id=finding_id,
        analyzer="runtime_events",
        title=title,
        description=title,
        severity=severity,
        tool=tool,
        recommendation="Review runtime telemetry and tighten tool input validation.",
        technique_id=technique_id,
        confidence=0.85,
        location=loc,
        evidence=evidence,
    )


def events_from_fuzz_findings(findings: list[Any]) -> list[dict[str, Any]]:
    """Convert fuzz findings into runtime event rows for optional scan enrichment."""
    from mcts.probe.events import events_from_fuzz_finding_rows

    return events_from_fuzz_finding_rows(findings)
