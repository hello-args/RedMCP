"""Multi-step attack chain detection."""

from __future__ import annotations

from collections import deque
from typing import Any

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity


class AttackChainAnalyzer(BaseAnalyzer):
    """Identifies dangerous combinations of tools via capability graph."""

    name = "attack_chains"

    def __init__(self) -> None:
        self.last_graph: dict[str, Any] = {"nodes": [], "edges": []}

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        self.last_graph = self._build_graph(server)
        findings: list[Finding] = []

        read_tools = [t for t in server.tools if _cap(t, "reads_untrusted_input")]
        exfil_tools = [t for t in server.tools if _cap(t, "egresses_network")]
        cred_tools = [t for t in server.tools if _cap(t, "accesses_sensitive_data")]
        exec_tools = [t for t in server.tools if _cap(t, "executes_commands")]

        if read_tools and exfil_tools:
            path = _find_path(self.last_graph, read_tools[0].name, exfil_tools[0].name)
            findings.append(
                Finding(
                    id="chain-read-exfil",
                    analyzer=self.name,
                    title="Read → exfiltration attack chain possible",
                    description="Tools exist to read data and send it externally.",
                    severity=Severity.CRITICAL,
                    recommendation="Isolate read and egress tools; require approval for outbound actions.",
                    technique_id="MCTS-T-1005",
                    evidence={
                        "read_tools": [t.name for t in read_tools],
                        "exfil_tools": [t.name for t in exfil_tools],
                        "path": path,
                    },
                )
            )

        if read_tools and cred_tools and exfil_tools:
            findings.append(
                Finding(
                    id="chain-credential-theft",
                    analyzer=self.name,
                    title="Credential theft chain possible",
                    description="Read + credential + egress tools enable multi-step credential exfiltration.",
                    severity=Severity.CRITICAL,
                    recommendation="Block credential tools from agent access or add step-up auth.",
                    technique_id="MCTS-T-1005",
                    evidence={
                        "read_tools": [t.name for t in read_tools],
                        "credential_tools": [t.name for t in cred_tools],
                        "exfil_tools": [t.name for t in exfil_tools],
                    },
                )
            )

        if read_tools and exec_tools:
            findings.append(
                Finding(
                    id="chain-read-exec",
                    analyzer=self.name,
                    title="Read → command execution chain possible",
                    description="Untrusted input can flow from read tools to command execution.",
                    severity=Severity.CRITICAL,
                    recommendation="Prevent chaining file reads into shell execution without validation.",
                    technique_id="MCTS-T-1005",
                    evidence={
                        "read_tools": [t.name for t in read_tools],
                        "exec_tools": [t.name for t in exec_tools],
                    },
                )
            )

        return findings

    def _build_graph(self, server: MCPServerInfo) -> dict[str, Any]:
        nodes: dict[str, dict[str, str]] = {}
        edges: list[dict[str, str]] = []

        for tool in server.tools:
            cap = tool.capability
            cap_label = _cap_summary(cap)
            nodes[tool.name] = {
                "id": tool.name,
                "label": tool.name,
                "type": "tool",
                "capability": cap_label,
            }

        tools = server.tools
        for src in tools:
            for dst in tools:
                if src.name == dst.name:
                    continue
                if _can_chain(src, dst):
                    label = _edge_label(src, dst)
                    edges.append({"from": src.name, "to": dst.name, "label": label})

        return {"nodes": list(nodes.values()), "edges": edges}


def _cap(tool: MCPTool, field: str) -> bool:
    if not tool.capability:
        return False
    return bool(getattr(tool.capability, field))


def _cap_summary(cap: Any) -> str:
    if not cap:
        return "unknown"
    flags = []
    for name in (
        "reads_untrusted_input",
        "accesses_sensitive_data",
        "mutates_state",
        "egresses_network",
        "executes_commands",
    ):
        if getattr(cap, name, False):
            flags.append(name.replace("_", " "))
    return ", ".join(flags) if flags else "minimal"


def _can_chain(src: MCPTool, dst: MCPTool) -> bool:
    if not src.capability or not dst.capability:
        return False
    s, d = src.capability, dst.capability
    return (s.reads_untrusted_input and (d.egresses_network or d.executes_commands)) or (
        s.accesses_sensitive_data and d.egresses_network
    )


def _edge_label(src: MCPTool, dst: MCPTool) -> str:
    if dst.capability and dst.capability.egresses_network:
        return "→ exfil"
    if dst.capability and dst.capability.executes_commands:
        return "→ exec"
    if dst.capability and dst.capability.accesses_sensitive_data:
        return "→ cred"
    return "→ chain"


def _find_path(graph: dict[str, Any], start: str, end: str) -> list[str]:
    adjacency: dict[str, list[str]] = {}
    for edge in graph.get("edges", []):
        adjacency.setdefault(edge["from"], []).append(edge["to"])

    queue: deque[list[str]] = deque([[start]])
    visited = {start}
    while queue:
        path = queue.popleft()
        node = path[-1]
        if node == end:
            return path
        for neighbor in adjacency.get(node, []):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            queue.append([*path, neighbor])
    return [start, end]
