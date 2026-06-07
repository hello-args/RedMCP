"""Cross-server tool shadowing detection."""

from __future__ import annotations

from difflib import SequenceMatcher

from mcts.analyzers.base import BaseAnalyzer
from mcts.inventory.models import InventoryEntry
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


class CrossServerAnalyzer(BaseAnalyzer):
    """Detects tool name collisions and near-duplicates across configured MCP servers."""

    name = "cross_server"

    def __init__(self, inventory: list[InventoryEntry] | None = None) -> None:
        self.inventory = inventory or []

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        if len(self.inventory) < 2:
            return []
        return self.analyze_inventory(self.inventory)

    def analyze_inventory(self, inventory: list[InventoryEntry]) -> list[Finding]:
        findings: list[Finding] = []
        tool_index: dict[str, list[tuple[str, str]]] = {}

        for entry in inventory:
            for tool in entry.tools:
                tool_index.setdefault(tool, []).append((entry.client, entry.server_name))

        for tool_name, locations in tool_index.items():
            if len(locations) < 2:
                continue
            servers = sorted({f"{client}/{server}" for client, server in locations})
            findings.append(
                Finding(
                    id=f"shadow-exact-{tool_name}",
                    analyzer=self.name,
                    title=f"Cross-server tool name collision: {tool_name}",
                    description=f"Tool '{tool_name}' appears on multiple MCP servers and may shadow intent.",
                    severity=Severity.HIGH,
                    tool=tool_name,
                    recommendation="Rename tools to be server-specific or disable unused servers.",
                    technique_id="MCTS-T-1008",
                    evidence={"tool": tool_name, "servers": servers},
                )
            )

        names = list(tool_index.keys())
        seen_pairs: set[tuple[str, str]] = set()
        for i, left in enumerate(names):
            for right in names[i + 1 :]:
                if left == right:
                    continue
                score = _similarity(left, right)
                if score < 0.85:
                    continue
                pair = tuple(sorted((left, right)))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                findings.append(
                    Finding(
                        id=f"shadow-similar-{left}-{right}",
                        analyzer=self.name,
                        title=f"Similar tool names may shadow: {left} / {right}",
                        description=(
                            f"Tool names are {score:.0%} similar across servers — agents may pick wrong tool."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation="Differentiate tool names clearly across MCP servers.",
                        technique_id="MCTS-T-1008",
                        evidence={
                            "tool_a": left,
                            "tool_b": right,
                            "similarity": round(score, 2),
                            "servers_a": [s for c, s in tool_index[left]],
                            "servers_b": [s for c, s in tool_index[right]],
                        },
                    )
                )

        return findings
