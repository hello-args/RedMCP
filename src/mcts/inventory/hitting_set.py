"""Minimum server set to break toxic cross-server flows."""

from __future__ import annotations

from collections import Counter


def minimum_hitting_set(flows: list[list[str]]) -> list[str]:
    """Greedy minimum hitting set for server identifiers in toxic flows."""
    remaining = [list(flow) for flow in flows if flow]
    chosen: list[str] = []
    while remaining:
        counts: Counter[str] = Counter(server for flow in remaining for server in flow)
        if not counts:
            break
        pick = counts.most_common(1)[0][0]
        chosen.append(pick)
        remaining = [flow for flow in remaining if pick not in flow]
    return chosen
