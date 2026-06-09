"""Tests for toxic flow and hitting-set analysis."""

from __future__ import annotations

from mcts.analyzers.toxic_flows import analyze_inventory
from mcts.inventory.hitting_set import minimum_hitting_set
from mcts.inventory.models import InventoryEntry


def test_minimum_hitting_set() -> None:
    flows = [["a", "b"], ["b", "c"], ["a", "c"]]
    hitting = minimum_hitting_set(flows)
    assert len(hitting) == 2


def test_toxic_flow_detects_read_write_chain() -> None:
    inventory = [
        InventoryEntry(
            client="cursor",
            config_path="/a",
            server_name="reader",
            tools=["read_file"],
        ),
        InventoryEntry(
            client="claude",
            config_path="/b",
            server_name="writer",
            tools=["write_file"],
        ),
    ]
    findings = analyze_inventory(inventory)
    codes = {f.evidence.get("issue_code") for f in findings}
    assert "W015" in codes
    assert "W020" in codes
