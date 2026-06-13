"""Analyzer bronze fact emission tests."""

from pathlib import Path

from mcts.analyzers.data_leakage import DataLeakageAnalyzer
from mcts.analyzers.prompt_injection import PromptInjectionAnalyzer
from mcts.core.config import ScanConfig
from mcts.discovery.static import StaticDiscovery


def test_prompt_injection_emits_bronze_facts(example_server_path: Path) -> None:
    server = StaticDiscovery(ScanConfig(target=example_server_path)).discover()
    findings = PromptInjectionAnalyzer().analyze(server)
    assert findings
    assert all((f.evidence or {}).get("facts") for f in findings)


def test_data_leakage_emits_bronze_facts(example_server_path: Path) -> None:
    server = StaticDiscovery(ScanConfig(target=example_server_path)).discover()
    findings = DataLeakageAnalyzer().analyze(server)
    assert findings
    assert all((f.evidence or {}).get("facts") for f in findings)
