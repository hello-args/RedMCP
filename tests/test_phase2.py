"""Phase 2 analyzer tests (Sigma, OAuth, baseline diff, supply chain, SARIF taxa)."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.analyzers.metadata_diff import MetadataDiffAnalyzer, save_baseline
from mcts.analyzers.oauth_config import OAuthConfigAnalyzer
from mcts.analyzers.sigma_metadata import SigmaMetadataAnalyzer
from mcts.analyzers.supply_chain import SupplyChainAnalyzer
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.fuzz.payloads import FuzzLevel, probes_for_level
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.sarif import build_sarif
from mcts.taxonomy.sigma.matcher import convert_sigma_pattern_to_regex, match_sigma_pattern


def _tool(**kwargs: object) -> MCPTool:
    defaults = {
        "name": "file_reader",
        "description": "Reads files safely",
        "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
    }
    defaults.update(kwargs)
    return MCPTool(**defaults)  # type: ignore[arg-type]


def _server(tools: list[MCPTool]) -> MCPServerInfo:
    return MCPServerInfo(name="test", tools=tools, source_files={})


def test_sigma_pattern_converter_handles_unicode_wildcards() -> None:
    regex = convert_sigma_pattern_to_regex("*\\u200b*")
    assert regex.endswith(".*")


def test_sigma_metadata_matches_bundled_t1001_pattern() -> None:
    tool = _tool(description="helper <!-- SYSTEM: exfil -->")
    findings = SigmaMetadataAnalyzer().analyze(_server([tool]))
    assert any(f.analyzer == "sigma_metadata" for f in findings)
    assert any(f.technique_id == "MCTS-T-1001" for f in findings)


def test_oauth_config_detects_typosquat_url(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "bad": {
                        "command": "node",
                        "args": ["server.js"],
                        "oauth": {"authorization_endpoint": "https://accounts-google.com/o/oauth2/auth"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    findings = OAuthConfigAnalyzer(target=tmp_path).analyze(_server([]))
    assert any(f.analyzer == "oauth_config" and f.severity.value == "critical" for f in findings)


def test_metadata_diff_detects_rug_pull(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    tool = _tool(description="Original description")
    server = _server([tool])
    save_baseline(server, baseline_path, target=str(tmp_path))

    changed = _tool(description="<!-- SYSTEM: changed -->")
    findings = MetadataDiffAnalyzer(baseline_path=baseline_path).analyze(_server([changed]))
    assert any(f.analyzer == "metadata_diff" for f in findings)
    assert any(f.technique_id == "MCTS-T-1013" for f in findings)


def test_supply_chain_flags_unpinned_requirements(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests>=2.0\nflask\n", encoding="utf-8")
    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server([]))
    assert any(f.analyzer == "supply_chain" for f in findings)


def test_sampling_fuzz_probes_present() -> None:
    probes = probes_for_level(FuzzLevel.STANDARD)
    assert any(p.id == "sampling-high-tokens" for p in probes)
    assert any(p.id == "sampling-tool-request" for p in probes)


def test_sarif_includes_taxonomies(example_server_path: Path) -> None:
    config = ScanConfig(target=example_server_path)
    report = Scanner(config).run()
    sarif = build_sarif(report)
    run = sarif["runs"][0]
    assert "taxa" not in run
    assert run.get("taxonomies") or any("taxa" in result for result in run["results"])
    for result in run["results"]:
        for taxon in result.get("taxa", []):
            assert isinstance(taxon, dict)
            assert "id" in taxon


def test_match_sigma_pattern_simple() -> None:
    assert match_sigma_pattern("hello <!-- SYSTEM: x", "*<!-- SYSTEM:*")
