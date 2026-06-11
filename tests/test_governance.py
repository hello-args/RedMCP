"""Tests for governance policy evaluation."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from mcts.cli.main import app
from mcts.governance import evaluate_policy, load_policy
from mcts.output.analysis_dir import ANALYSIS_DIR_NAME

runner = CliRunner()


def test_load_and_evaluate_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "min_score: 80\nmax_critical: 0\nallowed_servers:\n  - cursor/demo\nblocked_servers: []\n"
    )
    policy = load_policy(policy_path)
    assert policy is not None
    violations = evaluate_policy(
        policy=policy,
        score=70,
        critical=0,
        high=1,
        servers=["cursor/other"],
    )
    assert any("score" in item for item in violations)
    assert any("allowlist" in item for item in violations)


def test_scan_missing_policy_fails_before_reports(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "server.py"
    target.write_text("print('not an mcp server')\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["scan", str(target), "--policy", str(tmp_path / "missing.yaml"), "--no-progress"],
    )

    assert result.exit_code == 2
    assert "Governance policy not found" in result.stdout
    assert not (tmp_path / ANALYSIS_DIR_NAME).exists()


def test_scan_invalid_policy_fails_before_reports(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "server.py"
    target.write_text("print('not an mcp server')\n", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text("- not-a-mapping\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(target), "--policy", str(policy), "--no-progress"])

    assert result.exit_code == 2
    assert "Governance policy must be a YAML mapping" in result.stdout
    assert not (tmp_path / ANALYSIS_DIR_NAME).exists()
