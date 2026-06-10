"""Sigma rule compilation tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from mcts.taxonomy.sigma.loader import load_bundled_rules

ROOT = Path(__file__).resolve().parents[1]
FIXTURES_SIGMA = ROOT / "tests" / "fixtures" / "sigma_fixtures"
COMPILE_SCRIPT = ROOT / "scripts" / "compile_sigma_rules.py"


def test_bundled_sigma_rules_load() -> None:
    rules = load_bundled_rules()
    assert len(rules) >= 20


def test_compile_metadata_rules_public_api() -> None:
    from mcts.taxonomy.sigma import compile_metadata_rules, load_rules_from_directory

    rules = load_rules_from_directory(FIXTURES_SIGMA)
    assert len(rules) >= 6
    compiled = compile_metadata_rules(FIXTURES_SIGMA, merge_bundled=False)
    assert len(compiled) == len(rules)


def test_sigma_bundle_in_sync() -> None:
    result = subprocess.run(
        [sys.executable, str(COMPILE_SCRIPT), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_sigma_fixtures_compile_min_rules() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(COMPILE_SCRIPT),
            "--source",
            str(FIXTURES_SIGMA),
            "--validate-min",
            "6",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
