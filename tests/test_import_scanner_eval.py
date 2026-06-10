"""Tests for scripts/import_scanner_eval.py exit codes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]

_MALICIOUS = '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("test")

@mcp.tool()
def run_shell(command: str) -> str:
    """Execute a shell command."""
    import subprocess
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
'''

_BENIGN = '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("test")

@mcp.tool()
def greet(name: str) -> str:
    """Say hello."""
    return f"hello {name}"
'''


def _write_corpus(tmp_path: Path) -> Path:
    (tmp_path / "malicious.py").write_text(_MALICIOUS, encoding="utf-8")
    (tmp_path / "benign.py").write_text(_BENIGN, encoding="utf-8")
    return tmp_path


def _run_eval(data_dir: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/import_scanner_eval.py", str(data_dir), *extra],
        capture_output=True,
        text=True,
        check=False,
        cwd=_REPO_ROOT,
    )


def test_import_scanner_eval_default_exits_zero_on_partial_recall(tmp_path: Path) -> None:
    corpus = _write_corpus(tmp_path)
    result = _run_eval(corpus)
    assert result.returncode == 0
    assert "MISS benign.py" in result.stdout


def test_import_scanner_eval_strict_exits_one_on_miss(tmp_path: Path) -> None:
    corpus = _write_corpus(tmp_path)
    result = _run_eval(corpus, "--strict")
    assert result.returncode == 1
    assert "MISS benign.py" in result.stdout


def test_import_scanner_eval_min_recall_exits_one_when_below_threshold(tmp_path: Path) -> None:
    corpus = _write_corpus(tmp_path)
    result = _run_eval(corpus, "--min-recall", "1.0")
    assert result.returncode == 1


def test_import_scanner_eval_min_recall_passes_when_met(tmp_path: Path) -> None:
    corpus = _write_corpus(tmp_path)
    result = _run_eval(corpus, "--min-recall", "0.5")
    assert result.returncode == 0


def test_import_scanner_eval_missing_dir_exits_two(tmp_path: Path) -> None:
    result = _run_eval(tmp_path / "missing")
    assert result.returncode == 2
