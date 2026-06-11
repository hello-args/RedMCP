"""Tests for pyproject dependency parsing and lockfile-aware supply-chain checks."""

from __future__ import annotations

from pathlib import Path

from mcts.analyzers.manifest_deps import (
    iter_pyproject_dependencies,
    load_locked_versions,
    normalize_package_name,
)
from mcts.analyzers.supply_chain import SupplyChainAnalyzer
from mcts.mcp.models import MCPServerInfo


def _server() -> MCPServerInfo:
    return MCPServerInfo(tools=[])


def test_iter_pyproject_skips_poetry_metadata_and_tool_config(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry]
name = "demo"
description = "Bridge for IFD >= 3.9 environments"
authors = ["UXE AI Solutions <team@example.com>"]

[tool.pytest.ini_options]
python_files = "test_*.py"
python_classes = "Test*"

[tool.ruff]
line-length = 100

[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27.0"
""",
        encoding="utf-8",
    )
    deps = iter_pyproject_dependencies(pyproject)
    names = {dep.name for dep in deps}
    assert names == {"httpx"}


def test_supply_chain_skips_poetry_metadata_false_positives(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry]
description = "Supports environments >= 3.9"
authors = ["Team <team@example.com>"]

[tool.pytest.ini_options]
python_files = "test_*.py"

[tool.poetry.dependencies]
python = "^3.11"
""",
        encoding="utf-8",
    )

    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server())
    assert not findings


def test_supply_chain_flags_unpinned_without_lockfile(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry.dependencies]
httpx = "^0.27.0"
fastmcp = ">=1.0"
""",
        encoding="utf-8",
    )

    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server())
    titles = {finding.title for finding in findings}
    assert "Unpinned Python dependency: httpx" in titles
    assert "Unpinned Python dependency: fastmcp" in titles


def test_supply_chain_skips_locked_poetry_dependencies(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry.dependencies]
httpx = "^0.27.0"
requests = "^2.31.0"
""",
        encoding="utf-8",
    )
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        """
[[package]]
name = "httpx"
version = "0.27.2"

[[package]]
name = "requests"
version = "2.31.0"
""",
        encoding="utf-8",
    )

    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server())
    assert not findings


def test_supply_chain_honors_uv_lock(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = [
  "httpx>=0.28.0",
]
""",
        encoding="utf-8",
    )
    lock = tmp_path / "uv.lock"
    lock.write_text(
        """
[[package]]
name = "httpx"
version = "0.28.1"
""",
        encoding="utf-8",
    )

    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server())
    assert not any(f.title.startswith("Unpinned Python dependency") for f in findings)


def test_load_locked_versions_from_pipfile_lock(tmp_path: Path) -> None:
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(
        """
{
  "default": {
    "requests": {
      "version": "==2.31.0"
    }
  }
}
""",
        encoding="utf-8",
    )

    locked = load_locked_versions(tmp_path)
    assert locked[normalize_package_name("requests")] == "2.31.0"


def test_project_dependencies_parsed(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = ["pydantic>=2.13.4"]
""",
        encoding="utf-8",
    )

    deps = iter_pyproject_dependencies(pyproject)
    assert len(deps) == 1
    assert deps[0].name == "pydantic"
