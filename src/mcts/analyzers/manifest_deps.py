"""Parse Python dependency manifests and lockfiles for supply-chain checks."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

UNPINNED_PATTERN = re.compile(r"(\^|~|\*|latest|>=|<=|>|<)", re.I)
_PEP508_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_SKIP_DEPENDENCY_NAMES = frozenset({"python", "python_version"})


@dataclass(frozen=True)
class DeclaredDependency:
    name: str
    spec: str
    section: str


def normalize_package_name(name: str) -> str:
    return name.lower().replace("_", "-")


def is_unpinned_spec(spec: str) -> bool:
    text = spec.strip()
    if not text:
        return False
    if text.startswith("=="):
        return False
    return bool(UNPINNED_PATTERN.search(text))


def load_locked_versions(root: Path) -> dict[str, str]:
    """Return normalized package name -> pinned version from adjacent lockfiles."""
    locked: dict[str, str] = {}
    for filename in ("poetry.lock", "uv.lock"):
        path = root / filename
        if path.is_file():
            locked.update(_load_toml_lock_packages(path))
    pipfile_lock = root / "Pipfile.lock"
    if pipfile_lock.is_file():
        locked.update(_load_pipfile_lock(pipfile_lock))
    return locked


def iter_pyproject_dependencies(path: Path) -> list[DeclaredDependency]:
    """Extract declared Python dependencies from a pyproject.toml file."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []

    deps: list[DeclaredDependency] = []
    project = data.get("project")
    if isinstance(project, dict):
        raw_deps = project.get("dependencies")
        if isinstance(raw_deps, list):
            for entry in raw_deps:
                if isinstance(entry, str):
                    deps.extend(_dependency_from_pep508(entry, "project.dependencies"))

        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group, entries in optional.items():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if isinstance(entry, str):
                        deps.extend(_dependency_from_pep508(entry, f"project.optional-dependencies.{group}"))

    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            poetry_deps = poetry.get("dependencies")
            if isinstance(poetry_deps, dict):
                for name, spec in poetry_deps.items():
                    if isinstance(name, str) and isinstance(spec, str):
                        deps.extend(_dependency_from_mapping(name, spec, "tool.poetry.dependencies"))

            groups = poetry.get("group")
            if isinstance(groups, dict):
                for group_name, group_cfg in groups.items():
                    if not isinstance(group_cfg, dict):
                        continue
                    group_deps = group_cfg.get("dependencies")
                    if isinstance(group_deps, dict):
                        section = f"tool.poetry.group.{group_name}.dependencies"
                        for name, spec in group_deps.items():
                            if isinstance(name, str) and isinstance(spec, str):
                                deps.extend(_dependency_from_mapping(name, spec, section))

    return deps


def _dependency_from_pep508(entry: str, section: str) -> list[DeclaredDependency]:
    text = entry.strip()
    if not text or text.startswith("#"):
        return []
    match = _PEP508_NAME.match(text)
    if not match:
        return []
    name = match.group(1)
    if normalize_package_name(name) in _SKIP_DEPENDENCY_NAMES:
        return []
    return [DeclaredDependency(name=name, spec=text, section=section)]


def _dependency_from_mapping(name: str, spec: str, section: str) -> list[DeclaredDependency]:
    if normalize_package_name(name) in _SKIP_DEPENDENCY_NAMES:
        return []
    return [DeclaredDependency(name=name, spec=spec.strip(), section=section)]


def _load_toml_lock_packages(path: Path) -> dict[str, str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}

    locked: dict[str, str] = {}
    packages = data.get("package")
    if not isinstance(packages, list):
        return locked
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            locked[normalize_package_name(name)] = version
    return locked


def _load_pipfile_lock(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    locked: dict[str, str] = {}
    for section_name, section in data.items():
        if section_name.startswith("_") or not isinstance(section, dict):
            continue
        for name, meta in section.items():
            if not isinstance(name, str) or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str):
                locked[normalize_package_name(name)] = version.lstrip("=")
    return locked
