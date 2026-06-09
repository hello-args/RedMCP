"""Default local output directory for MCTS CLI artifacts."""

from __future__ import annotations

import os
from pathlib import Path

ANALYSIS_DIR_NAME = "mcts_analysis"


def workspace_root() -> Path:
    """Directory used as the parent of ``mcts_analysis/``."""
    override = os.environ.get("MCTS_ANALYSIS_ROOT")
    if override:
        return Path(override).expanduser().resolve()
    return Path.cwd()


def ensure_analysis_dir(root: Path | None = None) -> Path:
    """Create ``mcts_analysis/`` under *root* (or cwd) and return its path."""
    path = (root or workspace_root()) / ANALYSIS_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def analysis_path(filename: str, root: Path | None = None) -> Path:
    """Return ``mcts_analysis/<filename>``, creating the folder if needed."""
    return ensure_analysis_dir(root) / filename


def resolve_report_input_path(user_path: Path, *, root: Path | None = None) -> Path:
    """Locate scan JSON — try *user_path*, then ``mcts_analysis/`` fallbacks.

    Relative ``-o report.json`` on scan writes to ``mcts_analysis/report.json``;
    ``mcts report report.json`` should resolve the same file.
    """
    path = user_path.expanduser()
    if path.is_file():
        return path.resolve()

    candidates: list[Path] = []
    seen: set[Path] = set()

    def _add(candidate: Path) -> None:
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            candidates.append(resolved)

    if not path.is_absolute():
        _add(analysis_path(path.name, root=root))
        if path.name in {"report.json", "scan-report.json"}:
            if path.name != "scan-report.json":
                _add(analysis_path("scan-report.json", root=root))
            if path.name != "report.json":
                _add(analysis_path("report.json", root=root))

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return path.resolve() if path.is_absolute() else user_path


def resolve_output_path(
    user_path: Path | None,
    default_filename: str,
    *,
    root: Path | None = None,
) -> Path:
    """Resolve a CLI output path into ``mcts_analysis/`` when appropriate.

    - ``None`` → ``mcts_analysis/<default_filename>``
    - Relative paths → ``mcts_analysis/<name>`` (basename only when nested ``.``)
    - Absolute paths → used as-is (parent dirs created)
    """
    if user_path is None:
        return analysis_path(default_filename, root=root)

    path = user_path.expanduser()
    if not path.is_absolute():
        path = analysis_path(path.name, root=root)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
