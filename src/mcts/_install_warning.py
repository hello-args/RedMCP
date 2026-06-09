"""Warn when MCTS runs inside an application virtual environment."""

from __future__ import annotations

import os
from pathlib import Path

_WARNED = False

_PROJECT_MARKERS = ("pyproject.toml", "poetry.lock", "setup.py", "Pipfile", "requirements.txt")


def _is_mcts_dev_checkout(root: Path) -> bool:
    if not (root / "src" / "mcts").is_dir():
        return False
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return False
    try:
        text = pyproject.read_text(encoding="utf-8")
    except OSError:
        return False
    return "mcp-mcts" in text or "Model Context Threat Scanner" in text


def should_warn_app_venv() -> bool:
    venv = os.environ.get("VIRTUAL_ENV")
    if not venv:
        return False
    root = Path.cwd()
    if _is_mcts_dev_checkout(root):
        return False
    return any((root / marker).exists() for marker in _PROJECT_MARKERS)


def maybe_warn_venv_install(console) -> None:
    """Emit a one-time stderr warning when running inside a project venv."""
    global _WARNED  # noqa: PLW0603
    del console
    if _WARNED or os.environ.get("MCTS_NO_VENV_WARN"):
        return
    if not should_warn_app_venv():
        return
    _WARNED = True
    from rich.console import Console

    venv = os.environ.get("VIRTUAL_ENV", "")
    stderr_console = Console(stderr=True, highlight=False)
    stderr_console.print(
        "[yellow]Warning:[/yellow] MCTS is running inside a project virtual environment.\n"
        f"  VIRTUAL_ENV={venv}\n"
        "  Installing MCTS here may upgrade dependencies (e.g. openai, torch) and break your app.\n"
        "  Prefer an isolated install: [bold]uvx mcp-mcts[/bold], [bold]pipx install mcp-mcts[/bold], "
        "or [bold]uv tool install mcp-mcts[/bold].\n"
        "  Suppress: export MCTS_NO_VENV_WARN=1",
    )
