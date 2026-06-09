"""MCP config discovery and first-run scan hints."""

from __future__ import annotations

from pathlib import Path

from mcts.discovery.config import list_server_names
from mcts.discovery.static import MCP_FILE_INDICATORS

CONFIG_CANDIDATES = (
    ".mcp.json",
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
)

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)


def find_mcp_configs(root: Path) -> list[Path]:
    """Return MCP client config files under root (relative paths preserved)."""
    base = root.expanduser().resolve()
    found: list[Path] = []
    for candidate in CONFIG_CANDIDATES:
        path = base / candidate
        if path.is_file():
            found.append(path)
    return found


def list_servers(config_path: Path) -> list[str]:
    """Return server names declared in an MCP client config."""
    return list_server_names(config_path)


def find_entrypoint_candidates(root: Path, *, limit: int = 5) -> list[Path]:
    """Heuristic MCP Python entrypoints under root (skips tests and venvs)."""
    base = root.expanduser().resolve()
    if not base.is_dir():
        return []
    scored: list[tuple[int, Path]] = []
    for path in base.rglob("*.py"):
        if _should_skip(path, base):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not any(indicator in content for indicator in MCP_FILE_INDICATORS):
            continue
        score = sum(1 for indicator in MCP_FILE_INDICATORS if indicator in content)
        name_lower = path.name.lower()
        if "bridge" in name_lower or "server" in name_lower:
            score += 2
        if "/mcp/" in f"/{path.relative_to(base).as_posix()}/":
            score += 1
        scored.append((score, path))

    scored.sort(key=lambda item: (-item[0], str(item[1])))
    return [path for _, path in scored[:limit]]


def format_discovery_hints(root: Path) -> str:
    """Multi-line hint text for Rich console (no ANSI)."""
    lines: list[str] = []
    configs = find_mcp_configs(root)
    for config_path in configs:
        try:
            servers = list_servers(config_path)
        except (OSError, ValueError):
            servers = []
        rel = _display_path(config_path, root)
        lines.append(f"Found MCP config: {rel}")
        if servers:
            preview = ", ".join(servers[:4])
            if len(servers) > 4:
                preview += ", …"
            lines.append(f"  Servers: {preview}")
            first = servers[0]
            lines.append(f"  Try: mcts scan . --config {rel} --server {first}")
    candidates = find_entrypoint_candidates(root, limit=3)
    for candidate in candidates:
        rel = _display_path(candidate, root)
        lines.append(f"  Or:  mcts scan {rel}")
    if not lines:
        lines.append(
            "No MCP config found in this directory. Scan a server entrypoint: mcts scan path/to/server.py"
        )
    return "\n".join(lines)


def _should_skip(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in _SKIP_DIRS or part.startswith(".") for part in rel_parts[:-1]) or any(
        part in {"tests", "test"} for part in rel_parts
    )


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)
