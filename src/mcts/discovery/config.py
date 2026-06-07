"""Load MCP server launch config from client JSON files."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcts.probe.models import LiveServerConfig


class ConfigDiscoveryError(RuntimeError):
    """Raised when a config file or server entry cannot be loaded."""


def load_server_from_config(config_path: Path, server_name: str) -> LiveServerConfig:
    """Parse a Cursor/Claude/VS Code MCP config and return stdio launch params."""
    path = config_path.expanduser().resolve()
    if not path.exists():
        raise ConfigDiscoveryError(f"Config file not found: {path}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigDiscoveryError(f"Invalid config JSON: {path}") from exc

    servers = payload.get("mcpServers")
    if servers is None and isinstance(payload.get("mcp"), dict):
        servers = payload["mcp"].get("servers", {})
    if not isinstance(servers, dict):
        raise ConfigDiscoveryError(f"No mcpServers block in {path}")

    if server_name not in servers:
        available = ", ".join(sorted(servers)) or "(none)"
        raise ConfigDiscoveryError(f"Server {server_name!r} not found in {path}. Available: {available}")

    entry = servers[server_name]
    if not isinstance(entry, dict):
        raise ConfigDiscoveryError(f"Server entry {server_name!r} is not an object")

    command = entry.get("command")
    if not command:
        raise ConfigDiscoveryError(
            f"Server {server_name!r} has no stdio command (remote-only servers not supported yet)"
        )

    args = [str(a) for a in entry.get("args") or []]
    env = {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
    merged_env = {**os.environ, **env}

    return LiveServerConfig(
        command=str(command),
        args=args,
        env=merged_env,
        server_name=server_name,
    )
