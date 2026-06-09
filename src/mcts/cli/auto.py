"""Auto scan target resolution for mcts scan --auto."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.discovery.onboarding import find_entrypoint_candidates, find_mcp_configs, list_servers


@dataclass
class AutoScanError(RuntimeError):
    """Raised when --auto cannot pick a unique scan target."""

    message: str
    multiple_servers: list[str] | None = None


def resolve_auto_scan(
    target: Path,
    base_config: ScanConfig,
    *,
    auto_server: str | None = None,
) -> ScanConfig:
    """Resolve scan target/config for --auto mode (static only)."""
    root = target.expanduser().resolve()
    candidates = find_entrypoint_candidates(root) if root.is_dir() else []
    if len(candidates) == 1:
        return base_config.model_copy(update={"target": candidates[0]})

    configs = find_mcp_configs(root) if root.is_dir() else []
    if len(configs) == 1:
        servers = list_servers(configs[0])
        if auto_server:
            if auto_server not in servers:
                raise AutoScanError(
                    f"Server {auto_server!r} not found in {configs[0].name}. Available: {', '.join(servers)}"
                )
            return base_config.model_copy(
                update={
                    "target": root,
                    "config_path": configs[0],
                    "config_server": auto_server,
                }
            )
        if len(servers) == 1:
            return base_config.model_copy(
                update={
                    "target": root,
                    "config_path": configs[0],
                    "config_server": servers[0],
                }
            )
        raise AutoScanError(
            f"Multiple MCP servers in {configs[0].name}; pass --auto-server NAME.",
            multiple_servers=servers,
        )

    return base_config.model_copy(update={"target": root})
