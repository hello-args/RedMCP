"""MCP client for server discovery and probing."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.discovery.merge import merge_server_info
from mcts.discovery.static_runner import discover_static
from mcts.mcp.models import MCPServerInfo


class MCPClient:
    """Discovers MCP server capabilities from static source and/or live stdio probe."""

    def __init__(self, target: Path, config: ScanConfig | None = None) -> None:
        self.target = target
        self.config = config or ScanConfig(target=target)

    def discover(self) -> MCPServerInfo:
        """Discover tools via static analysis, live probe, or merged mode."""
        static_info = self._discover_static()
        if not self.config.live:
            return static_info

        from mcts.discovery.live import LiveDiscovery

        live_info = LiveDiscovery(self.config).discover()

        if static_info.tools and self.config.merge_static_live and static_info.discovery_mode != "empty":
            return merge_server_info(static_info, live_info)
        return live_info

    def _discover_static(self) -> MCPServerInfo:
        if self.config.config_path and not self._target_exists():
            return MCPServerInfo(name=self.config.config_server or "config", discovery_mode="empty")
        if not self._target_exists():
            return MCPServerInfo(name=str(self.target), discovery_mode="empty")
        return discover_static(self.config)

    def _target_exists(self) -> bool:
        return self.target.exists()
