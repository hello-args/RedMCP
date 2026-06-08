"""MCP client for server discovery and probing."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.discovery.merge import merge_server_info
from mcts.discovery.static_json import load_snapshot
from mcts.discovery.static_runner import discover_static
from mcts.mcp.models import MCPServerInfo


class MCPClient:
    """Discovers MCP server capabilities from static source, JSON snapshot, and/or live probe."""

    def __init__(self, target: Path, config: ScanConfig | None = None) -> None:
        self.target = target
        self.config = config or ScanConfig(target=target)

    def discover(self) -> MCPServerInfo:
        """Discover tools via static analysis, JSON snapshot, live probe, or merged mode."""
        if self._has_snapshot():
            return self._apply_filters(
                load_snapshot(
                    tools_path=self.config.snapshot_tools,
                    prompts_path=self.config.snapshot_prompts,
                    resources_path=self.config.snapshot_resources,
                    instructions_path=self.config.snapshot_instructions,
                    snapshot_path=self.config.snapshot_path,
                )
            )

        static_info = self._discover_static()
        if not self.config.live and not self.config.remote_url:
            return self._apply_filters(static_info)

        from mcts.discovery.live import LiveDiscovery

        live_info = LiveDiscovery(self.config).discover()

        if static_info.tools and self.config.merge_static_live and static_info.discovery_mode != "empty":
            merged = merge_server_info(static_info, live_info)
            return self._apply_filters(merged)
        return self._apply_filters(live_info)

    def _has_snapshot(self) -> bool:
        return any(
            [
                self.config.snapshot_path,
                self.config.snapshot_tools,
                self.config.snapshot_prompts,
                self.config.snapshot_resources,
                self.config.snapshot_instructions,
            ]
        )

    def _discover_static(self) -> MCPServerInfo:
        if self.config.config_path and not self._target_exists():
            return MCPServerInfo(name=self.config.config_server or "config", discovery_mode="empty")
        if not self._target_exists():
            return MCPServerInfo(name=str(self.target), discovery_mode="empty")
        return discover_static(self.config)

    def _target_exists(self) -> bool:
        return self.target.exists()

    def _apply_filters(self, server: MCPServerInfo) -> MCPServerInfo:
        if not self.config.tool_filter:
            return server
        allowed = set(self.config.tool_filter)
        tools = [t for t in server.tools if t.name in allowed]
        return server.model_copy(update={"tools": tools})
