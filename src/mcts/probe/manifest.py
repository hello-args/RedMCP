"""Pre-connect remote MCP manifest probing."""

from __future__ import annotations

from dataclasses import dataclass

from mcts.core.config import ScanConfig
from mcts.mcp.client import MCPClient
from mcts.mcp.models import MCPServerInfo


@dataclass(frozen=True)
class ManifestProbeResult:
    url: str
    transport: str
    server: MCPServerInfo
    tool_count: int
    prompt_count: int
    resource_count: int


def probe_remote_manifest(config: ScanConfig) -> ManifestProbeResult:
    """Connect to a remote MCP endpoint and return tools/list metadata only."""
    if not config.remote_url:
        raise ValueError("Remote URL is required for manifest probe")
    client = MCPClient(config.target, config)
    server = client.discover()
    return ManifestProbeResult(
        url=config.remote_url,
        transport=config.remote_transport,
        server=server,
        tool_count=len(server.tools),
        prompt_count=len(server.prompts),
        resource_count=len(server.resources),
    )
