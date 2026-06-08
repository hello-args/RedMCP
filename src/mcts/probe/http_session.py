"""Async remote MCP probe (SSE and streamable HTTP)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from mcts.mcp.models import MCPPrompt, MCPResource, MCPServerInfo, MCPTool
from mcts.probe.auth import RemoteAuth
from mcts.probe.models import RemoteServerConfig
from mcts.probe.session import MCPNotInstalledError, MCPProbeError, _extract_instructions

logger = logging.getLogger(__name__)


def probe_remote_sync(config: RemoteServerConfig, timeout_seconds: int = 120) -> MCPServerInfo:
    return asyncio.run(probe_remote(config, timeout_seconds))


async def probe_remote(config: RemoteServerConfig, timeout_seconds: int = 120) -> MCPServerInfo:
    try:
        from mcp import ClientSession
    except ImportError as exc:
        raise MCPNotInstalledError(
            "Remote probing requires the optional mcp package. Install with: uv sync --extra mcp"
        ) from exc

    headers = config.auth.resolve_headers() if config.auth else {}
    transport = config.transport.lower()
    connect_timeout = min(timeout_seconds, 30)

    try:
        if transport in ("sse", "http-sse"):
            from mcp.client.sse import sse_client

            client_ctx = sse_client(config.url, headers=headers)
            transport_label = "sse-live"
        elif transport in ("streamable-http", "http", "streamable_http"):
            from mcp.client.streamable_http import streamable_http_client

            client_ctx = streamable_http_client(config.url, headers=headers)
            transport_label = "streamable-http-live"
        else:
            raise MCPProbeError(f"Unsupported remote transport: {config.transport}")

        async with asyncio.timeout(connect_timeout):
            async with client_ctx as (read, write, *_):
                async with ClientSession(read, write) as session:
                    init_result = await asyncio.wait_for(session.initialize(), timeout=timeout_seconds)
                    tools = await _list_tools(session, timeout_seconds)
                    prompts = await _list_prompts(session, timeout_seconds)
                    resources = await _list_resources(session, timeout_seconds)
                    from mcts.probe.resources import enrich_resources_with_content

                    resources = await enrich_resources_with_content(
                        session, resources, timeout=timeout_seconds
                    )
                    instructions = _extract_instructions(init_result)
                    return MCPServerInfo(
                        name=config.server_name,
                        version=getattr(init_result, "server_version", None) or "0.0.0",
                        tools=tools,
                        prompts=prompts,
                        resources=resources,
                        instructions=instructions,
                        transport=transport_label,
                        discovery_mode="live",
                    )
    except TimeoutError as exc:
        raise MCPProbeError(f"Timed out connecting to {config.url}") from exc
    except MCPProbeError:
        raise
    except Exception as exc:
        raise MCPProbeError(f"Remote probe failed for {config.url}: {exc}") from exc


async def _list_tools(session: Any, timeout: int) -> list[MCPTool]:
    from mcts.probe.session import _list_tools as list_tools

    return await list_tools(session, timeout)


async def _list_prompts(session: Any, timeout: int) -> list[MCPPrompt]:
    from mcts.probe.session import _list_prompts as list_prompts

    return await list_prompts(session, timeout)


async def _list_resources(session: Any, timeout: int) -> list[MCPResource]:
    from mcts.probe.session import _list_resources as list_resources

    return await list_resources(session, timeout)


def remote_config_from_scan(
    url: str,
    transport: str,
    auth: RemoteAuth | None,
    server_name: str = "remote-server",
) -> RemoteServerConfig:
    return RemoteServerConfig(
        url=url,
        transport=transport,
        auth=auth or RemoteAuth(),
        server_name=server_name,
    )
