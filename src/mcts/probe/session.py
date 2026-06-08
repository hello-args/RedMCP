"""Async stdio MCP probe session."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from mcts.capability.inferrer import infer_capability
from mcts.mcp.models import MCPPrompt, MCPResource, MCPServerInfo, MCPTool
from mcts.probe.models import LiveServerConfig

logger = logging.getLogger(__name__)


class MCPProbeError(RuntimeError):
    """Raised when live MCP probing fails."""


class MCPNotInstalledError(MCPProbeError):
    """Raised when the optional ``mcp`` package is not installed."""


def probe_stdio_sync(config: LiveServerConfig, timeout_seconds: int = 120) -> MCPServerInfo:
    """Run a stdio probe synchronously (CLI entry point)."""
    return asyncio.run(probe_stdio(config, timeout_seconds))


async def probe_stdio(config: LiveServerConfig, timeout_seconds: int = 120) -> MCPServerInfo:
    """Connect to a stdio MCP server and list tools, prompts, and resources."""
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as exc:
        raise MCPNotInstalledError(
            "Live probing requires the optional mcp package. Install with: uv sync --extra mcp"
        ) from exc

    merged_env = {**os.environ, **config.env}
    errlog = None
    if config.stderr_file:
        errlog = open(config.stderr_file, "w", encoding="utf-8")  # noqa: SIM115
    server_params = StdioServerParameters(
        command=config.command,
        args=config.args,
        env=merged_env,
        cwd=config.cwd,
        errlog=errlog,
    )

    connect_timeout = min(timeout_seconds, 30)
    session_timeout = timeout_seconds

    try:
        async with asyncio.timeout(connect_timeout):
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    init_result = await asyncio.wait_for(
                        session.initialize(),
                        timeout=session_timeout,
                    )
                    tools = await _list_tools(session, session_timeout)
                    prompts = await _list_prompts(session, session_timeout)
                    resources = await _list_resources(session, session_timeout)
                    from mcts.probe.resources import enrich_resources_with_content

                    resources = await enrich_resources_with_content(
                        session, resources, timeout=session_timeout
                    )
                    instructions = _extract_instructions(init_result)

                    return MCPServerInfo(
                        name=config.server_name,
                        version=getattr(init_result, "server_version", None)
                        or getattr(getattr(init_result, "serverInfo", None), "version", None)
                        or "0.0.0",
                        tools=tools,
                        prompts=prompts,
                        resources=resources,
                        instructions=instructions,
                        transport="stdio-live",
                        discovery_mode="live",
                    )
    except TimeoutError as exc:
        raise MCPProbeError(
            f"Timed out connecting to MCP server '{config.command}' after {connect_timeout}s"
        ) from exc
    except MCPProbeError:
        raise
    except Exception as exc:
        raise MCPProbeError(f"Live probe failed for '{config.command}': {exc}") from exc


async def _list_tools(session: Any, timeout: int) -> list[MCPTool]:
    try:
        result = await asyncio.wait_for(session.list_tools(), timeout=timeout)
    except Exception as exc:
        logger.warning("list_tools failed: %s", exc)
        return []
    return [_tool_from_mcp(tool) for tool in result.tools]


async def _list_prompts(session: Any, timeout: int) -> list[MCPPrompt]:
    if not hasattr(session, "list_prompts"):
        return []
    try:
        result = await asyncio.wait_for(session.list_prompts(), timeout=timeout)
    except Exception as exc:
        logger.warning("list_prompts failed: %s", exc)
        return []
    return [_prompt_from_mcp(prompt) for prompt in result.prompts]


async def _list_resources(session: Any, timeout: int) -> list[MCPResource]:
    if not hasattr(session, "list_resources"):
        return []
    try:
        result = await asyncio.wait_for(session.list_resources(), timeout=timeout)
    except Exception as exc:
        logger.warning("list_resources failed: %s", exc)
        return []
    return [_resource_from_mcp(resource) for resource in result.resources]


def _extract_instructions(init_result: Any) -> str | None:
    instructions = getattr(init_result, "instructions", None)
    if isinstance(instructions, str) and instructions.strip():
        return instructions.strip()
    return None


def _tool_from_mcp(tool: Any) -> MCPTool:
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None) or {}
    if not isinstance(schema, dict):
        schema = {}
    mcts_tool = MCPTool(
        name=tool.name,
        description=getattr(tool, "description", None) or "",
        input_schema=schema,
    )
    mcts_tool.capability = infer_capability(mcts_tool)
    return mcts_tool


def _prompt_from_mcp(prompt: Any) -> MCPPrompt:
    arguments = []
    for arg in getattr(prompt, "arguments", []) or []:
        arguments.append(
            {
                "name": getattr(arg, "name", ""),
                "description": getattr(arg, "description", "") or "",
                "required": getattr(arg, "required", False),
            }
        )
    return MCPPrompt(
        name=prompt.name,
        description=getattr(prompt, "description", None) or "",
        arguments=arguments,
    )


def _resource_from_mcp(resource: Any) -> MCPResource:
    return MCPResource(
        uri=getattr(resource, "uri", ""),
        name=getattr(resource, "name", None) or "",
        description=getattr(resource, "description", None) or "",
        mime_type=getattr(resource, "mimeType", None) or getattr(resource, "mime_type", None),
    )
