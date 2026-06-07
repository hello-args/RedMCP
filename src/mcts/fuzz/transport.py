"""Raw stdio JSON-RPC transport for fuzz probes."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from mcts.probe.models import LiveServerConfig


async def run_probe_messages(
    config: LiveServerConfig,
    messages: tuple[Any, ...],
    *,
    timeout_seconds: float = 10.0,
    followups: tuple[dict[str, Any], ...] = (),
) -> tuple[str, bool]:
    """Send JSON-RPC lines to a fresh stdio server process and collect stdout."""
    try:
        from mcp import StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as exc:
        raise RuntimeError(
            "Fuzzing requires the optional mcp package. Install with: uv sync --extra mcp"
        ) from exc

    merged_env = {**os.environ, **config.env}
    server_params = StdioServerParameters(
        command=config.command,
        args=config.args,
        env=merged_env,
        cwd=config.cwd,
    )

    chunks: list[str] = []
    process_exited = False

    try:
        async with asyncio.timeout(timeout_seconds):
            async with stdio_client(server_params) as (read, write):
                for message in messages:
                    line = _encode_message(message)
                    write.write(line)
                    await write.drain()
                    chunk = await _read_chunk(read, timeout_seconds)
                    if chunk:
                        chunks.append(chunk)

                if (
                    followups
                    and messages
                    and isinstance(messages[0], dict)
                    and messages[0].get("method") == "initialize"
                ):
                    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                    write.write((json.dumps(initialized) + "\n").encode("utf-8"))
                    await write.drain()

                for followup in followups:
                    line = (json.dumps(followup) + "\n").encode("utf-8")
                    write.write(line)
                    await write.drain()
                    chunk = await _read_chunk(read, timeout_seconds)
                    if chunk:
                        chunks.append(chunk)

    except TimeoutError:
        chunks.append("")
    except Exception as exc:
        chunks.append(str(exc))
        process_exited = True

    return "\n".join(chunks), process_exited


def _encode_message(message: Any) -> bytes:
    if isinstance(message, str):
        return (message + "\n").encode("utf-8")
    return (json.dumps(message) + "\n").encode("utf-8")


async def _read_chunk(read, timeout_seconds: float) -> str:
    try:
        data = await asyncio.wait_for(read.readline(), timeout=timeout_seconds)
    except TimeoutError:
        return ""
    if not data:
        return ""
    return data.decode("utf-8", errors="replace")
