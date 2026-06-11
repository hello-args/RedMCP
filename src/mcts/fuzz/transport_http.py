"""Raw HTTP JSON-RPC transport for fuzz probes against remote MCP endpoints."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from mcts.probe.models import RemoteServerConfig

logger = logging.getLogger(__name__)

_JSONRPC_CONTENT_TYPE = {"Content-Type": "application/json"}


async def run_probe_messages_http(
    config: RemoteServerConfig,
    messages: tuple[Any, ...],
    *,
    timeout_seconds: float = 10.0,
    followups: tuple[dict[str, Any], ...] = (),
) -> tuple[str, bool]:
    """POST JSON-RPC payloads to a remote MCP HTTP endpoint and collect responses.

    Returns ``(response_text, server_error)`` matching the stdio transport
    signature so the classifier can be reused without changes.
    ``server_error`` is True when the server returned a 5xx status or the
    connection failed entirely (analogous to ``process_exited`` in stdio).
    """
    auth_headers = config.auth.resolve_headers() if config.auth else {}
    headers = {**_JSONRPC_CONTENT_TYPE, **auth_headers}

    chunks: list[str] = []
    server_error = False

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 10.0)),
            follow_redirects=True,
        ) as client:
            for message in messages:
                body = _encode_body(message)
                text, is_error = await _post_once(client, config.url, body, headers)
                if text:
                    chunks.append(text)
                if is_error:
                    server_error = True

            if (
                followups
                and messages
                and isinstance(messages[0], dict)
                and messages[0].get("method") == "initialize"
            ):
                initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                await _post_once(
                    client,
                    config.url,
                    json.dumps(initialized),
                    headers,
                )

            for followup in followups:
                body = json.dumps(followup)
                text, is_error = await _post_once(client, config.url, body, headers)
                if text:
                    chunks.append(text)
                if is_error:
                    server_error = True

    except httpx.ConnectError:
        chunks.append("")
        server_error = True
    except TimeoutError:
        chunks.append("")

    return "\n".join(chunks), server_error


async def _post_once(
    client: httpx.AsyncClient,
    url: str,
    body: str,
    headers: dict[str, str],
) -> tuple[str, bool]:
    """Send a single POST and return ``(response_text, is_server_error)``."""
    try:
        resp = await client.post(url, content=body, headers=headers)
        is_error = resp.status_code >= 500
        return resp.text, is_error
    except httpx.TimeoutException:
        return "", False
    except httpx.HTTPError as exc:
        return str(exc), True


def _encode_body(message: Any) -> str:
    if isinstance(message, str):
        return message
    return json.dumps(message)
