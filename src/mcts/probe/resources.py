"""Read MCP resource contents during live probes."""

from __future__ import annotations

import logging
from typing import Any

from mcts.mcp.models import MCPResource

logger = logging.getLogger(__name__)

_TEXT_MIME_PREFIXES = ("text/", "application/json", "application/xml", "application/javascript")
_TEXT_MIME_EXACT = frozenset(
    {
        "application/json",
        "application/ld+json",
        "application/xml",
        "application/xhtml+xml",
    }
)
_SKIP_MIME_PREFIXES = ("image/", "video/", "audio/", "application/octet-stream", "application/pdf")


def is_text_resource(mime_type: str | None) -> bool:
    if not mime_type:
        return True
    lowered = mime_type.lower().split(";")[0].strip()
    if any(lowered.startswith(prefix) for prefix in _SKIP_MIME_PREFIXES):
        return False
    if lowered in _TEXT_MIME_EXACT:
        return True
    return any(lowered.startswith(prefix) for prefix in _TEXT_MIME_PREFIXES)


async def enrich_resources_with_content(
    session: Any,
    resources: list[MCPResource],
    *,
    timeout: int,
    max_bytes: int = 100_000,
) -> list[MCPResource]:
    """Call resources/read for text-like resources and attach content."""
    if not hasattr(session, "read_resource"):
        return resources
    enriched: list[MCPResource] = []
    for resource in resources:
        if not resource.uri or not is_text_resource(resource.mime_type):
            enriched.append(resource)
            continue
        content = await _read_resource_text(session, resource.uri, timeout, max_bytes)
        if content is None:
            enriched.append(resource)
        else:
            enriched.append(resource.model_copy(update={"content": content}))
    return enriched


async def _read_resource_text(
    session: Any,
    uri: str,
    timeout: int,
    max_bytes: int,
) -> str | None:
    import asyncio

    try:
        result = await asyncio.wait_for(session.read_resource(uri), timeout=timeout)
    except Exception as exc:
        logger.debug("read_resource failed for %s: %s", uri, exc)
        return None
    chunks: list[str] = []
    contents = getattr(result, "contents", None) or []
    for item in contents:
        text = getattr(item, "text", None)
        if isinstance(text, str) and text:
            chunks.append(text)
            continue
        blob = getattr(item, "blob", None)
        if isinstance(blob, bytes):
            try:
                chunks.append(blob.decode("utf-8", errors="replace"))
            except Exception:
                continue
    if not chunks:
        return None
    joined = "\n".join(chunks)
    return joined[:max_bytes]
