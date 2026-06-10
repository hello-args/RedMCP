"""Request limits, rate limiting, and scan concurrency controls for the REST API."""

from __future__ import annotations

import asyncio
import os
import threading
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

DEFAULT_MAX_BODY_BYTES = 1_048_576  # 1 MiB
DEFAULT_MAX_CONCURRENT_SCANS = 2
DEFAULT_MAX_FANOUT_ITEMS = 50
DEFAULT_RATE_LIMIT_PER_MINUTE = 30
DEFAULT_MAX_LIST_ITEMS = 100
DEFAULT_MAX_RUNTIME_EVENTS = 500


class _ScanConcurrencyState:
    semaphore: asyncio.Semaphore | None = None
    limit: int = 0


_scan_concurrency = _ScanConcurrencyState()
_rate_lock = threading.Lock()
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def max_body_bytes() -> int:
    return _env_int("MCTS_API_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)


def max_concurrent_scans() -> int:
    return _env_int("MCTS_API_MAX_CONCURRENT_SCANS", DEFAULT_MAX_CONCURRENT_SCANS)


def max_fanout_items() -> int:
    return _env_int("MCTS_API_MAX_FANOUT_ITEMS", DEFAULT_MAX_FANOUT_ITEMS)


def rate_limit_per_minute() -> int:
    return _env_int("MCTS_API_RATE_LIMIT_PER_MINUTE", DEFAULT_RATE_LIMIT_PER_MINUTE)


def max_list_items() -> int:
    return _env_int("MCTS_API_MAX_LIST_ITEMS", DEFAULT_MAX_LIST_ITEMS)


def max_runtime_events() -> int:
    return _env_int("MCTS_API_MAX_RUNTIME_EVENTS", DEFAULT_MAX_RUNTIME_EVENTS)


def _scan_semaphore_for(limit: int) -> asyncio.Semaphore:
    if _scan_concurrency.semaphore is None or _scan_concurrency.limit != limit:
        _scan_concurrency.semaphore = asyncio.Semaphore(limit)
        _scan_concurrency.limit = limit
    return _scan_concurrency.semaphore


def _client_key(request: Request) -> str:
    api_key = request.headers.get("X-API-Key", "").strip()
    if api_key:
        return f"key:{api_key}"
    client = request.client
    host = client.host if client else "unknown"
    return f"ip:{host}"


def reset_rate_limits_for_tests() -> None:
    """Clear in-memory rate limit buckets (test helper)."""
    with _rate_lock:
        _rate_buckets.clear()


def _check_rate_limit(key: str) -> Response | None:
    limit = rate_limit_per_minute()
    now = time.monotonic()
    window_start = now - 60.0
    with _rate_lock:
        bucket = _rate_buckets[key]
        _rate_buckets[key] = [stamp for stamp in bucket if stamp >= window_start]
        if len(_rate_buckets[key]) >= limit:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded; retry later"},
            )
        _rate_buckets[key].append(now)
    return None


def validate_scan_request_payload(payload: dict[str, Any]) -> None:
    """Reject oversized list fields before scan work starts."""
    list_limits = {
        "runtime_events": max_runtime_events(),
        "tool_filter": max_list_items(),
        "analyzer_filter": max_list_items(),
        "severity_filter": max_list_items(),
        "analyzers": max_list_items(),
        "technique_filter": max_list_items(),
        "surfaces": max_list_items(),
        "resource_mime_allowlist": max_list_items(),
    }
    for field, limit in list_limits.items():
        value = payload.get(field)
        if isinstance(value, list) and len(value) > limit:
            raise HTTPException(
                status_code=413,
                detail=f"Field '{field}' exceeds maximum length of {limit}",
            )


class RequestLimitsMiddleware(BaseHTTPMiddleware):
    """Enforce body size and per-client rate limits."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in {"POST", "PUT", "PATCH"}:
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    size = int(content_length)
                except ValueError:
                    size = 0
                if size > max_body_bytes():
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Request body exceeds {max_body_bytes()} bytes"},
                    )

            blocked = _check_rate_limit(_client_key(request))
            if blocked is not None:
                return blocked

        return await call_next(request)


async def run_scan_with_limits(func: Callable[[], Any]) -> Any:
    """Acquire scan semaphore and run blocking scan work off the event loop."""
    semaphore = _scan_semaphore_for(max_concurrent_scans())
    if semaphore.locked() and semaphore._value <= 0:  # noqa: SLF001
        raise HTTPException(status_code=503, detail="Scan queue full; retry later")

    async with semaphore:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func)


def cap_fanout(items: list[Any], *, label: str) -> list[Any]:
    limit = max_fanout_items()
    if len(items) > limit:
        raise HTTPException(
            status_code=413,
            detail=f"Too many {label} ({len(items)}); maximum fan-out is {limit}",
        )
    return items
