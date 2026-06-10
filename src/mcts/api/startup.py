"""Startup validation for the MCTS REST API server."""

from __future__ import annotations

import ipaddress
import os
import sys


def is_loopback_host(host: str) -> bool:
    """Return True when host binds to a local-only interface."""
    normalized = host.strip().lower()
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def validate_serve_options(host: str, *, allow_unauthenticated: bool) -> None:
    """Refuse insecure non-loopback binds unless explicitly opted in."""
    api_key_set = bool(os.environ.get("MCTS_API_KEY", "").strip())
    if api_key_set:
        return

    loopback = is_loopback_host(host)
    if not loopback and not allow_unauthenticated:
        print(
            "ERROR: MCTS API requires MCTS_API_KEY or --allow-unauthenticated "
            f"when binding to non-loopback host {host!r}.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    if loopback:
        print(
            "WARNING: MCTS API running without authentication (MCTS_API_KEY unset). "
            "Do not expose this server beyond localhost.",
            file=sys.stderr,
        )
        return

    print(
        "WARNING: MCTS API running WITHOUT authentication on a non-loopback interface. "
        "Set MCTS_API_KEY for production deployments.",
        file=sys.stderr,
    )
