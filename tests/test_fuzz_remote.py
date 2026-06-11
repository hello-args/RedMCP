"""Tests for remote HTTP/SSE fuzz transport and runner integration."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mcts.core.config import ScanConfig
from mcts.fuzz.runner import FuzzRunner
from mcts.fuzz.transport_http import run_probe_messages_http
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.probe.models import RemoteServerConfig
from mcts.reporting.models import Severity


def _remote_config(url: str = "https://mcp.example.com/mcp") -> RemoteServerConfig:
    return RemoteServerConfig(url=url, transport="streamable-http")


def _scan_config(**overrides: Any) -> ScanConfig:
    defaults: dict[str, Any] = {
        "target": Path("."),
        "live_consent": True,
        "fuzz_level": "safe",
        "remote_url": "https://mcp.example.com/mcp",
        "remote_transport": "streamable-http",
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


def _fake_server(tool_names: tuple[str, ...] = ("read_file",)) -> MCPServerInfo:
    return MCPServerInfo(
        name="remote-test",
        tools=[MCPTool(name=n) for n in tool_names],
        transport="streamable-http-live",
        discovery_mode="live",
        initialize_succeeded=True,
    )


# ---------------------------------------------------------------------------
# transport_http unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_transport_posts_jsonrpc() -> None:
    """Verify run_probe_messages_http sends JSON-RPC messages via POST."""
    response = httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Not found"}},
    )
    transport = httpx.MockTransport(lambda req: response)

    cfg = _remote_config("https://mcp.test/mcp")
    async with httpx.AsyncClient(transport=transport) as _:
        with patch("mcts.fuzz.transport_http.httpx.AsyncClient") as mock_cls:
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=ctx)
            ctx.__aexit__ = AsyncMock(return_value=False)
            ctx.post = AsyncMock(return_value=response)
            mock_cls.return_value = ctx

            text, server_error = await run_probe_messages_http(
                cfg,
                ({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},),
                timeout_seconds=5.0,
            )

    assert "Not found" in text
    assert server_error is False


@pytest.mark.asyncio
async def test_http_transport_flags_server_error() -> None:
    """A 500 response should set server_error=True."""
    response = httpx.Response(500, text="Internal Server Error")
    cfg = _remote_config()

    with patch("mcts.fuzz.transport_http.httpx.AsyncClient") as mock_cls:
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=ctx)
        ctx.__aexit__ = AsyncMock(return_value=False)
        ctx.post = AsyncMock(return_value=response)
        mock_cls.return_value = ctx

        text, server_error = await run_probe_messages_http(
            cfg,
            ({"jsonrpc": "2.0", "id": 1, "params": {}},),
            timeout_seconds=5.0,
        )

    assert server_error is True
    assert "Internal Server Error" in text


@pytest.mark.asyncio
async def test_http_transport_handles_connect_error() -> None:
    """Connection failure should return empty text with server_error=True."""
    cfg = _remote_config()

    with patch("mcts.fuzz.transport_http.httpx.AsyncClient") as mock_cls:
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=ctx)
        ctx.__aexit__ = AsyncMock(return_value=False)
        ctx.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_cls.return_value = ctx

        text, server_error = await run_probe_messages_http(
            cfg,
            ({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},),
        )

    assert server_error is True


@pytest.mark.asyncio
async def test_http_transport_sends_malformed_json_as_string() -> None:
    """Malformed JSON (a raw string probe) should be sent as-is."""
    response = httpx.Response(400, text="Bad Request")
    cfg = _remote_config()

    with patch("mcts.fuzz.transport_http.httpx.AsyncClient") as mock_cls:
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=ctx)
        ctx.__aexit__ = AsyncMock(return_value=False)
        ctx.post = AsyncMock(return_value=response)
        mock_cls.return_value = ctx

        text, _ = await run_probe_messages_http(
            cfg,
            ("{ not valid json",),
            timeout_seconds=5.0,
        )

    posted_body = ctx.post.call_args[1].get("content") or ctx.post.call_args[0][1]
    assert "not valid json" in str(posted_body)


@pytest.mark.asyncio
async def test_http_transport_sends_auth_headers() -> None:
    """Bearer token from RemoteServerConfig should appear in POST headers."""
    from mcts.probe.auth import RemoteAuth

    response = httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
    auth = RemoteAuth(bearer_token="test-token-xyz")
    cfg = RemoteServerConfig(
        url="https://mcp.test/mcp",
        transport="streamable-http",
        auth=auth,
    )

    with patch("mcts.fuzz.transport_http.httpx.AsyncClient") as mock_cls:
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=ctx)
        ctx.__aexit__ = AsyncMock(return_value=False)
        ctx.post = AsyncMock(return_value=response)
        mock_cls.return_value = ctx

        await run_probe_messages_http(
            cfg,
            ({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},),
        )

    call_headers = ctx.post.call_args[1].get("headers", {})
    assert call_headers.get("Authorization") == "Bearer test-token-xyz"


@pytest.mark.asyncio
async def test_http_transport_sends_followups_after_initialized() -> None:
    """Followup messages should be preceded by notifications/initialized."""
    response = httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": 1, "result": {}},
    )
    cfg = _remote_config()
    posted_bodies: list[str] = []

    async def capture_post(url: str, *, content: str, headers: Any) -> httpx.Response:
        posted_bodies.append(content)
        return response

    with patch("mcts.fuzz.transport_http.httpx.AsyncClient") as mock_cls:
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=ctx)
        ctx.__aexit__ = AsyncMock(return_value=False)
        ctx.post = AsyncMock(side_effect=capture_post)
        mock_cls.return_value = ctx

        await run_probe_messages_http(
            cfg,
            ({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},),
            followups=({"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},),
        )

    assert len(posted_bodies) == 3
    assert "notifications/initialized" in posted_bodies[1]
    assert "tools/list" in posted_bodies[2]


# ---------------------------------------------------------------------------
# FuzzRunner remote integration tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_remote_runner_collects_findings() -> None:
    """FuzzRunner should route through HTTP transport when remote_url is set."""
    config = _scan_config()
    runner = FuzzRunner(config)

    async def fake_http_probe(*_args: Any, **_kwargs: Any) -> tuple[str, bool]:
        return "Traceback (most recent call last)", False

    with (
        patch(
            "mcts.fuzz.runner.probe_remote",
            new=AsyncMock(return_value=_fake_server()),
        ),
        patch(
            "mcts.fuzz.runner.run_probe_messages_http",
            new=AsyncMock(side_effect=fake_http_probe),
        ),
    ):
        result = await runner.run_async()

    assert result.probes_run >= 5
    assert result.findings
    assert result.findings[0].analyzer == "fuzz"
    assert result.findings[0].evidence.get("transport") == "http"
    assert result.findings[0].evidence.get("remote_url") == "https://mcp.example.com/mcp"


@pytest.mark.asyncio
async def test_remote_runner_no_findings_on_clean_responses() -> None:
    """Clean JSON-RPC errors from a remote server should produce zero findings."""
    config = _scan_config()
    runner = FuzzRunner(config)

    async def clean_response(*_a: Any, **_kw: Any) -> tuple[str, bool]:
        return '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Not found"}}', False

    with (
        patch("mcts.fuzz.runner.probe_remote", new=AsyncMock(return_value=_fake_server())),
        patch("mcts.fuzz.runner.run_probe_messages_http", new=AsyncMock(side_effect=clean_response)),
    ):
        result = await runner.run_async()

    assert result.probes_run >= 5
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_remote_runner_aggressive_requires_consent() -> None:
    """Aggressive fuzz on a remote server still requires --i-understand-fuzz-risk."""
    config = _scan_config(fuzz_level="aggressive", fuzz_consent=False)
    with pytest.raises(ValueError, match="Aggressive fuzz"):
        await FuzzRunner(config).run_async()


@pytest.mark.asyncio
async def test_remote_runner_requires_live_consent() -> None:
    """Remote fuzz should require live consent."""
    from mcts.probe.consent import LiveProbeConsentError

    config = _scan_config(live_consent=False)
    with pytest.raises(LiveProbeConsentError):
        await FuzzRunner(config).run_async()


@pytest.mark.asyncio
async def test_remote_runner_uses_probe_remote_for_discovery() -> None:
    """Tool discovery for remote fuzz should use probe_remote, not probe_stdio."""
    config = _scan_config()
    runner = FuzzRunner(config)

    mock_remote = AsyncMock(return_value=_fake_server(("tool_a", "tool_b")))

    async def noop_probe(*_a: Any, **_kw: Any) -> tuple[str, bool]:
        return "", False

    with (
        patch("mcts.fuzz.runner.probe_remote", new=mock_remote),
        patch("mcts.fuzz.runner.run_probe_messages_http", new=AsyncMock(side_effect=noop_probe)),
    ):
        result = await runner.run_async()

    mock_remote.assert_awaited_once()
    assert result.probes_run >= 5


@pytest.mark.asyncio
async def test_stdio_runner_still_works_without_url() -> None:
    """Stdio fuzz path should be unaffected by the remote changes."""
    config = ScanConfig(
        target=Path("examples/live-mcp-server/server.py"),
        live_consent=True,
        fuzz_level="safe",
    )
    runner = FuzzRunner(config)

    async def fake_probe(*_a: Any, **_kw: Any) -> tuple[str, bool]:
        return "Traceback (most recent call last)", False

    with (
        patch("mcts.fuzz.runner.resolve_live_config", return_value=None),
        patch("mcts.fuzz.runner.probe_stdio", new=AsyncMock(return_value=_fake_server())),
        patch("mcts.fuzz.runner.run_probe_messages", new=AsyncMock(side_effect=fake_probe)),
    ):
        result = await runner.run_async()

    assert result.probes_run >= 5
    assert result.findings
    assert "transport" not in result.findings[0].evidence


@pytest.mark.asyncio
async def test_remote_runner_classifier_detects_server_crash() -> None:
    """HTTP 500 / server_error=True should be classified as a finding."""
    config = _scan_config()
    runner = FuzzRunner(config)

    async def server_crash(*_a: Any, **_kw: Any) -> tuple[str, bool]:
        return "500 Internal Server Error", True

    with (
        patch("mcts.fuzz.runner.probe_remote", new=AsyncMock(return_value=_fake_server())),
        patch("mcts.fuzz.runner.run_probe_messages_http", new=AsyncMock(side_effect=server_crash)),
    ):
        result = await runner.run_async()

    server_error_findings = [
        f for f in result.findings if "server" in f.title.lower() or f.severity == Severity.HIGH
    ]
    assert server_error_findings
