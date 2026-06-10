"""Tests for API startup validation and live consent."""

from __future__ import annotations

import pytest

from mcts.api.startup import is_loopback_host, validate_serve_options


def test_is_loopback_host() -> None:
    assert is_loopback_host("127.0.0.1") is True
    assert is_loopback_host("::1") is True
    assert is_loopback_host("0.0.0.0") is False


def test_validate_serve_rejects_non_loopback_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCTS_API_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        validate_serve_options("0.0.0.0", allow_unauthenticated=False)
    assert exc.value.code == 2


def test_validate_serve_allows_non_loopback_with_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCTS_API_KEY", raising=False)
    validate_serve_options("0.0.0.0", allow_unauthenticated=True)


def test_api_live_scan_requires_consent(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api.app import app

    monkeypatch.delenv("MCTS_LIVE_OK", raising=False)
    client = TestClient(app)
    denied = client.post("/scan", json={"target": ".", "live": True})
    assert denied.status_code == 403
    allowed = client.post(
        "/scan",
        json={"target": ".", "live": True, "understand_live_risk": True},
    )
    assert allowed.status_code != 403


def test_api_live_scan_consent_header(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api.app import app

    monkeypatch.delenv("MCTS_LIVE_OK", raising=False)
    client = TestClient(app)
    allowed = client.post(
        "/scan",
        json={"target": ".", "live": True},
        headers={"X-MCTS-Live-Consent": "1"},
    )
    assert allowed.status_code != 403
