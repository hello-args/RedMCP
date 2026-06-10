"""Tests for API rate limits, body caps, and scan concurrency."""

from __future__ import annotations

import pytest


def test_api_rejects_oversized_content_length(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api import limits
    from mcts.api.app import app

    monkeypatch.setattr(limits, "max_body_bytes", lambda: 128)
    client = TestClient(app)
    response = client.post(
        "/scan",
        json={"target": "."},
        headers={"Content-Length": "9999"},
    )
    assert response.status_code == 413


def test_api_rejects_oversized_runtime_events(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api import limits
    from mcts.api.app import app

    monkeypatch.setattr(limits, "max_runtime_events", lambda: 2)
    client = TestClient(app)
    response = client.post(
        "/scan",
        json={"target": ".", "runtime_events": [{}, {}, {}]},
    )
    assert response.status_code == 422


def test_api_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api import limits
    from mcts.api.app import app

    limits.reset_rate_limits_for_tests()
    monkeypatch.setattr(limits, "rate_limit_per_minute", lambda: 1)
    client = TestClient(app)
    first = client.post("/readiness", json={"target": "."})
    second = client.post("/readiness", json={"target": "."})
    assert first.status_code == 200
    assert second.status_code == 429
