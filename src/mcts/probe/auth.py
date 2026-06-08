"""Authentication helpers for remote MCP probing."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx


@dataclass
class RemoteAuth:
    """HTTP auth configuration for remote MCP servers."""

    bearer_token: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    oauth_token_url: str | None = None
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = None
    oauth_scopes: str | None = None

    def resolve_headers(self) -> dict[str, str]:
        headers = dict(self.headers)
        token = self.bearer_token or os.environ.get("MCTS_BEARER_TOKEN")
        if not token and self.oauth_token_url:
            token = self._fetch_oauth_token()
        if token:
            headers.setdefault("Authorization", f"Bearer {token}")
        return headers

    def _fetch_oauth_token(self) -> str | None:
        if not self.oauth_token_url or not self.oauth_client_id:
            return None
        data = {
            "grant_type": "client_credentials",
            "client_id": self.oauth_client_id,
            "client_secret": self.oauth_client_secret or "",
        }
        if self.oauth_scopes:
            data["scope"] = self.oauth_scopes
        try:
            resp = httpx.post(self.oauth_token_url, data=data, timeout=30)
            resp.raise_for_status()
            payload = resp.json()
            return str(payload.get("access_token") or "")
        except (httpx.HTTPError, ValueError):
            return None
