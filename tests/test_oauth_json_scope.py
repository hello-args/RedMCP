"""Tests for OAuth URL extraction scope in repo JSON scans."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.analyzers.oauth_config import OAuthConfigAnalyzer
from mcts.mcp.models import MCPServerInfo


def _server() -> MCPServerInfo:
    return MCPServerInfo(name="test", tools=[], source_files={})


def test_scraped_json_http_urls_are_not_flagged_as_oauth(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    payload = {
        "records": [
            {
                "homepage": "http://example.com/docs",
                "callback": "http://example.com/api/oauth/callback",
            }
        ]
    }
    (data_dir / "scraped.json").write_text(json.dumps(payload), encoding="utf-8")

    findings = OAuthConfigAnalyzer(target=tmp_path).analyze(_server())
    assert not any(f.title == "OAuth endpoint uses plaintext HTTP" for f in findings)


def test_oauth_authorization_endpoint_http_still_flagged(tmp_path: Path) -> None:
    config = tmp_path / "oauth-settings.json"
    config.write_text(
        json.dumps(
            {
                "oauth": {
                    "authorization_endpoint": "http://auth.example.com/oauth2/authorize",
                }
            }
        ),
        encoding="utf-8",
    )

    findings = OAuthConfigAnalyzer(target=tmp_path).analyze(_server())
    assert any(
        f.analyzer == "oauth_config"
        and f.title == "OAuth endpoint uses plaintext HTTP"
        and f.severity.value == "high"
        for f in findings
    )


def test_non_oauth_http_field_is_ignored(tmp_path: Path) -> None:
    config = tmp_path / "metadata.json"
    config.write_text(
        json.dumps({"documentation": "http://example.com/guide", "version": "1.0"}),
        encoding="utf-8",
    )

    findings = OAuthConfigAnalyzer(target=tmp_path).analyze(_server())
    assert not any(f.analyzer == "oauth_config" for f in findings)


def test_fixtures_directory_json_is_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "oauth.json").write_text(
        json.dumps(
            {
                "oauth": {
                    "authorization_endpoint": "http://auth.example.com/oauth2/authorize",
                }
            }
        ),
        encoding="utf-8",
    )

    findings = OAuthConfigAnalyzer(target=tmp_path).analyze(_server())
    assert not findings
