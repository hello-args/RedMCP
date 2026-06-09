"""Tests for expanded client registry."""

from __future__ import annotations

from mcts.inventory.client_registry import SKILL_DIR_CANDIDATES, config_paths_for_platform


def test_client_registry_has_twelve_plus_clients() -> None:
    clients = {client for client, _ in config_paths_for_platform()}
    assert len(clients) >= 12


def test_skill_dirs_cover_all_registry_clients() -> None:
    assert set(SKILL_DIR_CANDIDATES) >= {
        "cursor",
        "claude",
        "windsurf",
        "vscode",
        "gemini",
        "codex",
        "cline",
        "openclaw",
        "zed",
        "roo",
        "continue",
        "amazonq",
    }
