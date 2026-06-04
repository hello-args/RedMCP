"""Tests for layout width helpers."""

from mcpaudit.ui.layout import CONTENT_MAX_WIDTH, content_width


def test_content_width_clamps_wide_terminal() -> None:
    assert content_width(200) == CONTENT_MAX_WIDTH


def test_content_width_respects_narrow_terminal() -> None:
    assert content_width(80) == 80
