"""Layout helpers for fixed-width terminal dashboards."""

from __future__ import annotations

from rich.align import Align
from rich.console import RenderableType

# Keep dashboard readable on ultra-wide terminals (IDE panes often report 150–200+ cols).
CONTENT_MAX_WIDTH = 100
CONTENT_MIN_WIDTH = 72
SEVERITY_PANEL_WIDTH = 34
FINDINGS_PANEL_MIN_WIDTH = 52


def content_width(terminal_width: int) -> int:
    """Clamp layout width for a balanced dashboard on any terminal size."""
    return max(CONTENT_MIN_WIDTH, min(terminal_width, CONTENT_MAX_WIDTH))


def center_in_terminal(
    renderable: RenderableType,
    *,
    content_width: int,
    terminal_width: int,
) -> RenderableType:
    """Center a fixed-width block inside a possibly wider terminal."""
    inner = Align.center(renderable, width=content_width)
    if terminal_width <= content_width:
        return inner
    return Align.center(inner, width=terminal_width)
