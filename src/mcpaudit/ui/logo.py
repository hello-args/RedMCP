"""Brand logo and header rendering."""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

from rich.console import Console, Group, RenderableType
from rich.text import Text

from mcpaudit import __version__
from mcpaudit.brand import LOGO_PATH
from mcpaudit.ui.layout import center_in_terminal, content_width
from mcpaudit.ui.theme import Theme

LOGO_WIDTH = 64
LOGO_MIN_TERMINAL_WIDTH = LOGO_WIDTH + 4

# Legacy ASCII fallbacks (used only when PNG cannot be displayed in the terminal).
MCPAUDIT_ASCII = r"""
███╗   ███╗ ██████╗██████╗  █████╗ ██╗   ██╗██████╗ ██╗████████╗
████╗ ████║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
██╔████╔██║██║     ██████╔╝███████║██║   ██║██║  ██║██║   ██║
██║╚██╔╝██║██║     ██╔═══╝ ██╔══██║██║   ██║██║  ██║██║   ██║
██║ ╚═╝ ██║╚██████╗██║     ██║  ██║╚██████╔╝██████╔╝██║   ██║
╚═╝     ╚═╝ ╚═════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
""".strip("\n")

MCPAUDIT_ASCII_PLAIN = r"""
 __  __  ____  ____   _    _   _ _____ ___ _____ _____
|  \/  |/ ___||  _ \ / \  | | | |_   _|_ _|_   _| ____|
| |\/| | |    | |_) / _ \ | | | | | |  | |  | | |  _|
| |  | | |___ |  __/ ___ \| |_| | | |  | |  | | | |___
|_|  |_|\____||_| /_/   \_\\___/  |_| |___| |_| |_____|
""".strip("\n")


def _stdout_supports_unicode_logo() -> bool:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        MCPAUDIT_ASCII.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _terminal_supports_inline_image() -> bool:
    term_program = os.environ.get("TERM_PROGRAM", "")
    if term_program in ("iTerm.app", "WezTerm", "Apple_Terminal"):
        return True
    if os.environ.get("KITTY_WINDOW_ID"):
        return True
    term = os.environ.get("TERM", "")
    return "ghostty" in term.lower() or os.environ.get("GHOSTTY_RESOURCES_DIR") is not None


def _print_inline_png(path: Path, *, max_width_px: int = 360) -> bool:
    """Print PNG via iTerm2/WezTerm inline image protocol (returns False on failure)."""
    if not path.is_file():
        return False
    try:
        data = base64.b64encode(path.read_bytes()).decode("ascii")
        payload = f"\033]1337;File=name={path.name};width={max_width_px};inline=1:{data}\a"
        sys.stdout.write(payload)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return True
    except OSError:
        return False


def build_logo_text(theme: Theme, *, use_unicode: bool = True) -> Text:
    """Legacy ASCII logo (terminal fallback only)."""
    art = MCPAUDIT_ASCII if use_unicode else MCPAUDIT_ASCII_PLAIN
    lines = art.splitlines()
    gradient = theme.palette.logo_gradient
    text = Text()
    for line_idx, line in enumerate(lines):
        if line_idx:
            text.append("\n")
        for char_idx, char in enumerate(line):
            if char == " ":
                text.append(char)
            else:
                color = gradient[char_idx % len(gradient)]
                text.append(char, style=theme.style(color, bold=True))
    return text


def render_brand_logo(console: Console, theme: Theme, *, layout_width: int) -> bool:
    """Render the canonical PNG logo when the terminal supports inline images."""
    del theme, layout_width
    if not _terminal_supports_inline_image():
        return False
    return _print_inline_png(LOGO_PATH)


def render_header(
    console: Console,
    theme: Theme,
    *,
    terminal_width: int | None = None,
) -> None:
    """Render logo, tagline, version."""
    term_width = terminal_width or console.width
    layout_width = content_width(term_width)
    header_parts: list[RenderableType] = []

    if not render_brand_logo(console, theme, layout_width=layout_width):
        use_unicode = _stdout_supports_unicode_logo()
        header_parts.append(
            build_logo_text(
                theme,
                use_unicode=use_unicode and layout_width >= LOGO_MIN_TERMINAL_WIDTH,
            )
        )

    header_parts.append(
        Text(
            "The Security Linter for Model Context Protocol Servers",
            style=theme.style(theme.palette.subtitle, bold=True),
            justify="center",
        )
    )
    header_parts.append(
        Text(
            f"v{__version__}-alpha",
            style=theme.style(theme.palette.grey, dim=True),
            justify="center",
        )
    )

    if header_parts:
        console.print(
            center_in_terminal(
                Group(*header_parts),
                content_width=layout_width,
                terminal_width=term_width,
            )
        )
