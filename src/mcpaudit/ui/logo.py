"""ASCII logo and header rendering."""

from __future__ import annotations

import sys

from rich.console import Console, Group, RenderableType
from rich.text import Text

from mcpaudit import __version__
from mcpaudit.ui.layout import center_in_terminal, content_width
from mcpaudit.ui.theme import Theme

# Unicode block-letter logo (64 cols wide).
MCPAUDIT_ASCII = r"""
███╗   ███╗ ██████╗██████╗  █████╗ ██╗   ██╗██████╗ ██╗████████╗
████╗ ████║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
██╔████╔██║██║     ██████╔╝███████║██║   ██║██║  ██║██║   ██║
██║╚██╔╝██║██║     ██╔═══╝ ██╔══██║██║   ██║██║  ██║██║   ██║
██║ ╚═╝ ██║╚██████╗██║     ██║  ██║╚██████╔╝██████╔╝██║   ██║
╚═╝     ╚═╝ ╚═════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
""".strip("\n")

# Pure-ASCII fallback when Unicode block chars cannot be encoded.
MCPAUDIT_ASCII_PLAIN = r"""
 __  __  ____  ____   _    _   _ _____ ___ _____ _____ 
|  \/  |/ ___||  _ \ / \  | | | |_   _|_ _|_   _| ____|
| |\/| | |    | |_) / _ \ | | | | | |  | |  | | |  _|  
| |  | | |___ |  __/ ___ \| |_| | | |  | |  | | | |___ 
|_|  |_|\____||_| /_/   \_\\___/  |_| |___| |_| |_____|
""".strip("\n")

LOGO_WIDTH = max(len(line) for line in MCPAUDIT_ASCII.splitlines())
LOGO_MIN_TERMINAL_WIDTH = LOGO_WIDTH + 4


def _stdout_supports_unicode_logo() -> bool:
    """Return True if the logo can be encoded for this stdout."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        MCPAUDIT_ASCII.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def build_logo_text(theme: Theme, *, use_unicode: bool = True) -> Text:
    """Build gradient-styled ASCII logo."""
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


def render_header(
    console: Console,
    theme: Theme,
    *,
    terminal_width: int | None = None,
) -> None:
    """Render logo, tagline, version, and optional command echo."""
    term_width = terminal_width or console.width
    layout_width = content_width(term_width)
    use_unicode = _stdout_supports_unicode_logo()

    header_parts: list[RenderableType] = []

    logo = build_logo_text(theme, use_unicode=use_unicode and layout_width >= LOGO_MIN_TERMINAL_WIDTH)
    header_parts.append(logo)
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

    console.print(
        center_in_terminal(
            Group(*header_parts),
            content_width=layout_width,
            terminal_width=term_width,
        )
    )
