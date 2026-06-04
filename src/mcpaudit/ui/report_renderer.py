"""Main terminal report renderer."""

from __future__ import annotations

import shutil

from rich.console import Console

from mcpaudit.reporting.models import ScanReport
from mcpaudit.ui.dashboard import ScanDisplayMeta, build_dashboard
from mcpaudit.ui.layout import center_in_terminal, content_width
from mcpaudit.ui.logo import LOGO_MIN_TERMINAL_WIDTH, render_header
from mcpaudit.ui.theme import Theme, get_theme


class ReportRenderer:
    """Renders scan reports to the terminal using Rich."""

    def __init__(
        self,
        theme: str | Theme = "cyber",
        *,
        console: Console | None = None,
    ) -> None:
        resolved = theme if isinstance(theme, Theme) else get_theme(theme)
        self.theme = resolved
        self.console = console or Console(highlight=False)

    def render(
        self,
        report: ScanReport,
        *,
        command: str | None = None,
        duration_seconds: float = 0.0,
        analyzers_run: int = 6,
    ) -> None:
        """Render the full cybersecurity terminal dashboard."""
        del command  # command is printed during the scan animation phase
        meta = ScanDisplayMeta(
            command="",
            duration_seconds=duration_seconds,
            analyzers_run=analyzers_run,
        )
        term_width = self._terminal_width()
        layout_width = content_width(term_width)

        render_header(
            self.console,
            self.theme,
            terminal_width=term_width,
        )

        dashboard = build_dashboard(
            report,
            meta,
            self.theme,
            terminal_width=term_width,
        )
        self.console.print(
            center_in_terminal(
                dashboard,
                content_width=layout_width,
                terminal_width=term_width,
            )
        )

    def _terminal_width(self) -> int:
        """Best-effort terminal width (IDE terminals often misreport via Rich alone)."""
        try:
            return max(self.console.width, shutil.get_terminal_size().columns)
        except OSError:
            return max(self.console.width, LOGO_MIN_TERMINAL_WIDTH)

    def render_saved_notice(self, path: str) -> None:
        """Themed notice when JSON report is written."""
        p = self.theme.palette
        self.console.print(
            f"[{self.theme.style(p.green, bold=True)}]✓[/] "
            f"[{self.theme.style(p.muted)}]Report written to[/] "
            f"[{self.theme.style(p.command, bold=True)}]{path}[/]",
        )
