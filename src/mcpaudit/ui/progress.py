"""Hacker-style scan progress animation."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import TypeVar

from rich.console import Console
from rich.text import Text

from mcpaudit.ui.layout import content_width
from mcpaudit.ui.theme import Theme

T = TypeVar("T")

SCAN_PHASES = (
    "Discovering tools",
    "Mapping permissions",
    "Detecting attack chains",
    "Generating report",
)

SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


def print_scan_command(console: Console, theme: Theme, command: str, *, terminal_width: int) -> None:
    """Echo the scan command in terminal style."""
    p = theme.palette
    text = Text()
    text.append("$ ", style=theme.style(p.green, bold=True))
    text.append(command, style=theme.style(p.cyan))
    console.print(text, width=content_width(terminal_width))


def _phase_line(theme: Theme, phase: str, *, done: bool, frame: str = "·") -> Text:
    p = theme.palette
    line = Text()
    line.append("[", style=theme.style(p.grey))
    if done:
        line.append("✓", style=theme.style(p.green, bold=True))
    else:
        line.append(frame, style=theme.style(p.cyan, bold=True))
    line.append("] ", style=theme.style(p.grey))
    line.append(f"{phase}...", style=theme.style(p.white if done else p.cyan))
    return line


def run_with_progress(
    work: Callable[[], T],
    *,
    theme: Theme,
    console: Console | None = None,
    enabled: bool = True,
    min_duration: float = 1.2,
    terminal_width: int = 100,
) -> T:
    """Run scan work with sequential [✓] phase lines before the dashboard."""
    if not enabled:
        return work()

    term_console = console or Console()
    width = content_width(terminal_width)
    result: list[T] = []
    error: list[BaseException] = []
    done = threading.Event()

    def _runner() -> None:
        try:
            result.append(work())
        except BaseException as exc:  # noqa: BLE001
            error.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()

    phase_duration = max(min_duration / len(SCAN_PHASES), 0.28)
    frame_idx = 0

    for index, phase in enumerate(SCAN_PHASES):
        phase_start = time.monotonic()
        is_last = index == len(SCAN_PHASES) - 1

        while True:
            elapsed = time.monotonic() - phase_start
            frame = SPINNER_FRAMES[frame_idx % len(SPINNER_FRAMES)]
            frame_idx += 1
            term_console.print(_phase_line(theme, phase, done=False, frame=frame), width=width, end="\r")

            if done.is_set() and (elapsed >= phase_duration * 0.5 or is_last):
                break
            if elapsed >= phase_duration and not is_last:
                break
            time.sleep(0.07)

        term_console.print(_phase_line(theme, phase, done=True), width=width)

    thread.join()
    if error:
        raise error[0]
    return result[0]
