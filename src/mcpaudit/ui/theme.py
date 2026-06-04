"""Terminal color themes for MCPAudit CLI output."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mcpaudit.reporting.models import Severity


class ThemeName(StrEnum):
    CYBER = "cyber"
    MINIMAL = "minimal"
    GITHUB = "github"


@dataclass(frozen=True)
class ThemePalette:
    """Color palette for terminal rendering."""

    cyan: str
    blue: str
    red: str
    orange: str
    yellow: str
    green: str
    grey: str
    white: str
    panel_border: str
    logo_gradient: tuple[str, ...]
    subtitle: str
    divider: str
    tip_icon: str
    command: str
    muted: str


CYBER_PALETTE = ThemePalette(
    cyan="#00bfff",
    blue="#0099ff",
    red="#ff4d4f",
    orange="#ff8c00",
    yellow="#ffd43b",
    green="#2ecc71",
    grey="#8b949e",
    white="#f0f6fc",
    panel_border="#0099ff",
    logo_gradient=("#00bfff", "#0099ff", "#0077cc"),
    subtitle="#00bfff",
    divider="#f0f6fc",
    tip_icon="#ffd43b",
    command="#00bfff",
    muted="#8b949e",
)

MINIMAL_PALETTE = ThemePalette(
    cyan="#d0d0d0",
    blue="#a8a8a8",
    red="#ff6b6b",
    orange="#e0a060",
    yellow="#d4c46a",
    green="#7dce94",
    grey="#8b8b8b",
    white="#f5f5f5",
    panel_border="#666666",
    logo_gradient=("#f5f5f5", "#d0d0d0", "#a8a8a8"),
    subtitle="#d0d0d0",
    divider="#f5f5f5",
    tip_icon="#d4c46a",
    command="#d0d0d0",
    muted="#8b8b8b",
)

GITHUB_PALETTE = ThemePalette(
    cyan="#58a6ff",
    blue="#388bfd",
    red="#f85149",
    orange="#db6d28",
    yellow="#d29922",
    green="#3fb950",
    grey="#8b949e",
    white="#f0f6fc",
    panel_border="#30363d",
    logo_gradient=("#58a6ff", "#388bfd", "#1f6feb"),
    subtitle="#58a6ff",
    divider="#f0f6fc",
    tip_icon="#d29922",
    command="#58a6ff",
    muted="#8b949e",
)

THEMES: dict[ThemeName, ThemePalette] = {
    ThemeName.CYBER: CYBER_PALETTE,
    ThemeName.MINIMAL: MINIMAL_PALETTE,
    ThemeName.GITHUB: GITHUB_PALETTE,
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


@dataclass
class Theme:
    """Resolved theme with style helpers."""

    name: ThemeName
    palette: ThemePalette

    def style(self, color: str, *, bold: bool = False, dim: bool = False) -> str:
        parts = []
        if bold:
            parts.append("bold")
        if dim:
            parts.append("dim")
        parts.append(color)
        return " ".join(parts)

    def severity_color(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: self.palette.red,
            Severity.HIGH: self.palette.orange,
            Severity.MEDIUM: self.palette.yellow,
            Severity.LOW: self.palette.green,
        }
        return mapping[severity]

    def severity_label(self, severity: Severity) -> str:
        return severity.value.upper()

    def score_rating(self, score: int) -> tuple[str, str]:
        if score >= 90:
            return "LOW", self.palette.green
        if score >= 70:
            return "ELEVATED", self.palette.yellow
        if score >= 40:
            return "HIGH", self.palette.orange
        return "CRITICAL", self.palette.red

    def risk_index_color(self, risk_index: int) -> str:
        if risk_index >= 75:
            return self.palette.red
        if risk_index >= 50:
            return self.palette.orange
        if risk_index >= 25:
            return self.palette.yellow
        return self.palette.green

    def owasp_count_color(self, count: int, max_count: int) -> str:
        if max_count == 0:
            return self.palette.grey
        ratio = count / max_count
        if ratio >= 0.75:
            return self.palette.red
        if ratio >= 0.5:
            return self.palette.orange
        if ratio >= 0.25:
            return self.palette.yellow
        return self.palette.cyan


def get_theme(name: str) -> Theme:
    """Resolve a theme name to a Theme instance."""
    try:
        theme_name = ThemeName(name.lower())
    except ValueError as exc:
        valid = ", ".join(t.value for t in ThemeName)
        raise ValueError(f"Unknown theme {name!r}. Choose from: {valid}") from exc
    return Theme(name=theme_name, palette=THEMES[theme_name])
