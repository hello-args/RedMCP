"""Canonical MCTS brand assets."""

from __future__ import annotations

import base64
from pathlib import Path

BRAND_DIR = Path(__file__).resolve().parent
_SHIELD_ICON = BRAND_DIR.parent / "report" / "assets" / "icons" / "shield.svg"


def logo_data_uri(*, for_report: bool = True) -> str:
    """Return a data URI for embedding the sidebar icon in HTML reports."""
    del for_report
    if not _SHIELD_ICON.is_file():
        return ""
    payload = base64.b64encode(_SHIELD_ICON.read_bytes()).decode("ascii")
    return f"data:image/svg+xml;base64,{payload}"
