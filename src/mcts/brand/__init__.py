"""Canonical MCTS brand assets."""

from __future__ import annotations

import base64
from pathlib import Path

BRAND_DIR = Path(__file__).resolve().parent
LOGO_PATH = BRAND_DIR / "logo.png"
LOGO_JPG_PATH = BRAND_DIR / "logo.jpg"
LOGO_REPORT_PATH = BRAND_DIR / "logo-report.png"  # hex icon only for small HTML embeds


def logo_data_uri(*, for_report: bool = True) -> str:
    """Return a data URI for embedding the logo in HTML.

    Reports use ``logo-report.png`` (hex mark only) so the sidebar stays legible
    at 44×44px. Terminals and large displays use the full ``logo.png``.
    """
    path = LOGO_REPORT_PATH if for_report and LOGO_REPORT_PATH.is_file() else LOGO_PATH
    payload = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{payload}"
