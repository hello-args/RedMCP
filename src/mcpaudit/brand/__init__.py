"""Canonical MCPAudit brand assets."""

from __future__ import annotations

import base64
from pathlib import Path

BRAND_DIR = Path(__file__).resolve().parent
LOGO_PATH = BRAND_DIR / "logo.png"
LOGO_REPORT_PATH = BRAND_DIR / "logo-report.png"


def logo_data_uri(*, for_report: bool = True) -> str:
    """Return a data URI for embedding the logo in HTML."""
    path = LOGO_REPORT_PATH if for_report and LOGO_REPORT_PATH.is_file() else LOGO_PATH
    payload = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{payload}"
