"""Premium HTML security dashboard report generator."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from mcts.brand import logo_data_uri
from mcts.report.data import build_dashboard_payload
from mcts.reporting.models import ScanReport

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATE_DIR = _PACKAGE_ROOT / "templates"
_ASSETS_DIR = _PACKAGE_ROOT / "assets"
_VENDOR_DIR = _ASSETS_DIR / "vendor"


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_icons() -> dict[str, str]:
    icons_dir = _ASSETS_DIR / "icons"
    if not icons_dir.is_dir():
        return {}
    return {path.stem: _read_text(path) for path in sorted(icons_dir.glob("*.svg"))}


def write_html_report(report: ScanReport, output: Path) -> None:
    """Write a self-contained HTML security dashboard from scan results."""
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml")),
    )
    template = env.get_template("dashboard.html")

    payload = build_dashboard_payload(report)
    report_json = json.dumps(payload, default=str).replace("</", "<\\/")
    chart_js = _read_text(_VENDOR_DIR / "chart.umd.min.js")
    dashboard_js = _read_text(_ASSETS_DIR / "dashboard.js")
    html = template.render(
        report_json=report_json,
        styles=_read_text(_ASSETS_DIR / "styles.css"),
        chart_script=f"<script>\n{chart_js}\n</script>",
        dashboard_script=f"<script>\n{dashboard_js}\n</script>",
        logo_src=logo_data_uri(for_report=True),
        icons_json=json.dumps(_load_icons()),
        app_version=report.version,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
