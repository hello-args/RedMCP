"""HTML report generation."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template

from mcpaudit.reporting.models import ScanReport

HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>MCPAudit Security Report</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
    h1 { color: #c0392b; }
    .score { font-size: 2rem; font-weight: bold; }
    .finding { border-left: 4px solid #ccc; padding: 1rem; margin: 1rem 0; background: #fafafa; }
    .critical { border-color: #c0392b; }
    .high { border-color: #e67e22; }
    .medium { border-color: #f1c40f; }
    .low { border-color: #3498db; }
    .meta { color: #666; }
  </style>
</head>
<body>
  <h1>MCPAudit Security Report</h1>
  <p class="meta">Target: {{ report.target }} · Scanned: {{ report.scanned_at }}</p>
  <p class="score">
    Security Score: {{ report.score.overall }}/100 ·
    Risk Index: {{ report.score.risk_index }}/100
  </p>
  <p>
    Critical: {{ report.summary.critical }} ·
    High: {{ report.summary.high }} ·
    Medium: {{ report.summary.medium }} ·
    Low: {{ report.summary.low }}
  </p>
  <hr>
  {% for finding in report.findings %}
  <div class="finding {{ finding.severity.value }}">
    <h3>[{{ finding.severity.value | upper }}] {{ finding.title }}</h3>
    <p>{{ finding.description }}</p>
    <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
  </div>
  {% endfor %}
</body>
</html>
""")


def write_html_report(report: ScanReport, output: Path) -> None:
    """Write a standalone HTML security report."""
    output.write_text(HTML_TEMPLATE.render(report=report), encoding="utf-8")
