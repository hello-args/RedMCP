# HTML Security Dashboard

MCPAudit generates a **self-contained HTML security dashboard** from any JSON scan report. The UI is designed for security engineers and executives — comparable in density and clarity to products like Wiz, Prisma Cloud, Datadog Security, Snyk, and Microsoft Defender secure score views.

## Generate a report

```bash
# 1. Run a scan and save JSON
mcpaudit scan examples/vulnerable-mcp-server/server.py -o report.json

# 2. Build the HTML dashboard
mcpaudit report report.json -o security-report.html

# 3. Open in a browser
open security-report.html   # macOS
```

The output is a single HTML file with inlined CSS and JavaScript. **Chart.js** and **Inter** load from CDN; all scan data and brand assets are embedded so the file works offline after first load.

## Dashboard sections

### Overview

| Row | Content |
|-----|---------|
| **Metrics** | Overall risk score (gauge, grade, posture badge) + five severity cards (Critical, High, Medium, Low, Tools) |
| **Summary** | Full-width Security Posture Summary with recommended actions (P1/P2 badges) |
| **Breakdown** | Category risk metrics with progress bars + radar chart (your score vs industry benchmark) |
| **Trend** | Score history when multiple scans exist; otherwise a clear “No Historical Data” state |
| **Guide** | Risk level reference cards (0–25 Critical through 76–100 Low) |

### Additional pages (sidebar navigation)

- **Findings** — Searchable, filterable, sortable table (severity, OWASP, tool, remediation)
- **Analyzers** — Per-analyzer finding counts and severity breakdown
- **Attack Chains** — SVG tool dependency graph from chain analysis
- **OWASP Mapping** — LLM Top 10 categories with finding counts and affected tools
- **Recommendations** — Prioritized remediation (P1–P4)
- **Appendix** — Raw JSON for auditors and integrations

## Scoring display

The dashboard surfaces the same auditable scoring as the CLI:

- **Security score** (`score.overall`) — 0–100, higher is better; exponential decay from weighted findings
- **Security grade** — Letter grade A–F (e.g. **F** when score &lt; 60)
- **Risk posture** — Critical / High / Medium / Low risk label
- **ⓘ tooltip** — How the score is derived (severity weights, attack chains, OWASP mapping)

Severity cards show **finding counts**; category breakdown bars show **exposure per analyzer category** (higher bar = more risk in that dimension). A low overall score with high category bars is expected and documented in the UI.

## Export from the browser

Use the header **Export** menu or sidebar **Download JSON Report**:

| Action | Description |
|--------|-------------|
| **JSON** | Download the embedded raw `ScanReport` |
| **HTML** | Save the current page as HTML |
| **PDF (Print)** | Browser print dialog for executive PDFs |

## Implementation

```
src/mcpaudit/report/
├── templates/dashboard.html   # Jinja2 shell
├── assets/
│   ├── styles.css           # Enterprise card design system
│   ├── dashboard.js         # Charts, tables, navigation
│   └── icons/               # SVG severity icons
├── data.py                  # ScanReport → dashboard JSON payload
└── generators/html_report.py

src/mcpaudit/brand/
├── logo.png                 # Canonical MCPAudit logo
└── logo-report.png          # Optimized embed for HTML
```

Entry point: `mcpaudit report` → `mcpaudit.reporting.html.write_html_report()` → `report.generators.html_report.write_html_report()`.

## Design system (cards)

All dashboard cards share:

- Background `#0b1730`, 16px radius
- Border `1px solid rgba(255,255,255,.06)`
- Shadow `0 8px 32px rgba(0,0,0,.35)`
- Hover lift and 200ms transitions

Severity cards use a **4px top accent**, severity gradients, large numeric counts, and footer risk badges.

## Related docs

- [CLI Reference — `mcpaudit report`](cli.md#mcpaudit-report)
- [Architecture — Reporting](architecture.md#reporting)
- [Getting Started](getting-started.md)
