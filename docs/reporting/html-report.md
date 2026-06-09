# HTML Security Dashboard

> [Documentation](../index.md) → [Reporting](README.md)

The HTML dashboard turns a JSON scan report into a **shareable, self-contained web page** — suitable for security reviews, leadership briefings, or audit documentation.

> **Haven't generated a report yet?** Run `mcts scan ./server.py -o report.json` first, then `mcts report report.json -o report.html`.

---

## In plain English

After scanning, you get a JSON file with all findings and scores. The HTML dashboard converts that JSON into a polished web page with:

- A visual score gauge and letter grade (A–F)
- Severity breakdown cards and category radar chart
- A searchable, filterable findings table with remediation advice
- Attack chain visualization
- OWASP LLM Top 10 compliance mapping
- One-click export to PDF

The output is a single HTML file — no server needed to view it. Open it in any browser and share it via email or Slack.

---

## Quick start

```bash
# 1. Run a scan and save JSON
mcts scan examples/vulnerable-mcp-server/server.py -o report.json

# 2. Build the HTML dashboard
mcts report report.json -o security-report.html

# 3. Open in a browser
open security-report.html   # macOS
xdg-open security-report.html   # Linux
```

The output is one HTML file with **inlined CSS and JavaScript**. Chart.js and Inter font load from CDN on first open; scan data and brand assets are embedded for portability.

---

## Page structure

### Overview (landing)

| Section | Content |
|---------|---------|
| **Header** | MCTS logo, target path, scan timestamp, export menu |
| **Score gauge** | SVG arc showing `score.overall` (0–100) |
| **Grade card** | Letter grade A–F derived from score |
| **Posture badge** | Critical / High / Medium / Low risk label |
| **Severity cards** | Five cards: Critical, High, Medium, Low, Tools count |
| **Executive summary** | Narrative posture + P1/P2 recommended actions |
| **Category breakdown** | Progress bars per risk dimension |
| **Radar chart** | Your categories vs `INDUSTRY_BENCHMARK` |
| **Trend panel** | Historical scores when available; empty state otherwise |
| **Risk guide** | Reference cards for score ranges 0–25 through 76–100 |

### Sidebar pages

| Page | Purpose |
|------|---------|
| **Findings** | Search, filter by severity, sort, expandable remediation |
| **Analyzers** | Per-analyzer finding counts and severity breakdown |
| **Attack Chains** | SVG graph from `attack_graph` capability paths |
| **OWASP Mapping** | LLM Top 10 categories with counts and affected tools |
| **Recommendations** | Prioritized P1–P4 remediation list |
| **Appendix** | Collapsible raw JSON for auditors |

Navigation is client-side (no server required).

---

## Scoring display

The dashboard mirrors CLI scoring exactly:

| Element | Source field | Notes |
|---------|--------------|-------|
| Security score | `score.overall` | Higher is better |
| Risk index | `score.risk_index` | Shown in tooltip/detail |
| Letter grade | Computed in `report/data.py` | A=90+, F&lt;60 |
| Severity counts | `summary.*` | Scorable findings |
| Category bars | `CATEGORY_DEFS` weighting | Higher bar = more risk in dimension |
| Formula tooltip | `score.basis` | Shows weighted calculation |

**Important:** A low overall score with high category bars is expected — the UI explains that dimensions can be elevated even when exponential score is low.

---

## Attack chain graph

Renders `ScanReport.attack_graph` from `AttackChainAnalyzer`:

- Nodes = tools with capability profiles
- Edges = inferred attack transitions (read→exfil, read→exec, etc.)
- Empty state when no chains detected (no synthetic fake edges)

---

## OWASP LLM Top 10 mapping

`report/data.py` → `OWASP_CATALOG` maps analyzers to OWASP categories:

| ID | Category | Mapped analyzers |
|----|----------|------------------|
| LLM01 | Prompt Injection | injection cluster |
| LLM02 | Sensitive Information Disclosure | data leakage, path validation |
| LLM04 | Model Denial of Service | tool abuse |
| LLM06 | Excessive Agency | attack chains, permissions, command execution |
| LLM07 | System Prompt Leakage | jailbreak |

Compliance findings appear here but do not affect score.

---

## Export options

Header **Export** menu and sidebar actions:

| Action | Mechanism |
|--------|-----------|
| **Download JSON** | Embedded `ScanReport` blob |
| **Save HTML** | Browser save of current document |
| **Print / PDF** | `@media print` styles for executive PDFs |

No data is sent to MCTS servers — all processing is local in the browser.

---

## Implementation architecture

```
mcts report report.json
        │
        ▼
ScanReport.model_validate_json()
        │
        ▼
report/data.py → build_dashboard_payload()
        │
        ▼
report/generators/html_report.py
  ├── Jinja2: templates/dashboard.html
  ├── Inline: assets/styles.css, assets/dashboard.js
  └── Embed: brand/logo-report.png (base64)
        │
        ▼
security-report.html (single file)
```

### Key files

| Path | Role |
|------|------|
| `report/templates/dashboard.html` | Jinja2 shell and section layout |
| `report/assets/styles.css` | Enterprise dark card design system |
| `report/assets/dashboard.js` | Charts, tables, navigation, export |
| `report/assets/icons/` | SVG severity icons |
| `report/data.py` | ScanReport → dashboard JSON |
| `report/generators/html_report.py` | Assembly and inlining |
| `brand/logo-report.png` | Hex icon embed (no wordmark — legible at 44×44) |

Entry: `mcts.reporting.html.write_html_report()` delegates to generator.

### Tests

`tests/test_html_report.py` — payload builder validation, self-contained HTML smoke checks, delegation from CLI.

---

## Design system

All dashboard cards share:

| Token | Value |
|-------|-------|
| Background | `#0b1730` |
| Border radius | 16px |
| Border | `1px solid rgba(255,255,255,.06)` |
| Shadow | `0 8px 32px rgba(0,0,0,.35)` |
| Transition | 200ms hover lift |

Severity cards: **4px top accent**, gradient backgrounds, large numeric counts, footer risk badges.

---

## CDN dependencies

When opened in a browser, the file may fetch:

| Resource | Purpose |
|----------|---------|
| Chart.js | Radar and trend charts |
| Inter font | Typography |

Scan data itself never leaves the file. See [SECURITY.md](../../SECURITY.md).

---

## Planned enhancements

| Feature | Phase | GAP |
|---------|-------|-----|
| Interactive attack-graph UI (force-directed) | 2 | GAP-218 |
| Capability Matrix | 1 | `capability/inferrer.py` profiles |
| Technique Map (full MCTS-T grid) | 1 | All `technique_id` on findings |
| Live trend chart | 2 | GAP-126 — `.mcts/history/` |
| Diff view vs baseline | 2 | `--baseline` snapshots |
| Credential / blast-radius graph pages | 3 | L7-07 |

See [Feature Expansion Plan — Reporting](../more/feature-expansion-plan.md#reporting-10) and [Roadmap](../more/roadmap.md).

---

## Related

- [CLI Reference — `mcts report`](../platform/cli.md#mcts-report)
- [Scoring Specification](scoring-spec.md)
- [Architecture — Reporting](../analysis/architecture.md#reporting)
- [Getting Started](../get-started/getting-started.md)
