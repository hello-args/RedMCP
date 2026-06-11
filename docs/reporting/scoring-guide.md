# Scoring — developer guide

> **Read this first** if you are confused by two scores, different CI flags, or mismatched numbers on the same scan.

One scan produces **findings** plus **scores**. MCTS runs **two score engines** in parallel by default (`--scoring both`). They answer different questions — both are intentional.

**Not a scoring question?** Use the [documentation index](../index.md) task picker for install, scan modes, or CI wiring.

---

## Which doc should I read?

| Your situation | Start here | Then (if needed) |
|----------------|------------|------------------|
| First scan — what do the numbers mean? | This page → [60-second mental model](#60-second-mental-model) | [Getting started](../get-started/getting-started.md#reading-the-output) |
| Wiring CI / GitHub Action | [CI gates](#ci-gates--pick-one-strategy) | [CI integration](../platform/ci-integration.md) |
| JSON field reference | [JSON report fields](#json-report-fields) | [REST API](../platform/rest-api.md) |
| HTML dashboard blocks | [HTML dashboard](#html-dashboard) | [HTML report](html-report.md) |
| Change legacy formula | [Implementing](#implementing-or-debugging-scoring) | [Scoring spec (legacy)](scoring-spec.md) |
| Change v2 factors / chains | [Implementing](#implementing-or-debugging-scoring) | [Scoring spec v2](scoring-spec-v2.md) |
| Policy YAML / assets / history | [Migration notes](../migration/scoring-v2.md) | — |
| SARIF + Code Scanning | [API](#api) | [SARIF scoreV2](sarif-score-v2.md) |

---

## 60-second mental model

```
Findings  →  Legacy engine  →  score.overall        (0–100, higher = better)
          →  v2 engine      →  score_v2             (absolute_risk, higher = worse)
```

| You want to… | Use this field | CI flag (examples) |
|--------------|----------------|-------------------|
| Keep existing pipelines working | `score.overall` | `--min-score 70` |
| Stable risk number for policies | `score_v2.absolute_risk` | `--max-absolute-risk 500` |
| Compare to other MCP servers | `score_v2.security_score` | `--min-security-score 40` |
| Simple pass/fail band | `score_v2.risk_level` | `--max-risk-level high` |
| Block on critical findings | `summary.critical` | `--fail-on-critical` |

**Default:** `--scoring both` — you get legacy **and** v2 in JSON, terminal, HTML, and SARIF.  
**Legacy only:** `--scoring legacy` — no `score_v2` field.

---

## Why two scores on one scan?

| | Legacy `score.overall` | v2 `score_v2.absolute_risk` |
|--|------------------------|----------------------------|
| **Formula** | Severity weights + exponential decay | Eight security factors + chain multiplier |
| **Scale** | 0–100 (higher = better) | Integer ≥ 0 (higher = worse) |
| **Findings counted** | All except `compliance` | Also excludes `attack_chains` meta-rows |
| **Attack chains** | Critical chain rows in the sum | Chain signal via `chain_factor` on tool findings |
| **Typical use** | Existing CI, letter grade | New policies, explainability, benchmarks |

**Different numbers on the same scan are normal** — not a bug.

Example (`examples/vulnerable-mcp-server/server.py`):

- Legacy overall: **1/100** (includes chain meta-findings)
- v2 absolute risk: **2260** (multi-factor, tool findings only)
- v2 security score: **9/100** (benchmark vs corpus — not the same as legacy overall)

---

## Reading terminal output

When `--scoring both` (default):

```text
Overall Score:   1/100 (CRITICAL)     ← legacy; gates: --min-score
Risk Index:      100/100              ← legacy linear burden (higher = worse)
Scoring basis:   5 Critical, 11 High, 1 Medium (17 scorable findings)
Absolute Risk:   2260 (critical)      ← v2 headline; gates: --max-absolute-risk
Security Score:  9/100                ← v2 benchmark vs corpus; gates: --min-security-score
MCP Surface:     1/100                ← legacy partition only
```

| Line | Engine | Use in CI? |
|------|--------|------------|
| Overall Score | Legacy | `--min-score` |
| Risk Index | Legacy | Display only |
| Absolute Risk | v2 | `--max-absolute-risk`, `--max-risk-level` |
| Security Score | v2 | `--min-security-score` |
| MCP Surface / Supply Chain | Legacy partitions | `--fail-on-category` (legacy keys) |

**Risk Index** is legacy only (linear 0–100, higher = worse).  
**MCP Surface / Supply Chain / Composite** are legacy partitions — not v2.

---

## JSON report fields

Every `ScanReport` includes `score` (legacy). With v2/both, `score_v2` is added.

```json
{
  "scoring_version": "both",
  "score": {
    "overall": 1,
    "risk_index": 100,
    "basis": { "critical": 5, "high": 11, "scorable_total": 17 }
  },
  "score_v2": {
    "absolute_risk": 2260,
    "risk_level": "critical",
    "security_score": 9,
    "dimension_scores": { "blast_radius": 100, "reachability": 90, "threat_maturity": 25 },
    "top_contributors": [ "..." ],
    "basis": { "scorable_count": 12, "excluded_non_scorable": 7 }
  }
}
```

| Field | Engine | Notes |
|-------|--------|-------|
| `score.overall` | Legacy | Always present (invariant I1) |
| `score_v2` | v2 | `null` when `--scoring legacy` |
| `score_breakdown` | Legacy | MCP Surface / Supply Chain partitions — **not** v2 |
| `category_scores_v2` | v2 | In dashboard JSON only; OWASP tiles, 100 = good |

---

## CI gates — pick one strategy

### Strategy A: Keep legacy CI (no change)

```bash
mcts scan ./server.py --fail-on-critical --min-score 70
```

Works exactly as before. v2 fields are still in the report for visibility.

### Strategy B: Add v2 gates (recommended for new policies)

```bash
mcts scan ./server.py \
  --fail-on-critical \
  --max-absolute-risk 500 \
  --max-risk-level high
```

Scoring is already `both` by default — no extra `--scoring` flag needed.

### Strategy C: Dual gates (transition period)

```bash
mcts scan ./server.py --min-score 70 --max-absolute-risk 500
```

Both must pass. Tune thresholds independently.

### Gate cheat sheet

| Flag | Metric | Needs `--scoring` |
|------|--------|-------------------|
| `--min-score` | Legacy `overall` | No |
| `--fail-on-category` | Legacy category bars | No |
| `--min-security-score` | v2 benchmark | v2 or both (default) |
| `--max-absolute-risk` | v2 `absolute_risk` | v2 or both |
| `--max-risk-level` | v2 `risk_level` | v2 or both |
| `--min-category-score-v2` | v2 OWASP tiles | v2 or both |

Full CI patterns: [CI integration](../platform/ci-integration.md)

---

## HTML dashboard

| UI block | Source | When shown |
|----------|--------|------------|
| **Absolute risk + risk pill** | `score_v2` | Primary when v2 present |
| **Factor radar + contributors** | `score_v2` | v2/both |
| **Legacy gauge + letter grade** | `score.overall` | Legacy-only scans; hidden when `score_v2` present |
| **Category bars (7 dimensions)** | Legacy | Always |
| **v2 OWASP tiles** | `category_scores_v2` | v2/both |

Details: [HTML report](html-report.md)

---

## API

- Request: `scoring_mode` (`legacy` | `v2` | `both`, default `both`)
- Response: full report + `gate_violations[]` when gates fail
- HTTP status stays **200** on gate failure — check `gate_violations` or use CLI for exit code 1

Details: [REST API](../platform/rest-api.md)

---

## Common pitfalls

### `--no-attack-chains` under v2/both

Does **not** turn off the chains analyzer. It only disables the v2 **multiplier** (`chain_factor = 1.0`). Graph and chain findings still appear.

Use `--scoring legacy` if you want the old behavior (no chain meta-findings).

### Mixing metrics in trends

History stores `scoring_version`. The HTML trend chart uses **either** legacy score **or** `absolute_risk` — never both on one axis. Mixed history shows legacy with a warning.

### Readiness / vet scores

`mcts readiness` and `mcts vet` use **separate** scoring pipelines. They do not affect scan `score` or `score_v2`.

### Fuzz / live findings

Fuzz and runtime events are **not** merged into the default static scan v2 sum today. Run separate fuzz/pentest flows for live signal.

### Letter grade (A–F) in HTML

The letter grade and doughnut gauge use **legacy** `score.overall` and appear only on **legacy-only** scans. When `score_v2` is present, the HTML report shows the v2 block (absolute risk + risk pill) instead.

### `--ci` preset

The `--ci` preset applies **legacy** gates only (`--fail-on-critical`, `--min-score 70`). For v2 gates in CI, set flags explicitly or use the [GitHub Action](../../action/README.md) v2 inputs.

---

## FAQ

**Why is legacy overall 1/100 but absolute risk 2260?**  
Different formulas and finding sets. Legacy uses exponential decay on all scorable severities including chain meta-rows; v2 sums per-finding factor brackets on tool rows only. See [Why two scores](#why-two-scores-on-one-scan).

**Which score should my CI use?**  
Keep `--min-score` if you have existing pipelines. Add `--max-absolute-risk` or `--max-risk-level` for new policies. See [CI strategies](#ci-gates--pick-one-strategy).

**Does `--no-attack-chains` remove chain findings?**  
No — it only disables the v2 **multiplier**. Use `--scoring legacy` to drop chain meta-findings from the legacy sum.

**Where is `score_v2` in SARIF?**  
Run-level property `mcts/scoreV2` on the SARIF run object. Per-finding v2 metadata is not emitted yet.

**Do readiness or vet scores affect scan scores?**  
No — separate commands and pipelines.

---

## Implementing or debugging scoring

| Task | Doc |
|------|-----|
| Change legacy formula | [Scoring spec (legacy)](scoring-spec.md) · `src/mcts/scoring/engine.py` |
| Change v2 factors / chains | [Scoring spec v2](scoring-spec-v2.md) · `src/mcts/scoring/engine_v2.py` |
| Pipeline order | [Architecture](../analysis/architecture.md#scoring-and-reporting) |
| All formulas (internal) | `local/score-calculations-reference.md` (contributors) |
| ADR decisions | [ADR-003](../analysis/adr-003-scoring-v2.md) |

---

## Related

- [Reporting overview](README.md)
- [Glossary — score terms](../glossary.md#scores-and-reports)
- [Migration notes](../migration/scoring-v2.md) — policy YAML, assets, history
