# Scoring Specification

> [Documentation](../index.md) → [Reporting](README.md)

MCTS computes an auditable **security score** and **risk index** from findings. Every `ScanReport` includes a `ScoreBasis` so teams can verify how the number was derived — nothing is hardcoded per target.

**Implementation:** `src/mcts/scoring/engine.py` (core math), `src/mcts/report/data.py` (category breakdown, HTML radar)

---

## Design goals

1. **Deterministic** — same findings always produce the same score
2. **Auditable** — `score.basis` documents exact severity counts used
3. **CI-friendly** — gates on overall score, critical count, and category thresholds
4. **Separated compliance** — OWASP meta-findings do not inflate risk score

The scanner calls `RiskScoringEngine.verify()` after scoring; mismatch raises `RuntimeError` (regression guard).

---

## Severity weights

| Severity | Raw risk points | Rationale |
|----------|-----------------|-----------|
| Critical | 25 | Immediate exploitation or catastrophic impact |
| High | 10 | Serious misuse or strong attack enabler |
| Medium | 3 | Meaningful weakness requiring attention |
| Low | 1 | Informational or defense-in-depth gap |

```python
raw_risk = critical×25 + high×10 + medium×3 + low×1
```

Constants: `RISK_WEIGHTS` in `scoring/engine.py`.

---

## Overall security score

Exponential decay — **higher is better**:

```
overall = round(100 × e^(-raw_risk / 50))
```

| Property | Value |
|----------|-------|
| `raw_risk == 0` | Score **100** (perfect) |
| Clamp range | `[0, 100]` |
| Decay scale | `RISK_DECAY_SCALE = 50` |

### Worked examples

| Findings | Raw risk | Overall score |
|----------|----------|---------------|
| None | 0 | 100 |
| 1 High | 10 | 82 |
| 3 Medium | 9 | 83 |
| 1 Critical + 2 High | 45 | 41 |
| 3 Critical + 7 High + 2 Medium | 151 | **5** |

Example servers: `examples/safe-mcp-server/` (~100), `examples/medium-risk-mcp-server/` (~67), `examples/vulnerable-mcp-server/` (~5).

---

## Risk index

Linear cap on raw risk — **higher is worse**:

```
risk_index = min(100, raw_risk)
```

Use when dashboards should show "risk burden" without exponential inversion. A server with raw_risk 151 shows risk_index **100** (capped).

---

## Non-scoring findings

Findings where `analyzer == "compliance"` are excluded from score calculation:

```python
NON_SCORING_ANALYZERS = frozenset({"compliance"})
```

Compliance findings still appear in reports, HTML OWASP section, and SARIF — they inform governance but should not double-penalize already-scored issues.

`score.basis.excluded_non_scorable` counts excluded rows.

---

## JSON schema

```json
{
  "score": {
    "overall": 5,
    "risk_index": 100,
    "raw_risk": 151,
    "penalty": 151,
    "basis": {
      "critical": 3,
      "high": 7,
      "medium": 2,
      "low": 0,
      "scorable_total": 12,
      "excluded_non_scorable": 2
    }
  },
  "summary": {
    "critical": 3,
    "high": 7,
    "medium": 2,
    "low": 0,
    "total": 12
  }
}
```

Note: `summary` reflects scorable findings used for score; total finding count in `findings[]` may be higher when compliance rows exist.

`penalty` is a deprecated alias for `raw_risk` (backward compatibility).

---

## Category breakdown

Category scores power the **terminal dashboard**, **HTML radar chart**, and **`--fail-on-category`** gates.

Defined in `report/data.py` → `CATEGORY_DEFS`:

| Key | Label | Max points | Analyzers mapped |
|-----|-------|------------|------------------|
| `permissions` | Excessive Permissions | 20 | `permission_analyzer` |
| `injection` | Injection & Metadata | 20 | `prompt_injection`, `metadata_integrity`, `schema_surface` |
| `execution` | Execution & Path Risk | 15 | `command_execution`, `path_validation`, `tool_abuse` |
| `data_leakage` | Data Leakage Risk | 15 | `data_leakage` |
| `attack_chains` | Attack Chain Risk | 15 | `attack_chains` |
| `shadowing` | Cross-Server Shadowing | 5 | `cross_server` |
| `jailbreak` | Jailbreak Resistance | 10 | `jailbreak` |

### Per-category calculation

For each category:

1. Collect findings whose `analyzer` matches the category's analyzer list
2. Sum severity weights (same 25/10/3/1 table)
3. Category score = `min(maximum, weighted_sum)`

### Industry benchmark overlay

HTML radar chart compares your category scores to `INDUSTRY_BENCHMARK` defaults:

| Category | Benchmark |
|----------|-----------|
| permissions | 8 |
| injection | 6 |
| execution | 5 |
| data_leakage | 5 |
| attack_chains | 4 |
| shadowing | 2 |
| jailbreak | 3 |

Benchmarks are illustrative overlays — not pass/fail thresholds.

---

## CI gate semantics

Exit code **1** when a gate fails; **2** for usage/consent errors.

| Flag | Fails when |
|------|------------|
| `--fail-on-critical` | `summary.critical > 0` (scorable findings) |
| `--min-score N` | `score.overall < N` |
| `--max-critical N` | `summary.critical > N` |
| `--fail-on-category KEY:LIMIT` | Category score ≥ LIMIT |

Category gates are **inclusive** at the limit: `--fail-on-category permissions:10` fails when permissions category score is **10 or higher**.

### Recommended starter policy

```bash
mcts scan ./repo/ \
  --min-score 75 \
  --max-critical 0 \
  --fail-on-category permissions:10 \
  --fail-on-category injection:12 \
  --fail-on-category execution:10
```

Tune limits per team risk appetite. Start strict on `max-critical` and relax `min-score` as debt is burned down.

---

## Letter grades (HTML dashboard)

| Score range | Grade | Posture label |
|-------------|-------|---------------|
| 90–100 | A | Low risk |
| 80–89 | B | Moderate |
| 70–79 | C | Elevated |
| 60–69 | D | High |
| 0–59 | F | Critical |

Grades are derived from `score.overall` in `report/data.py`.

---

## Integrity check

```python
RiskScoringEngine.verify(findings, score)  # must return True
```

Called at end of `Scanner.run()`. Prevents:

- Stale cached scores in tests
- Manual score tampering in JSON
- Regression when weights change without test updates

---

## Related

- [CLI Reference — gate flags](../platform/cli.md#ci-gate-flags)
- [CI Integration](../platform/ci-integration.md)
- [HTML Security Dashboard](html-report.md)
- [Architecture — Scoring](../analysis/architecture.md#scoring-scoringenginepy)
