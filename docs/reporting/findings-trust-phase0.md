# Findings trust layer — Phase 0 implementation status

> [Documentation](../index.md) → [Reporting](README.md) → **Findings trust (Phase 0)**

**Status:** Implemented in tree (Phase 0 → B2) · **637+ tests** (reporting/scoring) · Tracks [#258](https://github.com/MCP-Audit/MCTS/issues/258)

This document is the **maintainer-facing record** of what Phase 0 delivered, what was intentionally deferred, known operational risks, and the mitigation plan for follow-up work.

**User-facing guide:** [Interpreting findings](interpreting-findings.md) · **Product roadmap:** `local/findings-quality-evidence-roadmap.md` (internal)

---

## Summary

Phase 0 adds a **findings trust layer** so MCTS can show honest attack-chain overlap without breaking legacy CI or scoring:

```
Parallel display fields + validate_findings() + consumer migration (primary path)
```

**Default behavior is unchanged:** `findings_trust_mode=off` — same `summary.critical`, same `--fail-on-critical`, same scores.

**Opt-in honest UX/CI:** `--findings-trust-mode enforce` — display severity caps overlap chains; gates use `display_summary`.

---

## What was expected (Phase 0 scope)

From [#258](https://github.com/MCP-Audit/MCTS/issues/258) and the 7-PR train:

| # | Deliverable | Expected outcome |
|---|-------------|------------------|
| PR 1 | Schema + `display.py` | Optional trust fields; helpers; **no behavior change** when off |
| PR 2 | Validator + pipeline | `validate_findings()` after enrich; `findings_trust_mode` config |
| PR 3 | Graph honesty | No fake hop/path; self-loops skipped; v2 overlap suppress |
| PR 4 | Dual summary | `report.summary` (template) + `report.display_summary` (trust) |
| PR 5 | Dashboard + terminal | Badges, sort, summary cards on display severity |
| PR 6 | Single-tool fixture | `examples/single-tool-agent-server/` regression |
| PR 7 | SARIF | `level` from display severity when trust on |

### Phase A invariants (non-negotiable)

- Do **not** mutate `finding.severity` until Phase B
- Validator is the **single** mutation point for display fields
- Stable `finding.id`; rewrite display titles only in **enforce** mode
- Legacy CI unchanged unless trust is explicitly enabled

### Target pipeline order

```
dedupe → enrich_findings → enrich_scoring_evidence → validate_findings()
  → _apply_filters → compliance (effective_severity) → score → dual summary
```

---

## What was implemented

### Core modules

| Module | Role |
|--------|------|
| `src/mcts/reporting/models.py` | Trust fields on `Finding`; `ScanReport.display_summary`; `ScanSummary.from_display()` |
| `src/mcts/reporting/display.py` | `effective_severity()`, `effective_impact()`, `is_security_finding()`, `summary_for_gates()` |
| `src/mcts/reporting/finding_validator.py` | Caps overlap chains; sets `evidence_type`, titles (enforce), strips fake path/hop |
| `src/mcts/core/scanner.py` | Validator hook; dual summary; pipeline order |
| `src/mcts/core/config.py` | `findings_trust_mode` (`off` \| `warn` \| `enforce`, default `off`) |

### Validator behavior (attack chains)

| Condition | `evidence_type` | `display_severity` | Title (enforce) |
|-----------|-----------------|--------------------|-----------------|
| Unproven overlap (incl. multi-tool) | `capability_overlap` | ≤ medium | “Potential capability overlap (…)” |
| Proven path (hop ≥ 2 or 3+ nodes) | `graph_path` | template (usually critical) | unchanged |
| Single-tool overlap | + `single_tool_overlap: true` in evidence | medium | rewritten |

Overlap evidence: `path_status: unproven`; fake `hop_count` / `path` removed.

### Graph honesty (PR 3)

| Change | Location |
|--------|----------|
| No fake `hop_count: 1` / `path: read_tools` | `scoring/evidence_tags.py` → `path_status: unproven` only |
| Self-loop edges skipped | `scoring/graph.py` (`src != dst`) |
| Overlap-only paths omitted from v2 top contributors | `scoring/engine_v2.py` `_paths_are_proven()` |

### Consumers migrated (when trust on)

| Consumer | Uses display? |
|----------|---------------|
| HTML dashboard finding table, summary cards, metrics | Yes |
| Dashboard analyzer modal severity counts | Yes |
| Dashboard recommendations priority | Yes |
| Dashboard score footnote (severity breakdown) | Yes when `display_summary` present |
| Terminal dashboard (`ui/dashboard.py`) | Yes |
| Executive summary (overlap + exfil heuristics) | Yes |
| SARIF `level`, `display_severity`, `evidence_type` | Yes |
| Compliance `multiple-critical` | Yes (`effective_severity`) |
| CI gates `fail_on_critical`, `max_critical` | Yes when **enforce** |
| CLI `scan` | `--findings-trust-mode` |
| REST API `POST /scan` | `findings_trust_mode` field |

### Post-audit fixes (included)

| Fix | Description |
|-----|-------------|
| Executive exfil/shell heuristics | Skip `capability_overlap` chains; no false “exfiltration paths” paragraph |
| `_enrich_analyzer_row` | Count `effective_severity`, not template |
| `build_recommendations` | Priority/impact from display severity |
| `dashboard.js` score-detail | Display counts when `display_summary` in payload |

### Fixture and tests

| Asset | Purpose |
|-------|---------|
| `examples/single-tool-agent-server/server.py` | sa-mcp overlap regression |
| `tests/reporting/test_*.py` (20 tests) | Validator, scanner, gates, SARIF, dashboard payload |

**Acceptance (single-tool + enforce):** `display_summary.critical == 0`; overlap titles honest; gates pass with `--fail-on-critical`.

---

## Acceptance criteria checklist (#258)

| Criterion | Status |
|-----------|--------|
| Overlap → `capability_overlap`, display ≤ medium, honest titles | Done |
| `finding.severity` unchanged; `verify()` passes | Done |
| Dual summary | Done |
| No fake hop/path fallback | Done |
| Single-tool fixture; zero display critical overlap | Done |
| Validator tests (overlap, warn, enforce) | Done |
| Executive summary honest on overlap-only | Done |
| `--fail-on-critical` default unchanged | Done |
| Gates use display when enforce | Done |

---

## What was **not** implemented (expected deferrals)

These were **explicitly out of Phase 0** — documented in the roadmap and issue #258 “Later phases”.

| Item | Planned phase | Notes |
|------|---------------|-------|
| Mutate `finding.severity` | Phase B | Still deferred — display fields only |
| Full v2 scoring on display severity | Phase B2 | **Done** — enforce mode; `finding.severity` unchanged |
| Corpus Spearman recalibration after B2 | Phase B2 | Deferred until corpus run |
| `--ci-trust` preset + GitHub Action input | PR 8 / Phase A½ | **Done** — `--ci-trust`, `findings-trust-mode`, `ci-trust` inputs |
| `fail_on_priority_min`, `min_evidence_strength` gates | Phase 2 | **Done** — CLI, API, Action, policy YAML |
| `GovernancePolicy` / `.mcts/policy.yaml` trust fields | Phase 2 | **Done** — `.mcts/policy.yaml.example` |
| Inferrer `signals[]` + facts on chains | Phase 1 / PR 10 | **Done** — inferrer signals + `evidence.facts` when trust on |
| Full 23-consumer migration | Phased | See table below |
| History/trend `display_critical` | Consumer step 12 | **Done (A½)** |
| Category tiles / OWASP badges on display | Phase A½ | **Done (A½)** |
| CLI printed finding lists on display | Phase A½ | **Done** for `mcts scan` / `mcts report`; fuzz/readiness/vet/pentest still template |
| `severity_filter` on display severity | Consumer step 5 | **Done (A½)** |
| Legacy score + `score.basis` on display | Phase A½ narrow B | **Done (A½)** — enforce only; v2 unchanged |
| Pentest / fuzz / inventory validator | §K bypass paths | |
| `canonical_attack_graph_from_scan` early-return fix | M5 deferred | |

---

## Partial migration — still on template severity

When `findings_trust_mode=enforce`, these surfaces are **aligned** (Phase A½):

| Surface | Status |
|---------|--------|
| Gates (`--fail-on-critical`, governance) | display |
| Legacy `score.basis` + `--min-score` | display effective severity |
| HTML dashboard severity / categories / OWASP | display |
| Terminal dashboard + `--format summary` | display |
| `history.json` `display_critical` | recorded |
| `--severity-filter` | display |

Still on **template** severity when enforce:

| Surface | Field used | User-visible effect |
|---------|------------|---------------------|
| `summary` / `finding.severity` in JSON | template | Audit trail preserved |
| v2 `absolute_risk` | display when enforce | **B2** — `ScoringContext.use_display_severity` |
| Pentest / fuzz / inventory | template | Out of scope A½ |

---

## Modes: off, warn, enforce

| Surface | `off` (default) | `warn` | `enforce` |
|---------|-----------------|--------|-----------|
| Display fields populated | No | Yes | Yes |
| Title rewrite | No | No | Yes |
| `display_summary` | No | Yes | Yes |
| SARIF `level` from display | No (fallback) | Yes | Yes |
| `--fail-on-critical` | template | template | **display** |
| Compliance `multiple-critical` | template* | display | display |

\*When off, `display_severity` is unset → `effective_severity()` equals template.

**Important:** `warn` is for preview/telemetry — it does **not** relax CI. Use `enforce` for honest gates.

---

## Operational risks and mitigations

| Risk | Mitigation (plan) | Status |
|------|-------------------|--------|
| Two severities in one report confuses users | Phase A½ + B2 v2 alignment | **Done** for v1/v2 under enforce |
| Score unchanged when display improves | Phase A½ narrow B + Phase B2 | **Done** — legacy basis + v2 under enforce |
| SARIF/JSON consumers read `severity` only | Export `display_severity`, `evidence_type`; integrator guide | Fields yes; guide partial |
| GitHub Action stays noisy | Phase A½ PR 8 | **Done** — `findings-trust-mode`, `ci-trust` |
| `warn` mistaken for CI relief | Document; steer to `enforce` | **Done** — CLI help + docs |
| Rule churn unknown to users | **`rule_stability`** (Phase 1.5) | **Done** — catalog + chip |
| Proven-path heuristic too loose | Roadmap §L; tighten edge validation | Documented only |
| Report/config gate mismatch | Use same config for scan and gate evaluation | Operational note |

### Follow-up issues (revised PR train — post external review)

| PR | Phase | Focus |
|----|-------|-------|
| **8–9** | **A½ Consistency** | ✅ Action, `--ci-trust`, CLI/history, score basis, maturity chip |
| **10** | Phase 1 | inferrer `signals[]`, facts |
| **11** | Phase 1.5 | `rule_stability`, FindingBuilder |
| **12** | Phase 2 | `priority_score` gates, policy YAML |
| **13** | Phase B2 | ✅ v2 display severity + chain factors; corpus recalibration deferred |

Legacy mapping: old “PR 8” CI trust is now **PR 8–9 (Phase A½)**; provenance is **PR 10+**.

---

## How to use

### Local / CI (honest overlap handling)

```bash
# Dashboard + gates use display severity; overlap chains capped to medium
mcts scan examples/single-tool-agent-server/server.py \
  --findings-trust-mode enforce \
  --fail-on-critical

# Legacy behavior (default) — unchanged
mcts scan examples/single-tool-agent-server/server.py --fail-on-critical
# → exits 1 (template critical)
```

### Governance policy merge

`merge_scan_config_with_policy()` fills unset CLI defaults from `.mcts/policy.yaml` before the scan runs:

- `findings_trust_mode` when CLI is still `off`
- `max_critical`, `min_score`, `fail_on_priority_min`, `min_evidence_strength`, v2 gate fields when unset

Explicit CLI flags always override policy. Post-scan `evaluate_policy()` uses the same merged config for gate counts via `summary_for_gates()`.

Copy `.mcts/policy.yaml.example` → `.mcts/policy.yaml` to opt in without repeating flags on every scan.

### API

```json
{
  "target": "examples/single-tool-agent-server/server.py",
  "findings_trust_mode": "enforce",
  "fail_on_critical": true
}
```

### JSON fields (integrators)

| Field | Meaning |
|-------|---------|
| `finding.severity` | Template severity (scoring, legacy) |
| `finding.display_severity` | Trust-adjusted (null when off) |
| `finding.evidence_type` | `capability_overlap` \| `graph_path` \| null |
| `summary` | Template counts |
| `display_summary` | Display counts (null when off) |

**Rule:** When `findings_trust_mode=enforce`, gate and triage on `display_summary` / `display_severity`, not `summary.critical` alone.

### SARIF

- `level` ← display severity (when trust on)
- `properties.severity` ← template (legacy)
- `properties.display_severity` ← display
- `properties.evidence_type` ← when set

---

## Code map

| Area | Path |
|------|------|
| Validator | `src/mcts/reporting/finding_validator.py` |
| Display helpers | `src/mcts/reporting/display.py` |
| Scanner pipeline | `src/mcts/core/scanner.py` (~219–283) |
| Dashboard payload | `src/mcts/report/data.py` |
| Dashboard JS | `src/mcts/report/assets/dashboard.js` |
| Terminal UI | `src/mcts/ui/dashboard.py` |
| SARIF | `src/mcts/reporting/sarif.py` |
| Gates | `src/mcts/governance/scan_gates.py` |
| Trust gates (priority) | `src/mcts/reporting/trust_gates.py` |
| Evidence provenance | `src/mcts/reporting/evidence_provenance.py` |
| Rule stability | `src/mcts/reporting/rule_stability.py` |
| FindingBuilder SDK | `src/mcts/reporting/finding_builder.py` |
| V2 scoring (B2) | `src/mcts/scoring/context.py`, `engine_v2.py`, `chains.py`, `factors.py` |
| Config / CLI / API | `config.py`, `cli/main.py`, `api/app.py` |
| Fixture | `examples/single-tool-agent-server/server.py` |
| Tests | `tests/reporting/`, `tests/scoring/test_scoring_v2_trust.py` |

---

## Verification

- Reporting + scoring trust: `uv run pytest tests/reporting/ tests/scoring/ -q` (111+ tests)
- B2 only: `uv run pytest tests/scoring/test_scoring_v2_trust.py -q`
- Full suite: `uv run pytest` (requires optional extras: `uv sync --extra mcp`)
- Manual: scan single-tool fixture with enforce; confirm `display_summary.critical == 0` and v2 `verify()` passes

---

## Phase B2 — v2 scoring on display severity

When `findings_trust_mode=enforce`, v2 scoring reads **display** severity for:

| Component | Behavior |
|-----------|----------|
| `base_risk()` / `ScoreV2Basis` counts | `severity_for_scoring(..., use_display=True)` |
| `classify_business_impact()` | Falls back to display severity when no explicit hints |
| `resolve_chain_factors()` | Skips unproven paths (`path_is_proven`) |
| `build_top_contributors()` | Omits overlap-only attack-chain rows |

`finding.severity` (template) is **unchanged** — `RiskScoringEngineV2.verify()` still passes.

Corpus Spearman recalibration is **deferred** until a maintainer run confirms score drift.

---

## Next priority — Phase 3 + adoption

Phases 0, A½, 1, 1.5, 2, B2, and pre-Phase-3 adoption are shipped in-tree:

- Shared `apply_trust_layer()` for scan, fuzz, and inventory entry points
- Bronze CI gate (`--enforce-bronze-facts`) for experimental analyzers without `evidence.facts`
- `command_execution` emits findings via `FindingBuilder` (reference adoption)

**Next:** optional taint/runtime validation (Phase 3); adopt `FindingBuilder` in remaining analyzers; flip GitHub Action default to `--ci-trust` after opt-in period.

### Gap fixes (pre-Phase 3)

| Gap | Status |
|-----|--------|
| FindingBuilder in mature analyzers | **Done** — `command_execution`, `prompt_injection`, `data_leakage` |
| Pentest / readiness trust pipeline | **Done** — fuzz rows + readiness notes via `apply_trust_layer` |
| Fuzz / inventory trust | **Done** (prior slice) |
| API policy loader | **Done** — `_merge_policy()` on REST scan/readiness |
| Global weak-evidence caps | **Done** — thin evidence + low confidence → `weak` |
| B2 residual template paths | **Done** — disagreement factor + readiness score use display under enforce |
| Vet trust pipeline | **Deferred** — `VetFinding` model separate from `Finding` |
| Mutate `finding.severity` (B3) | **Deferred** — breaking change |
| `warn` gate vs display split | **By design** — document in [interpreting-findings](interpreting-findings.md) |

---

## Related

- [#258 — Phase 0 feature issue](https://github.com/MCP-Audit/MCTS/issues/258)
- [Interpreting findings](interpreting-findings.md) — user-facing overlap explanation
- [CI integration](../platform/ci-integration.md) — legacy gates (Phase A½ pending)
- [Scoring developer guide](scoring-guide.md) — v2 uses display severity when trust enforce (B2)
