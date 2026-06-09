# Issue Labeling & Creation Guide

This guide explains how to open, label, and track issues in [MCP-Audit/MCTS](https://github.com/MCP-Audit/MCTS). Consistent labels keep triage fast, make reporting reliable, and support automation.

**Quick rules:** every issue needs exactly one **type**, exactly one **priority**, and at least one **component**. Add **finding** labels when they clarify the risk. Use **status** labels to track workflow.

---

## Before you create an issue

1. **Search existing issues** — avoid duplicates (`is:issue is:open` plus component or keyword filters).
2. **Verify on latest code** — reproduce on `main` or your PR branch; stale findings should be closed, not re-filed.
3. **Gather evidence** — file paths, config snippets, logs, reproduction steps, or screenshots.
4. **Pick type, priority, and component** — use the tables below before opening the issue.

**GitHub templates:** use the repo templates when they fit:

- [Bug report](https://github.com/MCP-Audit/MCTS/issues/new?template=bug_report.yml)
- [Feature request](https://github.com/MCP-Audit/MCTS/issues/new?template=feature_request.yml)

For security vulnerabilities in **MCTS itself**, follow [SECURITY.md](../../SECURITY.md) — do not file public issues for undisclosed vulns.

---

## Creation workflow

### Step 1 — Choose the type (required)

Ask:

| Question | Label |
|----------|-------|
| Is something broken? | `type:bug` |
| Is this a security weakness? | `type:security` |
| Is new functionality needed? | `type:feature` |
| Is this CI/CD or release pipeline related? | `type:ci` |
| Is documentation incorrect or missing? | `type:docs` |
| Is this maintenance, DX, or code quality? | `type:task` |

**Title prefix:** prepend the type for scanability:

| Type | Title prefix |
|------|--------------|
| `type:bug` | `[BUG]` |
| `type:security` | `[SECURITY]` |
| `type:feature` | `[FEATURE]` |
| `type:ci` | `[CI]` |
| `type:docs` | `[DOCS]` |
| `type:task` | `[TASK]` |

Example: `[SECURITY] REST API accepts unauthenticated requests by default`

---

### Step 2 — Choose priority (required)

| Label | When to use |
|-------|-------------|
| `priority:P0` | Blocks production readiness; immediate action (e.g. untested release publish, auth bypass) |
| `priority:P1` | High impact; fix soon (e.g. missing rate limits, major false negatives) |
| `priority:P2` | Medium impact (e.g. missing non-critical feature, incomplete coverage) |
| `priority:P3` | Low impact (docs polish, minor refactors, nice-to-have) |

#### Priority examples in MCTS

| Priority | Examples |
|----------|----------|
| **P0** | Release workflow publishes without tests; critical auth bypass |
| **P1** | API lacks rate limiting; GitHub Action installs without optional extras |
| **P2** | Missing scan-history persistence; fuzz runner swallows errors |
| **P3** | Outdated doc for `setup-uv` version; Ruff `src` omits `scripts/` |

---

### Step 3 — Select components (≥1 required)

Identify the primary code or surface area. Multiple components are allowed.

| Label | Scope |
|-------|-------|
| `component:api` | REST API (`mcts serve`, `src/mcts/api/`) |
| `component:cli` | CLI commands and flags (`src/mcts/cli/`) |
| `component:ci` | GitHub Actions, pytest gates, coverage |
| `component:sast` | Static analysis, taint, tree-sitter paths |
| `component:fuzz` | Protocol fuzzing (`mcts fuzz`) |
| `component:live-probe` | Live MCP session probing |
| `component:inventory` | Local MCP config discovery (`mcts inventory`) |
| `component:reporting` | JSON/SARIF/HTML reports and scoring |
| `component:ui` | HTML dashboard rendering |
| `component:github-action` | Published `action/action.yml` |
| `component:scripts` | `scripts/` tooling and eval harnesses |
| `component:release` | PyPI publish, packaging, versioning |
| `component:auth` | Authentication and API keys |
| `component:docs` | Documentation and README assets |

---

### Step 4 — Add finding labels (optional)

Use when the label adds context beyond type and component.

| Label | Use when |
|-------|----------|
| `finding:authentication` | Missing or weak auth |
| `finding:privacy` | Reads sensitive local data without consent |
| `finding:dos` | Resource exhaustion or unbounded work |
| `finding:performance` | Avoidable slow paths or duplicate work |
| `finding:false-positive` | Detector fires without real risk |
| `finding:false-negative` | Detector misses a real risk |
| `finding:supply-chain` | Dependency or package audit gaps |
| `finding:compatibility` | Version matrix, API stability, deprecations |
| `finding:reproducibility` | Unpinned installs, non-deterministic builds |

---

### Step 5 — Set status (recommended)

New issues should start at **`status:triage`**. Maintainers move issues through the workflow:

| Label | Meaning |
|-------|---------|
| `status:triage` | New; needs review and confirmation |
| `status:ready` | Accepted; unblocked and prioritized |
| `status:in-progress` | Someone is actively working on it |
| `status:review` | Fix is up for review or verification |
| `status:blocked` | Waiting on dependency, design decision, or upstream |

Only one status label should be active at a time.

---

## Issue body template

Use this structure so reviewers can act without back-and-forth:

```markdown
## Summary
One or two sentences.

## Problem
What happens today (broken behavior, missing capability, or risk).

## Expected Behavior
What should happen instead.

## Evidence
- File paths and line references
- Config or code snippets
- Reproduction commands
- Logs or screenshots

## Impact
Who is affected and severity (users, CI, security posture).

## Recommendation
Preferred fix or design direction.

## Remediation Steps
1. First concrete step
2. Second step
3. Verification step

## References
Links to docs, standards, or related issues.

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2
- [ ] Tests or docs updated if user-facing
```

> **Note:** Bulk audit issues generated from the local `issues/` workflow may use `Problem` and `Impact` section names interchangeably with `Finding` and `Risk` — keep the same information density.

---

## Complete example

**Title:** `[SECURITY] REST API accepts unauthenticated requests by default`

**Labels:**

```
type:security
priority:P1
component:api
finding:authentication
status:triage
```

**Body (abbreviated):**

```markdown
## Summary
When `MCTS_API_KEY` is unset, POST scan endpoints accept unauthenticated requests.

## Problem
`require_api_key()` returns early when the env var is empty, allowing anonymous scans.

## Expected Behavior
Protected routes reject unauthenticated requests outside explicit local-dev mode.

## Evidence
`src/mcts/api/auth.py` — no key configured → request allowed.

## Impact
Misconfigured deployments expose scan and inventory operations to the network.

## Recommendation
Require authentication by default; document opt-out for localhost-only dev.

## Acceptance Criteria
- [ ] Authentication enforced for non-local deployments
- [ ] Anonymous requests receive 401
- [ ] Tests cover authenticated and unauthenticated paths
```

---

## Label taxonomy reference

### Required on every issue

| Category | Cardinality | Labels |
|----------|-------------|--------|
| Type | exactly 1 | `type:bug`, `type:feature`, `type:security`, `type:docs`, `type:ci`, `type:task` |
| Priority | exactly 1 | `priority:P0`, `priority:P1`, `priority:P2`, `priority:P3` |
| Component | ≥1 | See [Step 3](#step-3--select-components-1-required) |

### Optional

| Category | Labels |
|----------|--------|
| Finding | `finding:false-positive`, `finding:false-negative`, `finding:authentication`, `finding:privacy`, `finding:dos`, `finding:performance`, `finding:supply-chain`, `finding:compatibility`, `finding:reproducibility` |
| Status | `status:triage`, `status:ready`, `status:in-progress`, `status:review`, `status:blocked` |

### Labels we do not use

Avoid legacy or redundant labels:

- `audit-finding`, `mcts-audit` — every issue in this repo is an audit finding
- Bare `bug`, `feature`, `ci` without the `type:` prefix
- `priority-critical` / `priority-high` / `priority-medium` / `priority-low` — use `priority:P0`–`P3` instead
- `quality`, `dx` as types — use `type:task`

---

## Bulk audit workflow (maintainers)

The repository maintains a local audit corpus under `issues/` (gitignored) for batch triage. Maintainers with that directory can sync GitHub from markdown sources:

```bash
# Preview labels and body for one issue
python issues/create_github_issues.py --dry-run --id 025

# Validate labels on all logged GitHub issues
python issues/create_github_issues.py --validate-labels

# Push markdown updates to existing GitHub issues
python issues/create_github_issues.py --update
```

The script applies the same taxonomy automatically: `type:*` + `priority:P*` + `component:*` + optional `finding:*` + default `status:triage`.

---

## Filtering issues on GitHub

Use label filters in the issue search bar:

```
is:issue is:open label:type:security label:priority:P1
is:issue label:component:api label:finding:authentication
is:issue label:status:ready label:component:ci
```

---

## Related docs

- [CONTRIBUTING.md](../../CONTRIBUTING.md) — development workflow and PR guidelines
- [SECURITY.md](../../SECURITY.md) — responsible disclosure for MCTS vulnerabilities
- [Feature Expansion Plan](../more/feature-expansion-plan.md) — prioritized capability backlog
- [Product Roadmap](../more/roadmap.md) — phased deliverables
