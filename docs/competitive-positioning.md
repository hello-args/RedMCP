# Competitive Positioning — MCTS vs MCP Security Tools

How **MCTS** (Model Context Threat Scanner) compares to tools audited under `mcp_audit_competitor/`.  
Last updated after Phase 0/1 foundation work (live stdio probe, inventory, fuzz, SARIF, taxonomy).

---

## Executive summary

| Dimension | MCTS position |
|-----------|---------------|
| **Local-first / offline** | **Leader** — no cloud API or LLM required for core scan |
| **CI gates (SARIF + score)** | **Leader** — SARIF 2.1.0, `--min-score`, `--max-critical`, published Action |
| **HTML executive dashboard** | **Leader** (tied with ProofLayer) — richer than all others except agent-security-scanner |
| **Attack-chain threat model** | **Unique** — capability-graph chains, not keyword-only |
| **Auditable scoring** | **Unique** — exponential decay + `ScoreBasis` on every report |
| **Config inventory** | **Competitive** — Cursor/Claude/VS Code/Windsurf (agent-scan still broader) |
| **Live MCP probing** | **Competitive** — stdio shipped; mcp-scanner ahead on multi-transport |
| **Dynamic fuzzing** | **Competitive** — safe read-only default; aggressive tier with consent |
| **Deep multi-language SAST** | **Gap** — mcp-scanner / agent-security ahead (tree-sitter + Semgrep) |
| **MCP server mode for agents** | **Gap** — scanner-main / agent-security ahead (Phase 3) |

**Bottom line:** MCTS wins on **deterministic CI adoption**, **risk scorecard**, **attack chains**, and **executive reporting** without cloud lock-in. Peers still win on **multi-transport live depth** (mcp-scanner SSE/HTTP) and **full destructive fuzz suites** (mcp-guard aggressive mode).

---

## One-by-one comparison

### 1. mcp-scanner (Cisco AI MCP Scanner)

| | mcp-scanner | MCTS |
|---|-------------|------|
| Live MCP (tools/prompts/resources) | ✅ Multi-transport | ✅ Stdio (`--live`); SSE/HTTP planned |
| Static SAST depth | ✅ Tree-sitter + taint | ⚠️ Python AST + TS patterns + heuristics |
| YARA / behavioral LLM | ✅ | ❌ |
| Config discovery | ✅ known-configs | ✅ `mcts inventory` |
| SARIF | ❌ | ✅ |
| HTML dashboard | ❌ | ✅ |
| Attack chains | ⚠️ Implicit | ✅ Capability graph |
| CI score gate | ⚠️ Severity only | ✅ `--min-score` + SARIF |
| Cloud dependency | ⚠️ Optional Cisco API | ✅ None |

**MCTS wins:** SARIF, HTML, scoring, offline default, attack chains, stdio live probe.  
**mcp-scanner wins:** Multi-transport live, deeper SAST/taint, YARA, behavioral alignment.

---

### 2. MCPScan

| | MCPScan | MCTS |
|---|---------|------|
| Semgrep + LLM pipeline | ✅ | ❌ |
| Tests | ❌ | ✅ 40+ tests |
| Live MCP | ❌ | ✅ Stdio (`--live`) |
| SARIF / CI | ❌ | ✅ |
| Repo scan | ✅ | ✅ |

**MCTS wins:** Everything except Semgrep corpus (planned as optional extra).

---

### 3. agent-scan (Snyk)

| | agent-scan | MCTS |
|---|------------|------|
| Config inventory breadth | ✅ 10+ agents | ⚠️ 4 clients |
| Live introspection | ✅ Multi-client | ✅ Stdio (`--live`) |
| Security findings | ☁️ Snyk cloud | ✅ Local |
| SARIF | ❌ | ✅ |
| HTML dashboard | ❌ | ✅ |
| Enterprise guard hooks | ✅ | ❌ (out of scope) |

**MCTS wins:** Local findings, SARIF, HTML, no token required.  
**agent-scan wins:** Inventory breadth, live probe, enterprise runtime guard.

---

### 4. McpSafetyScanner (MCP-XPLORER)

| | McpSafetyScanner | MCTS |
|---|------------------|------|
| Production readiness | ❌ Alpha single-file | ✅ |
| Structured output | ❌ Markdown narrative | ✅ JSON/SARIF/HTML |
| Agent red-team | ✅ | ❌ (`pentest` stub) |
| Tests / CI | ❌ | ✅ |

**MCTS wins:** All structural/product dimensions.

---

### 5. scanner-main (SAF-MCP Scanner, Rust)

| | scanner-main | MCTS |
|---|--------------|------|
| MCTS technique mapping | ✅ 10 specs | ✅ MCTS-T taxonomy (41 techniques, 25 mitigations) |
| MCP server mode | ✅ | ❌ (Phase 3) |
| LLM required | ✅ | ❌ |
| Deterministic scan | ❌ | ✅ |
| SARIF | ❌ | ✅ |
| HTML | ❌ | ✅ |

**MCTS wins:** Offline CI, SARIF, HTML, deterministic scoring.  
**scanner-main wins:** MCP tools for IDE agents, SAF-MCP corpus depth.

---

### 6. saf-mcp (framework)

Not a scanner — taxonomy corpus. MCTS **links** via `technique_id` / optional external refs without vendoring the full corpus (**by design**).

---

### 7. mcp-guard

| | mcp-guard | MCTS |
|---|-----------|------|
| Dynamic fuzzing | ✅ ~5k LOC, broad `tools/call` by default | ✅ Safe read-only default; aggressive with consent |
| CVSS scoring | ✅ | ⚠️ Exponential security score (different model) |
| SARIF | ❌ | ✅ |
| HTML | ❌ | ✅ |
| Monolith maintainability | ⚠️ | ✅ Modular analyzers |
| Tests / CI | ⚠️ Minimal | ✅ |

**MCTS wins:** SARIF, HTML, CI, architecture, tests, CI-safe fuzz defaults.  
**mcp-guard wins:** Broader default `tools/call` fuzz coverage and larger payload corpus.

---

### 8. mcp-fortress (snapshot)

No auditable source in competitor folder — **not a code peer**. MCTS exceeds any claims verifiable from docs alone.

---

### 9. agent-security-scanner-mcp (ProofLayer)

| | agent-security | MCTS |
|---|----------------|------|
| General SAST (Semgrep 1700+ rules) | ✅ | ❌ (MCP-boundary focused) |
| SARIF | ✅ | ✅ |
| HTML | ✅ | ✅ (attack graph + OWASP) |
| MCP scan mode | ⚠️ Static filesystem | ✅ Static Python + TypeScript |
| Live MCP probe | ❌ | ✅ Stdio (`--live`) |
| Supply chain / SBOM | ✅ | ❌ (Phase 3) |
| Attack chains | ❌ | ✅ |
| Local-first default | ⚠️ Heavy deps | ✅ Lean core |

**MCTS wins:** Attack chains, MCP-specific scoring, lean install, capability graph.  
**agent-security wins:** SAST breadth, SBOM, compliance frameworks, MCP server mode.

---

## MCTS differentiators (why teams pick us)

1. **`mcts scan` → score → gate in CI** without API keys or LLM bills  
2. **Capability-graph attack chains** — read→exfil, read→exec paths with real graph data  
3. **Executive HTML dashboard** + **SARIF** in one toolchain  
4. **`mcts inventory`** + **cross-server shadowing** (`MCTS-T-1008`)  
5. **MCTS-T technique taxonomy** with CWE/OWASP mapping on every finding  
6. **19 analyzers** covering metadata poisoning, schema surface, command execution, path validation, runtime telemetry  
7. **`mcts fuzz`** — CI-safe read-only protocol fuzzing with consent-gated aggressive tier  

---

## Honest gaps (roadmap)

| Gap | Best peer | MCTS phase |
|-----|-----------|------------|
| SSE/HTTP live transports | mcp-scanner | Phase 2+ |
| Protocol fuzzing (safe defaults) | mcp-guard (broader aggressive) | ✅ Phase 2.1 |
| TypeScript discovery | ✅ `registerTool`, `server.tool`, `setRequestHandler` | ✅ Multi-language static |
| Semgrep optional layer | MCPScan / agent-security | Optional extra |
| MCP server mode (`mcts-mcp`) | agent-security | Phase 3.3 |
| Package vetting (`mcts vet`) | agent-scan / mcp-scanner | Phase 3.1 |

---

## Verdict matrix

| Tool | MCTS better overall? | Notes |
|------|---------------------|-------|
| mcp-scanner | **Partial** | Better CI/reporting; they win multi-transport live+SAST |
| MCPScan | **Yes** | Strictly ahead on product maturity |
| agent-scan | **Partial** | Better local CI; they win inventory breadth+cloud |
| McpSafetyScanner | **Yes** | |
| scanner-main | **Partial** | Better CI; they win MCP server mode |
| saf-mcp | N/A | Complementary corpus |
| mcp-guard | **Partial** | Better CI/reporting; they win default aggressive fuzz breadth |
| mcp-fortress | **Yes** | No code to compare |
| agent-security | **Partial** | Better MCP focus+chains; they win SAST/SBOM |

**MCTS is the best choice when:** you need offline MCP server scanning, PR gates, executive reports, and attack-chain intelligence without cloud or LLM dependency.

**Choose a peer when:** you need live multi-transport probing (mcp-scanner), unbounded destructive fuzzing without consent tiers (mcp-guard), or full-stack SAST+SBOM (agent-security).
