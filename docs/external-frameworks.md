# External Threat Frameworks

MCTS uses a **first-party taxonomy** (`MCTS-T-*` techniques, `MCTS-M-*` mitigations). Industry MCP threat frameworks and Sigma rule corpora inform detection patterns and roadmap priorities but are **not vendored** in this repository.

**Product source of truth:** `src/mcts/taxonomy/techniques.json` · [Threat Taxonomy](taxonomy.md)

---

## Framework vs scanner

| Dimension | External threat framework | MCTS |
|-----------|---------------------------|------|
| **What it is** | Threat intelligence catalog | Automated MCP security scanner |
| **Primary output** | Technique dossiers, Sigma YAML, mitigations | Findings, scores, JSON/SARIF/HTML |
| **Execution** | Reference artifacts and documentation | CLI: `mcts scan`, `inventory`, `fuzz` |
| **Answers** | "What attacks exist and how do they work?" | "Does my server/config exhibit this risk?" |

They are **complementary**: frameworks describe the threat space; MCTS operationalizes detection for MCP server authors.

```
   Industry threat taxonomy
   (techniques, Sigma rules, mitigations)
              │
    patterns adapted into MCTS modules
              │
              ▼
         MCTS scan pipeline
              │
              ▼
   Findings with MCTS-T-* / MCTS-M-* IDs
```

---

## MCTS reports use native IDs only

Scan output emits `technique_id` (MCTS-T-*) and `mitigation_ids` (MCTS-M-*). External technique IDs are **not** written to findings — maintainers may use informal crosswalks internally for gap analysis when reading upstream dossiers.

---

## Pattern adoption in MCTS

Detection patterns from industry reference corpora were adapted into MCTS-owned modules:

| Area | MCTS modules | Status |
|------|--------------|--------|
| TPA / metadata poisoning | `tpa_patterns.py`, `prompt_injection`, `metadata_integrity`, `sigma_metadata` | Shipped |
| Homoglyph, Unicode tag block, mixed-script | `tpa_patterns.py` | Shipped |
| Recursive schema / FSP | `schema_fsp.py`, `schema_surface.py` | Partial |
| Credential regex + semantic secrets | `data_leakage.py`, `embedding_secrets.py` (`--semantic-secrets`) | Shipped |
| Path traversal encodings | `path_traversal.py`, fuzz payloads | Shipped |
| Sigma metadata rules | `taxonomy/sigma/metadata_rules.json`, `--sigma-rules-path` | Shipped |
| OAuth misconfiguration | `oauth_config.py`, runtime OAuth cluster | Shipped |
| Rug pull / redefinition | `metadata_diff.py`, `tool_redefinition.py`, `--baseline` | Shipped |
| Supply chain signals | `supply_chain.py` | Shipped |
| Regression fixtures | `tests/fixtures/regression/MCTS-T-*/` | Shipped (34+ IDs, CI ≥80% gate) |

When adapting external Sigma rules, attribute upstream per license terms; ship compiled rules under MCTS-owned paths only.

---

## Static vs runtime detection

Many industry Sigma rules assume **runtime telemetry** (`tool_description`, `path`, `oauth_token`, invocation logs). MCTS primarily performs **pre-deployment static analysis** on source and discovered tool metadata, plus optional live/fuzz telemetry via `--live`, `mcts fuzz`, and `--runtime-events`.

Both layers are valid; they are not drop-in substitutes. Runtime rules must be adapted to metadata and source context when porting patterns.

---

## Roadmap priorities from threat density

Technique density in industry catalogs suggests where to expand MCTS next:

- **Initial Access + Execution + Privilege Escalation** — TPA, prompt injection, OAuth, cross-server escalation  
- **Additional regression fixtures** — multimodal, exfiltration, and persistence clusters  
- **Optional advanced** — embedding-based credential detection, deeper behavioral probes, vector-store checks for RAG MCP servers  

---

## What not to port blindly

| External artifact | Why caution |
|-------------------|-------------|
| Runtime Sigma rules on static repos | Log field names do not exist in source scans |
| Behavioral demo thresholds | Tuned for conversation logs, not tool manifests |
| Attack PoC scripts | Use as test vectors only — do not bundle into scanner |
| Immature technique drafts | Wait for stable definitions before MCTS-T promotion |

---

## Related

- [Threat Taxonomy](taxonomy.md)
- [Product Positioning](product-positioning.md)
- [Architecture — Taxonomy](architecture.md#taxonomy-taxonomy)
