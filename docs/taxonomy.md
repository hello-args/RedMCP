# MCTS Threat Taxonomy

MCTS uses a first-party technique and mitigation catalog. Findings expose `technique_id` (MCTS-T-*), `mitigation_ids` (MCTS-M-*), `cwe_id`, and `confidence`. SARIF and HTML reports link back to this catalog.

**Source of truth:** `src/mcts/taxonomy/techniques.json`  
**Enrichment:** `src/mcts/taxonomy/mapper.py` (runs on every scan after analyzers)

---

## Technique IDs (MCTS-T-*)

| ID | Name | Primary analyzers |
|----|------|-------------------|
| MCTS-T-1001 | Tool Description Poisoning | `prompt_injection`, `metadata_integrity` |
| MCTS-T-1001.002 | Schema Surface Poisoning (FSP) | `schema_surface` |
| MCTS-T-1002 | Path Traversal / Missing Validation | `path_validation`, `tool_abuse` |
| MCTS-T-1003 | Command Execution via Tool Handler | `command_execution` |
| MCTS-T-1004 | Sensitive Data Exposure | `data_leakage` |
| MCTS-T-1005 | Multi-Step Attack Chain | `attack_chains` |
| MCTS-T-1006 | Excessive Tool Permissions | `permission_analyzer` |
| MCTS-T-1007 | Tool Output Prompt Injection | `jailbreak`, `runtime_events` |
| MCTS-T-1008 | Cross-Server Tool Shadowing | `cross_server` |
| MCTS-T-1009 | Protocol Fuzzing Exposure | `fuzz`, `runtime_events` |
| MCTS-T-1010 | Sigma Metadata Rule Match | `sigma_metadata` |
| MCTS-T-1011–1019 | OAuth / token escalation family | `oauth_config`, `runtime_events` |
| MCTS-T-1020 | Tool Shadowing Attack | `tool_shadowing` |
| MCTS-T-1021 | Line Jumping / Context Precedence | `line_jumping` |
| MCTS-T-1022 | Semantic Credential Exposure | `embedding_secrets` |
| MCTS-T-1023–1039 | Runtime telemetry techniques | `runtime_events` |
| MCTS-T-1040 | Persistent Tool Redefinition | `metadata_diff`, `runtime_events` |
| MCTS-T-1041 | Instruction Steganography in Metadata | `runtime_events`, `instruction_steganography` |

Run for the full machine-readable catalog:

```bash
uv run python -c "from mcts.taxonomy.mapper import technique_catalog; print(len(technique_catalog()))"
```

---

## Runtime event techniques (MCTS-T-1023+)

`RuntimeEventsAnalyzer` maps probe/telemetry rows to techniques via focused detectors in `analyzers/`:

| Detector module | Example technique |
|-----------------|-------------------|
| `command_injection` | MCTS-T-1023 |
| `oauth_mixup` | MCTS-T-1012 |
| `rug_pull` | MCTS-T-1013 |
| `behavioral_extraction` | MCTS-T-1026 |
| `tool_redefinition` | MCTS-T-1040 |
| `instruction_steganography` | MCTS-T-1041 |

Events originate from `--runtime-events`, `--live`, `--behavioral-probe`, or `mcts fuzz` output.

---

## Mitigation IDs (MCTS-M-*)

Twenty-five mitigations (`MCTS-M-001` … `MCTS-M-025`) map to one or more techniques. The mapper attaches all mitigations whose `techniques` list includes a finding's `technique_id`.

Opt-in semantic secrets detection references **MCTS-M-025** / **MCTS-T-1022** (`--semantic-secrets`).

---

## Sigma rule IDs (MCTS-S-*)

Bundled metadata Sigma rules in `src/mcts/taxonomy/sigma/metadata_rules.json` may reference **MCTS-S-*** IDs for pattern-only detections that do not yet have a full MCTS-T dossier. When `sigma_metadata` matches such a rule, the finding's `technique_id` is the rule's technique field (MCTS-T-* or MCTS-S-*).

Extra YAML rules can be supplied via `--sigma-rules-path` (directories named `MCTS-T-*/detection-rule.yml`).

---

## Regression fixtures

Thirty-four+ technique regression cases live under `tests/fixtures/regression/MCTS-T-*/`. CI enforces ≥80% detector accuracy via `src/mcts/testing/regression_harness.py`.

---

## Related

- [Architecture — Taxonomy](architecture.md#taxonomy-taxonomy)
- [CLI — sigma and semantic flags](cli.md#mcts-scan)
- [Scoring Spec](scoring-spec.md) (compliance findings excluded from score)
- [External Frameworks](external-frameworks.md) — Industry taxonomy relationship and pattern adoption
