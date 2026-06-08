# Analysis

> [Documentation](../index.md) → **Analysis**

How MCTS transforms `MCPServerInfo` into scored, taxonomy-enriched `ScanReport` output.

---

## Guide

| Page | Contents |
|------|----------|
| [Security Checks Reference](security-checks.md) | Every analyzer and check — what it detects, examples, and how to run |
| [Architecture](architecture.md) | End-to-end pipeline, data models (`MCPServerInfo`, `Finding`, `ScanReport`), discovery/probe/scanner layers, full analyzer registry, capability graphs, scoring, reporting, extension points |

---

## Key concepts

| Concept | Description |
|---------|-------------|
| **MCPServerInfo** | Discovered tools, schemas, source snippets, runtime events |
| **Analyzers** | 20 enabled by default (22 registered; 25+ with optional flags) in `core/scanner.py` |
| **Attack chains** | Capability-graph BFS (MCTS-T-1005) |
| **Taxonomy enrichment** | Post-processing attaches MCTS-T / MCTS-M IDs |
| **Compliance** | OWASP meta-findings (non-scoring) |

---

## Related

- [Scanning modes](../scanning/README.md)
- [Threat Taxonomy](../reporting/taxonomy.md)
- [Scoring Specification](../reporting/scoring-spec.md)
- [Documentation index](../index.md)
