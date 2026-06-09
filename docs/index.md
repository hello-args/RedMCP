# MCTS Documentation

**MCTS** (Model Context Threat Scanner) is a security scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers. It finds vulnerabilities in the tools, prompts, and resources that AI agents can access — before attackers do.

> **New here?** Start with [Install and first scan](get-started/getting-started.md). Unfamiliar with a term? See the [Glossary](glossary.md).

---

## What problem does MCTS solve?

AI assistants connect to external capabilities through **MCP servers** — small programs that expose tools like "query database", "read file", or "send email". If a server is poorly designed, an attacker (or a manipulated AI) could:

- Delete data through an overly powerful tool
- Steal secrets embedded in server code
- Chain multiple innocent-looking tools into a serious attack
- Trick the AI with poisoned tool descriptions

MCTS scans MCP servers the same way you would run a linter or SAST tool on application code — locally, in CI, with clear pass/fail gates.

```bash
mcts scan ./server.py                    # Scan and show results in terminal
mcts scan ./server.py -o report.json     # Save full report as JSON
mcts report report.json -o report.html   # Generate shareable HTML dashboard
```

---

## How MCTS works (four steps)

| Step | What happens | Example output |
|------|--------------|----------------|
| **1. Discover** | Find tools, prompts, resources, and handler code from source files, live probes, or exported JSON | List of 12 tools with schemas |
| **2. Analyze** | Run 20+ security checks on permissions, injection, secrets, attack chains, and more | 15 findings across 4 severity levels |
| **3. Score** | Compute a 0–100 security score with a transparent, auditable formula | Score: 67/100 (MEDIUM) |
| **4. Report** | Show results in terminal, JSON, SARIF (for GitHub), or HTML dashboard | Terminal table, CI artifact, executive report |

Details: [Architecture](analysis/architecture.md)

---

## Choose your path

Pick the guide that matches your role:

| I am a… | Start here | Then read |
|---------|------------|-----------|
| **Developer new to MCTS** | [Getting Started](get-started/getting-started.md) | [CLI Reference](platform/cli.md) |
| **MCP server author** | [Getting Started](get-started/getting-started.md) → scan your repo | [Security Checks](analysis/security-checks.md) |
| **DevOps / CI engineer** | [CI Integration](platform/ci-integration.md) | [Scoring Spec](reporting/scoring-spec.md) (gate thresholds) |
| **Security engineer** | [Architecture](analysis/architecture.md) | [Threat Taxonomy](reporting/taxonomy.md) |
| **Security / engineering leader** | [Getting Started](get-started/getting-started.md) → HTML report | [Product Positioning](more/product-positioning.md) |
| **Contributor** | [CONTRIBUTING.md](../CONTRIBUTING.md) | [Issue labeling guide](contributing/issue-labeling.md) |
| **Issue triage / planning** | [Issue labeling guide](contributing/issue-labeling.md) | [Feature Expansion Plan](more/feature-expansion-plan.md) |

---

## Documentation sections

### Get Started

Install MCTS, run your first scan, and understand the output.

- [Install and first scan](get-started/getting-started.md) — step-by-step guide (~15 minutes)
- [Get Started section](get-started/README.md)

### Scanning

How MCTS finds MCP servers and collects data before analysis.

| Guide | When to use it |
|-------|----------------|
| [Live Scanning](scanning/live-scanning.md) | You want to probe a running server, not just read source code |
| [Remote Scanning](scanning/remote-scanning.md) | The server is hosted over HTTP/SSE, not on your machine |
| [Static Snapshot](scanning/static-snapshot.md) | You have an exported JSON file and no network access |
| [Protocol Fuzzing](scanning/fuzzing.md) | You want to test how the server handles bad input |
| [TypeScript Discovery](scanning/typescript-discovery.md) | Your MCP server is written in Node.js/TypeScript |
| [Config Inventory](scanning/inventory.md) | You want to audit which MCP servers are installed locally |
| [Readiness Scanning](scanning/readiness.md) | You want production-readiness checks (separate from security) |

All scanning guides: [scanning/](scanning/README.md)

### Analysis

How findings are produced from discovered tools and source code.

| Guide | What you'll learn |
|-------|-------------------|
| [Security Checks Reference](analysis/security-checks.md) | Every check MCTS runs, what it looks for, and how to enable it |
| [Architecture](analysis/architecture.md) | Full pipeline: discovery → analyzers → scoring → reporting |

All analysis guides: [analysis/](analysis/README.md)

### Reporting

Scores, threat labels, and export formats.

| Guide | What you'll learn |
|-------|-------------------|
| [Scoring Specification](reporting/scoring-spec.md) | How the 0–100 score is calculated and how to set CI gates |
| [Threat Taxonomy](reporting/taxonomy.md) | MCTS-T technique IDs and MCTS-M mitigation IDs on findings |
| [HTML Security Dashboard](reporting/html-report.md) | Generate and share executive security reports |

All reporting guides: [reporting/](reporting/README.md)

### Platform

Running MCTS from the command line, in CI, or via API.

| Guide | What you'll learn |
|-------|-------------------|
| [CLI Reference](platform/cli.md) | Every command and flag |
| [REST API](platform/rest-api.md) | Programmatic scans via `mcts serve` |
| [CI Integration](platform/ci-integration.md) | GitHub Action, SARIF upload, pipeline gates |

All platform guides: [platform/](platform/README.md)

### Contributing

Issue tracking, labeling rules, and templates.

| Guide | What you'll learn |
|-------|-------------------|
| [Issue Labeling & Creation](contributing/issue-labeling.md) | How to open issues, pick labels, and use the body template |
| [Contributing section](contributing/README.md) | Index of contributor-facing docs |

### More

Planning, positioning, and contributor references.

| Guide | Audience |
|-------|----------|
| [Product Positioning](more/product-positioning.md) | What MCTS is for, who uses it, how it compares to other tools |
| [Product Roadmap](more/roadmap.md) | What's shipped vs planned, phased deliverables |
| [Feature Expansion Plan](more/feature-expansion-plan.md) | Detailed gap analysis and implementation guide for contributors |
| [External Frameworks](more/external-frameworks.md) | How MCTS relates to industry threat taxonomies |

All planning docs: [more/](more/README.md)

---

## Quick reference

| I want to… | Command |
|------------|---------|
| Scan a Python MCP server | `mcts scan ./server.py` |
| Scan a whole repository | `mcts scan ./repo/` |
| Fail CI on critical findings | `mcts scan ./server.py --fail-on-critical --min-score 70` |
| Export for GitHub Code Scanning | `mcts scan ./server.py -o report.sarif --format sarif` |
| Share results with leadership | `mcts report report.json -o security-report.html` |
| See what's installed on my machine | `mcts inventory --scan` |
| Probe a running server | `mcts scan ./server.py --live --i-understand-live-risk` |

Full flag reference: [CLI Reference](platform/cli.md)

---

## Reference

- [Glossary](glossary.md) — plain-language definitions for all key terms
- [Changelog](../CHANGELOG.md) — release notes
- [CONTRIBUTING.md](../CONTRIBUTING.md) — development workflow
- [Issue labeling guide](contributing/issue-labeling.md) — GitHub issue taxonomy and templates
- [SECURITY.md](../SECURITY.md) — vulnerability reporting
