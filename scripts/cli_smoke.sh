#!/usr/bin/env bash
# CLI smoke checks for CI (no pytest — test-gate runs pytest separately).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== mcts version =="
uv run mcts --version

echo "== static repo scan =="
uv run mcts scan examples/vulnerable-mcp-server/server.py --no-progress

echo "== snapshot scan =="
uv run mcts scan . --snapshot examples/fixtures/prompts-snapshot.json --surfaces prompt,instruction --no-progress

echo "== scan-prompts subcommand =="
uv run mcts scan-prompts . --snapshot examples/fixtures/prompts-snapshot.json

echo "== readiness heuristics =="
uv run mcts readiness examples/baseline-mcp-server/server.py

echo "== raw envelope output =="
uv run mcts scan examples/baseline-mcp-server/server.py --format raw -o /tmp/mcts-raw.json --no-progress
python3 -c "import json; p=json.load(open('/tmp/mcts-raw.json')); assert 'scan_results' in p"

echo "CLI smoke checks passed."
