#!/usr/bin/env bash
# Quick local validation for MCTS CLI (run from repo root).
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
RAW=$(mktemp /tmp/mcts-raw.XXXXXX.json)
trap 'rm -f "$RAW"' EXIT
uv run mcts scan examples/baseline-mcp-server/server.py --format raw -o "$RAW" --no-progress
python3 -c "import json, sys; p=json.load(open(sys.argv[1])); assert 'scan_results' in p" "$RAW"

echo "== pytest =="
uv run pytest tests/ -q --tb=no

echo "All CLI end-to-end checks passed."
