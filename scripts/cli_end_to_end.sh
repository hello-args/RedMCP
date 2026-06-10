#!/usr/bin/env bash
# Quick local validation for MCTS CLI (run from repo root).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash scripts/cli_smoke.sh

echo "== pytest =="
uv run pytest tests/ -q --tb=no

echo "All CLI end-to-end checks passed."
