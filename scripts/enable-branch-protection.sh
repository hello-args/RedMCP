#!/usr/bin/env bash
set -euo pipefail

# Apply branch protection requiring the CI "test" job to pass.
# Requires: gh CLI authenticated with admin access to the repository.
#
# Usage:
#   ./scripts/enable-branch-protection.sh
#   ./scripts/enable-branch-protection.sh hello-args/MCPVault

REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
RULESET_FILE="$(cd "$(dirname "$0")/.." && pwd)/.github/rulesets/main.json"

echo "Applying ruleset to ${REPO}..."
gh api "repos/${REPO}/rulesets" \
  --method POST \
  --input "${RULESET_FILE}"

echo "Done. Verify at: https://github.com/${REPO}/settings/rules"
