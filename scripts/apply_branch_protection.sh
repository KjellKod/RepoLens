#!/usr/bin/env bash
# X3b: apply (or re-apply) branch protection for the default branch.
#
# Idempotent — run it again whenever the required-check set grows.
# The repo is derived at runtime; no owner/repo literal is committed.
#
# Current policy (see docs/roadmap/rpl_roadmap.md "Branch protection"):
#   - required checks: security-canaries, codex-review, offline-ci
#   - strict: true  (branch must be up to date with main before merging)
#   - >=1 approving review (configured once in the UI/API; not touched here)
set -euo pipefail

REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
BRANCH="${1:-main}"

gh api -X PATCH "repos/${REPO}/branches/${BRANCH}/protection/required_status_checks" \
  --input - <<'JSON'
{
  "strict": true,
  "checks": [
    {"context": "security-canaries"},
    {"context": "codex-review"},
    {"context": "offline-ci"}
  ]
}
JSON

echo "Applied. Current protection for ${BRANCH}:"
gh api "repos/${REPO}/branches/${BRANCH}/protection" \
  --jq '{strict: .required_status_checks.strict, checks: [.required_status_checks.checks[].context], reviews: .required_pull_request_reviews.required_approving_review_count}'
