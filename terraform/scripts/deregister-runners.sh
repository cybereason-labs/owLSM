#!/bin/bash
set -euo pipefail

# =============================================================================
# Deregister GitHub Actions self-hosted runners by label and status.
# Calls the GitHub API to force-remove all offline runners matching a label.
# Designed to run BEFORE terraform destroy, since OCI instance termination
# does not allow graceful OS shutdown hooks.
#
# Usage:
#   ./deregister-runners.sh <repo> <label> [status]
#
# Arguments:
#   repo    - GitHub repository (owner/repo)
#   label   - Runner label to filter by (e.g., owLSM-automation)
#   status  - Runner status to filter by (default: offline)
#
# Environment:
#   GH_TOKEN - GitHub PAT with repo admin / self-hosted runners manage access
# =============================================================================

REPO="${1:?Usage: $0 <repo> <label> [status]}"
LABEL="${2:?Usage: $0 <repo> <label> [status]}"
STATUS="${3:-offline}"

if [ -z "${GH_TOKEN:-}" ]; then
    echo "::error::GH_TOKEN environment variable is not set"
    exit 1
fi

echo "Deregistering runners from '$REPO'..."
echo "  Label filter:  $LABEL"
echo "  Status filter: $STATUS"

# =========================================================================
# Fetch all runners and filter by label + status
# =========================================================================
RUNNERS_JSON=$(gh api "repos/${REPO}/actions/runners" --paginate --jq '.runners' 2>&1) || true
MERGED=$(echo "$RUNNERS_JSON" | jq -s 'add // []' 2>/dev/null) || MERGED="[]"

# Find runners matching both the label and the status
MATCHED=$(echo "$MERGED" | jq -c \
    "[.[] | select(.status == \"$STATUS\") | select(any(.labels[]; .name == \"$LABEL\"))]" \
    2>/dev/null) || MATCHED="[]"

RUNNER_COUNT=$(echo "$MATCHED" | jq 'length' 2>/dev/null) || RUNNER_COUNT=0

if [ "$RUNNER_COUNT" -eq 0 ]; then
    echo "  No $STATUS runners found with label '$LABEL'. Nothing to deregister."
    exit 0
fi

echo "  Found $RUNNER_COUNT $STATUS runner(s) to deregister:"
echo "$MATCHED" | jq -r '.[] | "    \(.name) (id=\(.id), status=\(.status))"' 2>/dev/null

# =========================================================================
# Delete each runner via the API
# =========================================================================
FAILED=0

for RUNNER_ID in $(echo "$MATCHED" | jq -r '.[].id' 2>/dev/null); do
    RUNNER_NAME=$(echo "$MATCHED" | jq -r ".[] | select(.id == $RUNNER_ID) | .name" 2>/dev/null)
    echo "  Removing runner '$RUNNER_NAME' (id=$RUNNER_ID)..."

    HTTP_CODE=$(gh api "repos/${REPO}/actions/runners/${RUNNER_ID}" \
        --method DELETE --silent 2>&1 && echo "204") || HTTP_CODE="failed"

    if [ "$HTTP_CODE" = "204" ]; then
        echo "    ✓ Removed successfully."
    else
        echo "    ✗ Failed to remove (response: $HTTP_CODE). Runner may already be gone."
        FAILED=$((FAILED + 1))
    fi
done

REMOVED=$((RUNNER_COUNT - FAILED))
echo "Deregistration complete: $REMOVED/$RUNNER_COUNT runners removed."

if [ "$FAILED" -gt 0 ]; then
    echo "::warning::$FAILED runner(s) could not be deregistered. They may need manual cleanup."
fi

exit 0
