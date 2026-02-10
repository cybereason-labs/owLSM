#!/bin/bash
set -euo pipefail

# =============================================================================
# Wait for GitHub Actions self-hosted runners to come online.
#
# Usage:
#   ./wait-for-runners.sh <repo> <run_label> <expected_count> [max_wait] [poll_interval]
#
# Arguments:
#   repo             - GitHub repository (owner/repo)
#   run_label        - Runner label to filter by (e.g., run-12345678)
#   expected_count   - Number of runners expected to come online
#   max_wait         - Max wait time in seconds (default: 300)
#   poll_interval    - Polling interval in seconds (default: 30)
#
# Environment:
#   GH_TOKEN         - GitHub PAT with repo admin / self-hosted runners read access
# =============================================================================

REPO="${1:?Usage: $0 <repo> <run_label> <expected_count> [max_wait] [poll_interval]}"
RUN_LABEL="${2:?Usage: $0 <repo> <run_label> <expected_count> [max_wait] [poll_interval]}"
EXPECTED_RUNNERS="${3:?Usage: $0 <repo> <run_label> <expected_count> [max_wait] [poll_interval]}"
MAX_WAIT="${4:-300}"
POLL_INTERVAL="${5:-30}"

if [ -z "${GH_TOKEN:-}" ]; then
    echo "::error::GH_TOKEN environment variable is not set"
    exit 1
fi

echo "Waiting for runners to register with GitHub..."
echo "  Repository:       $REPO"
echo "  Run label:        $RUN_LABEL"
echo "  Expected runners: $EXPECTED_RUNNERS"
echo "  Max wait:         ${MAX_WAIT}s"
echo "  Poll interval:    ${POLL_INTERVAL}s"

ELAPSED=0
ONLINE_COUNT=0
SEEN_ONLINE=""  # Track runners already reported as online

while [ $ELAPSED -lt $MAX_WAIT ]; do
    # Fetch all runners (--paginate + --jq flattens pages into a single array)
    RUNNERS_JSON=$(gh api "repos/${REPO}/actions/runners" --paginate --jq '.runners' 2>&1) || true

    # Merge paginated arrays into one: [page1...] [page2...] -> single array
    MERGED=$(echo "$RUNNERS_JSON" | jq -s 'add // []' 2>/dev/null) || MERGED="[]"

    # Debug: show all runners on first iteration
    if [ $ELAPSED -eq 0 ]; then
        echo "  Debug: All runners:"
        echo "$MERGED" | jq -r '.[] | "    \(.name) | status=\(.status) | labels=\([.labels[].name] | join(","))"'
    fi

    # Get names of online runners matching our label
    ONLINE_NAMES=$(echo "$MERGED" | jq -r \
        "[.[] | select(.status == \"online\") | select(any(.labels[]; .name == \"$RUN_LABEL\"))] | .[].name")

    ONLINE_COUNT=$(echo "$ONLINE_NAMES" | grep -c . 2>/dev/null || echo "0")

    # Print newly appeared online runners
    if [ -n "$ONLINE_NAMES" ]; then
        while IFS= read -r runner_name; do
            if ! echo "$SEEN_ONLINE" | grep -qF "$runner_name"; then
                echo "  ✓ Runner online: $runner_name (at ${ELAPSED}s)"
                SEEN_ONLINE="${SEEN_ONLINE}${runner_name}"$'\n'
            fi
        done <<< "$ONLINE_NAMES"
    fi

    echo "  Online runners with label '$RUN_LABEL': $ONLINE_COUNT / $EXPECTED_RUNNERS (elapsed: ${ELAPSED}s)"

    if [ "$ONLINE_COUNT" -ge "$EXPECTED_RUNNERS" ]; then
        echo "All expected runners are online!"
        exit 0
    fi

    sleep "$POLL_INTERVAL"
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

# Timeout reached -- fail the step
echo "::error::Timed out waiting for runners. Only $ONLINE_COUNT / $EXPECTED_RUNNERS are online after ${MAX_WAIT}s."
echo "  Final runner state:"
echo "$MERGED" | jq -r '.[] | "    \(.name) | status=\(.status) | labels=\([.labels[].name] | join(","))"' 2>/dev/null || true
exit 1
