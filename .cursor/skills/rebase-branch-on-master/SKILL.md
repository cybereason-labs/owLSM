---
name: rebase-branch-on-master
description: Safely rebases the current feature branch onto a target branch (default: main) with automatic stash handling and conflict detection.
---

# Rebase Branch onto Target

You are a Git workflow assistant that safely rebases the current branch onto a target branch.

## Input Parameter

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `target_branch` | No | `main` | The branch to rebase onto. User can specify any branch name. |

**Example invocations:**
- "rebase my branch" → rebases onto `main`
- "rebase onto develop" → rebases onto `develop`
- "rebase on feature/base" → rebases onto `feature/base`

## Pre-flight Checks (MUST ALL PASS before proceeding)

Before doing anything, verify ALL of the following. If ANY check fails, **STOP and report the issue** (and restore stash if already created):

1. **Target branch exists** — The specified target branch must exist locally or on remote
2. **Not on target branch** — Cannot rebase a branch onto itself
3. **Not on a detached HEAD** — Must be on a named branch
4. **Remote exists** — `origin` remote must be configured
5. **Network accessible** — Can reach the remote (test with `git ls-remote`)
6. **No ongoing rebase/merge/cherry-pick** — Check `.git/rebase-merge`, `.git/MERGE_HEAD`, `.git/CHERRY_PICK_HEAD`

## Critical Rule: ALWAYS Restore Stash on Any Error

**If a stash was created, it MUST be restored before reporting any error.**

This is non-negotiable. Use try-finally logic:
1. If stash was created → remember this
2. Do all operations
3. On ANY failure after stash → restore stash FIRST, then report error
4. On success → restore stash at the end

## Workflow

### Step 1: Record Initial State and Determine Target Branch

```bash
# Save current branch name
CURRENT_BRANCH=$(git branch --show-current)

# Target branch: use user-specified or default to "main"
TARGET_BRANCH="${USER_SPECIFIED_TARGET:-main}"

# Verify target branch exists (locally or on remote)
if ! git show-ref --verify --quiet "refs/heads/$TARGET_BRANCH" && \
   ! git show-ref --verify --quiet "refs/remotes/origin/$TARGET_BRANCH"; then
    echo "ERROR: Target branch '$TARGET_BRANCH' does not exist locally or on remote"
    exit 1
fi

# Verify we're not already on the target branch
if [ "$CURRENT_BRANCH" = "$TARGET_BRANCH" ]; then
    echo "ERROR: Already on target branch '$TARGET_BRANCH'. Cannot rebase onto itself."
    exit 1
fi
```

### Step 2: Stash Changes (if any) — PRESERVING STAGED/UNSTAGED STRUCTURE

Check for uncommitted changes and stash them:

```bash
# Check for any changes
HAS_CHANGES=false
if ! git diff --cached --quiet || ! git diff --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
    HAS_CHANGES=true
fi

STASH_CREATED=false
STASH_MSG=""

if [ "$HAS_CHANGES" = true ]; then
    # Stash everything including untracked files, with a unique marker
    STASH_MSG="rebase-skill-auto-stash-$(date +%s)-$$"
    git stash push -u -m "$STASH_MSG"
    STASH_CREATED=true
    echo "Stash created: $STASH_MSG"
fi
```

### Step 3: Fetch and Update Target Branch

**From this point on, ANY error must restore the stash first!**

```bash
# Fetch latest from remote
git fetch origin

# If target branch exists locally, update it
if git show-ref --verify --quiet "refs/heads/$TARGET_BRANCH"; then
    git checkout "$TARGET_BRANCH"
    if ! git pull origin "$TARGET_BRANCH" --ff-only; then
        echo "ERROR: Cannot fast-forward $TARGET_BRANCH. Local branch has diverged."
        # RESTORE STASH BEFORE EXITING
        restore_stash_if_needed
        exit 1
    fi
fi
```

### Step 4: Attempt Rebase

```bash
# Return to the original branch
git checkout "$CURRENT_BRANCH"

# Attempt rebase onto target (use origin/target if local doesn't exist)
if git show-ref --verify --quiet "refs/heads/$TARGET_BRANCH"; then
    REBASE_TARGET="$TARGET_BRANCH"
else
    REBASE_TARGET="origin/$TARGET_BRANCH"
fi

if ! git rebase "$REBASE_TARGET"; then
    # Rebase failed - ABORT to preserve original state
    git rebase --abort
    echo "ERROR: Rebase failed due to conflicts. Aborted to preserve original state."
    # RESTORE STASH BEFORE EXITING
    restore_stash_if_needed
    exit 1
fi

echo "Rebase successful!"
```

### Step 5: Push Changes

**Only if rebase succeeded:**

```bash
# Use --force-with-lease for safety (fails if remote has new commits we don't know about)
if ! git push --force-with-lease origin "$CURRENT_BRANCH"; then
    echo "WARNING: Push failed. Someone else may have pushed to this branch."
    echo "Local rebase is intact. You can retry push manually or investigate."
    # Still restore stash - this is a warning, not a fatal error
fi
```

### Step 6: Restore Stashed Changes — WITH STAGED/UNSTAGED PRESERVATION

**This step MUST run regardless of success/failure (if stash was created):**

```bash
restore_stash_if_needed() {
    if [ "$STASH_CREATED" = true ] && [ -n "$STASH_MSG" ]; then
        # Find our stash by its unique message
        STASH_REF=$(git stash list | grep "$STASH_MSG" | head -1 | cut -d: -f1)
        if [ -n "$STASH_REF" ]; then
            # Use --index to PRESERVE the staged/unstaged structure
            if git stash pop --index "$STASH_REF"; then
                echo "Stash restored successfully (staged/unstaged structure preserved)"
            else
                # If --index fails (can happen with conflicts), try without it
                echo "WARNING: Could not restore with staged/unstaged structure."
                echo "Attempting plain restore..."
                git stash pop "$STASH_REF" || {
                    echo "ERROR: Stash restore failed. Your changes are still in stash: $STASH_REF"
                    echo "Run 'git stash list' to see it and 'git stash pop' to restore manually."
                }
            fi
        else
            echo "WARNING: Could not find stash with message: $STASH_MSG"
        fi
    fi
}

# Always call this at the end
restore_stash_if_needed
```

## Error Handling Summary

| Scenario | Action |
|----------|--------|
| Target branch doesn't exist | STOP immediately (before stash) |
| Already on target branch | STOP immediately (before stash) |
| Detached HEAD | STOP immediately (before stash) |
| Ongoing rebase/merge | STOP immediately (before stash) |
| Network unreachable | Restore stash, then STOP |
| Target branch diverged | Restore stash, then STOP |
| Rebase conflicts | Abort rebase, restore stash, then STOP |
| Push rejected | Restore stash, report warning (keep local rebase) |
| Stash pop conflicts | Report — changes remain in stash for manual recovery |

## Output Format

Report the following at each stage:
- Current branch: `{branch_name}`
- Target branch: `{target_branch}` (user-specified or default)
- Stash created: `{yes|no}`
- Fetch result: `{success|failure}`
- Rebase result: `{success|aborted due to conflicts}`
- Push result: `{success|failed|skipped}`
- Stash restored: `{yes (with index)|yes (without index)|failed|N/A}`

## Safety Guarantees

1. **No data loss** — All changes are stashed before any git operations
2. **Staged/unstaged preserved** — Uses `git stash pop --index` to maintain staging structure
3. **Guaranteed stash restore** — Stash is ALWAYS restored on any error after creation
4. **Atomic rebase** — If rebase fails, it's fully aborted (not left half-done)
5. **Safe push** — Uses `--force-with-lease` which fails if remote has unexpected commits
6. **Reversible** — Original branch state is preserved if anything fails

