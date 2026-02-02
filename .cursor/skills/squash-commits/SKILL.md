---
name: squash-commits
description: Squashes multiple commits on the current branch into a single commit with an auto-generated message, then pushes.
---

# Squash Commits

You are a Git workflow assistant that squashes commits on the current branch into a single commit.

## Input Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `mode` | No | `since-branch` | How to determine which commits to squash |
| `base_branch` | No | `main` | For `since-branch` mode: the branch we branched from |
| `commit_count` | No | - | For `count` mode: number of commits to squash |
| `since_commit` | No | - | For `since-commit` mode: squash all commits after this SHA |

## Modes

### Mode 1: `since-branch` (Default)
Squash all commits since branching from a base branch.

**Example invocations:**
- "squash my commits" → squashes all commits since branching from `main`
- "squash commits since develop" → squashes all commits since branching from `develop`
- "squash since feature/base" → squashes all commits since branching from `feature/base`

### Mode 2: `count`
Squash a specific number of recent commits.

**Example invocations:**
- "squash last 3 commits"
- "squash the last 5 commits into one"

### Mode 3: `since-commit`
Squash all commits after a specific commit SHA.

**Example invocations:**
- "squash all commits after abc1234"
- "squash commits since abc1234"

## Pre-flight Checks (MUST ALL PASS before proceeding)

Before doing anything, verify ALL of the following. If ANY check fails, **STOP and report the issue**:

1. **Not on main/master/develop** — Squashing protected branches is dangerous
2. **Not on a detached HEAD** — Must be on a named branch
3. **No uncommitted changes** — Working directory must be clean (or stash first)
4. **Commits exist to squash** — At least 2 commits must be selected for squashing
5. **No ongoing rebase/merge** — Check `.git/rebase-merge`, `.git/MERGE_HEAD`
6. **Remote exists** — `origin` remote must be configured (for push)

## Critical Rule: Preserve Original State on Any Error

If anything fails after we start modifying history:
1. Use `git rebase --abort` if in rebase
2. Use `git reset --hard ORIG_HEAD` to restore if reset was used
3. Restore stash if created
4. Report the error clearly

## Workflow

### Step 1: Record Initial State

```bash
# Save current branch name
CURRENT_BRANCH=$(git branch --show-current)

# Verify not on protected branch
case "$CURRENT_BRANCH" in
    main|master|develop)
        echo "ERROR: Cannot squash commits on protected branch '$CURRENT_BRANCH'"
        exit 1
        ;;
esac

# Save current HEAD for recovery
ORIGINAL_HEAD=$(git rev-parse HEAD)

# Check for uncommitted changes
if ! git diff --cached --quiet || ! git diff --quiet; then
    echo "ERROR: You have uncommitted changes. Please commit or stash them first."
    exit 1
fi
```

### Step 2: Determine Commits to Squash

**For `since-branch` mode (default):**
```bash
BASE_BRANCH="${USER_SPECIFIED_BASE:-main}"

# Find the merge-base (where this branch diverged from base)
MERGE_BASE=$(git merge-base HEAD "$BASE_BRANCH" 2>/dev/null || \
             git merge-base HEAD "origin/$BASE_BRANCH" 2>/dev/null)

if [ -z "$MERGE_BASE" ]; then
    echo "ERROR: Cannot find common ancestor with '$BASE_BRANCH'"
    exit 1
fi

# Count commits to squash
COMMIT_COUNT=$(git rev-list --count "$MERGE_BASE"..HEAD)
```

**For `count` mode:**
```bash
COMMIT_COUNT=$USER_SPECIFIED_COUNT

# Verify we have enough commits
TOTAL_COMMITS=$(git rev-list --count HEAD)
if [ "$COMMIT_COUNT" -gt "$TOTAL_COMMITS" ]; then
    echo "ERROR: Requested $COMMIT_COUNT commits but branch only has $TOTAL_COMMITS"
    exit 1
fi

# Calculate the base commit
MERGE_BASE=$(git rev-parse "HEAD~$COMMIT_COUNT")
```

**For `since-commit` mode:**
```bash
SINCE_COMMIT=$USER_SPECIFIED_COMMIT

# Verify commit exists and is an ancestor
if ! git merge-base --is-ancestor "$SINCE_COMMIT" HEAD; then
    echo "ERROR: Commit '$SINCE_COMMIT' is not an ancestor of current HEAD"
    exit 1
fi

MERGE_BASE=$SINCE_COMMIT
COMMIT_COUNT=$(git rev-list --count "$MERGE_BASE"..HEAD)
```

### Step 3: Validate Commit Count

```bash
if [ "$COMMIT_COUNT" -lt 2 ]; then
    echo "ERROR: Need at least 2 commits to squash. Found: $COMMIT_COUNT"
    exit 1
fi

echo "Will squash $COMMIT_COUNT commits into one"
echo "Commits to be squashed:"
git log --oneline "$MERGE_BASE"..HEAD
```

### Step 4: Generate Commit Message

Analyze all commits being squashed and create a meaningful message:

```bash
# Collect all commit messages
ALL_MESSAGES=$(git log --format="%s%n%b" "$MERGE_BASE"..HEAD)

# Collect summary of files changed
FILES_CHANGED=$(git diff --stat "$MERGE_BASE"..HEAD)

# Get the branch name for context
BRANCH_CONTEXT=$(echo "$CURRENT_BRANCH" | sed 's/[-_]/ /g')
```

**Generate a commit message that includes:**
1. A summary line describing the overall change (based on branch name and commits)
2. A blank line
3. "Squashed commits:" header
4. List of original commit messages (indented)
5. Optionally: files changed summary

**Example generated message:**
```
feat: Add user authentication flow

Squashed commits:
- Add login form component
- Implement JWT token handling  
- Add password validation
- Fix login redirect bug
- Update tests for auth flow

Files changed: 12 files, +450/-23 lines
```

### Step 5: Perform the Squash

**Method: Soft Reset + Commit (simpler than interactive rebase)**

```bash
# Soft reset to merge base - keeps all changes staged
git reset --soft "$MERGE_BASE"

# Commit with the generated message
git commit -m "$GENERATED_MESSAGE"
```

**If this fails:**
```bash
# Restore original state
git reset --hard "$ORIGINAL_HEAD"
echo "ERROR: Squash failed. Original state restored."
exit 1
```

### Step 6: Push Changes

```bash
# Force push with lease for safety
if ! git push --force-with-lease origin "$CURRENT_BRANCH"; then
    echo "WARNING: Push failed. Possible reasons:"
    echo "  - Someone else pushed to this branch"
    echo "  - Remote branch doesn't exist yet (try: git push -u origin $CURRENT_BRANCH)"
    echo ""
    echo "Local squash is intact. You can:"
    echo "  - Retry with: git push --force-with-lease origin $CURRENT_BRANCH"
    echo "  - Or undo with: git reset --hard $ORIGINAL_HEAD"
fi
```

### Step 7: Report Success

```bash
echo ""
echo "=== Squash Complete ==="
echo "Branch: $CURRENT_BRANCH"
echo "Commits squashed: $COMMIT_COUNT → 1"
echo "New commit: $(git rev-parse --short HEAD)"
echo ""
echo "Original HEAD was: $ORIGINAL_HEAD"
echo "To undo: git reset --hard $ORIGINAL_HEAD && git push --force-with-lease"
```

## Error Handling Summary

| Scenario | Action |
|----------|--------|
| On protected branch (main/master/develop) | STOP immediately |
| Uncommitted changes | STOP: ask user to commit or stash |
| Base branch doesn't exist | STOP: report and suggest alternatives |
| Less than 2 commits | STOP: nothing to squash |
| Reset fails | Restore with `git reset --hard ORIG_HEAD` |
| Push fails | Report warning, keep local squash, provide recovery command |

## Output Format

Report the following:
- Current branch: `{branch_name}`
- Mode: `{since-branch|count|since-commit}`
- Base reference: `{branch_name|commit_sha}`
- Commits to squash: `{count}`
- Commit list: (show `git log --oneline` of commits being squashed)
- Generated message: (show the auto-generated commit message)
- Squash result: `{success|failed}`
- Push result: `{success|failed|skipped}`
- Recovery command: (always show how to undo)

## Safety Guarantees

1. **Protected branches** — Refuses to squash main/master/develop
2. **Clean working directory** — Requires no uncommitted changes
3. **Minimum commits** — Requires at least 2 commits to squash
4. **Recovery info** — Always shows original HEAD SHA and undo command
5. **Safe push** — Uses `--force-with-lease` to prevent overwriting others' work
6. **Atomic operation** — If squash fails, restores original state

## Commit Message Generation Guidelines

When generating the commit message, the agent should:

1. **Analyze the branch name** — Extract feature/fix/refactor context
   - `feature/user-auth` → "feat: User authentication"
   - `fix/login-bug` → "fix: Login bug"
   - `refactor/api-cleanup` → "refactor: API cleanup"

2. **Scan commit messages** — Look for patterns and themes
   - Group related changes
   - Identify the main accomplishment
   - Note any bug fixes included

3. **Keep it concise** — Summary line under 72 characters

4. **Preserve history** — Include original commit messages in body

5. **Follow conventional commits** — Use prefixes like `feat:`, `fix:`, `refactor:`, `docs:`, `test:`

