---
name: add-gitmcp
description: Adds a GitMCP URL for a GitHub repository to the project's MCP configuration (.cursor/mcp.json).
---

# Add GitMCP

You are a helper that adds GitMCP documentation URLs to the **project's** MCP configuration.

## What is GitMCP?

[GitMCP](https://gitmcp.io) is a service that turns any public GitHub repository into an MCP-compatible documentation server. It works on-the-fly — no registration needed. URLs are deterministic.

**URL Format:**
```
https://gitmcp.io/{owner}/{repo}
```

## Input Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `repo` | Yes | GitHub repo URL, `owner/repo` format, or just repo name |

**Accepted input formats:**
- Full URL: `https://github.com/owner/repo`
- Full URL with .git: `https://github.com/owner/repo.git`
- SSH URL: `git@github.com:owner/repo.git`
- Short format: `owner/repo`
- Just repo name: `repo` (will search or ask for owner)

**Example invocations:**
- "add gitmcp for https://github.com/libbpf/libbpf"
- "add gitmcp libbpf/libbpf"
- "add gitmcp SigmaHQ/sigma"

## Workflow (Fast Path)

**IMPORTANT: Do NOT make network calls to validate repos. GitMCP URLs are deterministic and work for any public repo. Skip validation to avoid timeouts.**

### Step 1: Parse Repository Input

Extract owner and repo name from the input. This is string parsing only — no network calls.

**If user provides `owner/repo`:** Use directly.
**If user provides just `repo`:** 
- Check the Quick Reference table below for known repos
- If not found, ask user for the owner

### Step 2: Construct GitMCP URL

```
GITMCP_URL = "https://gitmcp.io/{owner}/{repo}"
```

### Step 3: Add to Project MCP Configuration

**Always use project-level config:** `.cursor/mcp.json`

**Never use user-level config** (`~/.cursor/mcp.json`)

Read the existing `.cursor/mcp.json` (if exists), add the new entry:

```json
{
  "mcpServers": {
    "{repo}-docs": {
      "url": "https://gitmcp.io/{owner}/{repo}"
    }
  }
}
```

**If file exists:** Merge the new server into existing `mcpServers`
**If file doesn't exist:** Create it with proper structure

### Step 4: Report Result

```
✅ GitMCP Added
Repository: {owner}/{repo}
GitMCP URL: https://gitmcp.io/{owner}/{repo}
Config: .cursor/mcp.json
Server name: {repo}-docs

Restart Cursor to load the new MCP server.
```

## Server Naming Convention

- Pattern: `{repo}-docs`
- Examples: `vulnhuntr-docs`, `libbpf-docs`, `sigma-docs`
- If name exists, use `{owner}-{repo}-docs`

## Quick Reference: Known Repos

Use this table to quickly resolve repo names without network lookups:

| Repo Name | Owner | Full Path |
|-----------|-------|-----------|
| vulnhuntr | protectai | protectai/vulnhuntr |
| sigma | SigmaHQ | SigmaHQ/sigma |
| pySigma | SigmaHQ | SigmaHQ/pySigma |
| libbpf | libbpf | libbpf/libbpf |
| bcc | iovisor | iovisor/bcc |
| bpftool | libbpf | libbpf/bpftool |
| cilium | cilium | cilium/cilium |
| falco | falcosecurity | falcosecurity/falco |
| ebpf | cilium | cilium/ebpf |
| tracee | aquasecurity | aquasecurity/tracee |

## Error Handling

| Scenario | Action |
|----------|--------|
| Cannot parse input | Ask user for `owner/repo` format |
| Unknown repo name | Ask user for the owner |
| Config file malformed | Report JSON error, don't modify |
| Server name exists | Use `{owner}-{repo}-docs` instead |

## Notes

1. **No validation needed** — GitMCP URLs work for any public repo without verification
2. **Project-level only** — Always use `.cursor/mcp.json`, never user-level
3. **Fast execution** — No network calls during skill execution
4. **Restart required** — User must restart Cursor after adding

