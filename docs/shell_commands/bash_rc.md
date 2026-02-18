# RC File Approach for cmd_map Population

## The Technique
Add shell-specific hooks to rc files that write to BPF map via userspace helper.
The helper (`owlsm_cmd_helper`) is a small binary that:
1. Gets current PID, inode, dev, start_time
2. Writes to `cmd_map` BPF map using libbpf

## Shell Hook Support

| Shell | Hook Mechanism | Supported |
|-------|----------------|-----------|
| Bash | `trap DEBUG` | ✅ |
| Zsh | `preexec()` function | ✅ |
| Fish | `fish_preexec` event | ✅ |
| Ksh | `trap DEBUG` | ✅ |
| **Dash** | **NONE** | ❌ |

**Dash is POSIX-only with no hook mechanism. Cannot be monitored via rc files.**

## RC Files Per Shell

| Shell | File | Scope |
|-------|------|-------|
| Bash | `/etc/bash.bashrc` | Interactive non-login |
| Bash | `/etc/profile.d/*.sh` | Login shells |
| Zsh | `/etc/zsh/zshenv` | **ALL zsh invocations** (best) |
| Zsh | `/etc/zsh/zshrc` | Interactive only |
| Fish | `/etc/fish/config.fish` | Interactive fish |
| Ksh | `/etc/ksh.kshrc` | Interactive (if ENV set) |
| Dash | X | X |
| All | `/etc/profile` | Login shells (POSIX) |


## Bash Loading Behavior

| Shell Type | `/etc/bash.bashrc` | `/etc/profile` |
|------------|-------------------|----------------|
| Interactive login (`bash -l`) | ❌ | ✅ |
| Interactive non-login (`bash`) | ✅ | ❌ |
| Non-interactive (`bash -c`) | ❌ | ❌ |
| Scripts (`#!/bin/bash`) | ❌ | ❌ |

**Use BOTH `/etc/bash.bashrc` AND `/etc/profile.d/` for best coverage.**

## Critical Issues

### Easily Bypassed
```bash
bash --norc --noprofile    # Skips all rc files
zsh -f                     # Skips zshrc
fish --no-config           # Skips config
env -i bash                # Clean environment
trap '' DEBUG              # User disables trap in session
```

### User Can Modify
- Users can edit `~/.bashrc` and override/remove trap
- Users can `unset preexec` in zsh
- Only `/etc/` files are protected by root

### Dash can't be hooked with files 

## eBPF LSM Defenses

### Block `--norc` / `--noprofile` / `-f`
```c
// In bprm_check_security: deny bypass flags
if (is_shell(binary) && has_norc_flag(argv))
    return -EPERM;
```

### Protect RC Files from Modification
```c
// In file_permission: deny writes to system rc files
if (is_protected_rc_file(inode) && (mask & MAY_WRITE))
    return -EPERM;

// Protected files: /etc/bash.bashrc, /etc/profile, /etc/profile.d/*,
// /etc/zsh/zshenv, /etc/fish/config.fish, /etc/environment
```


## Coverage Summary

| Method | Bash | Zsh | Fish | Ksh | Dash |
|--------|------|-----|------|-----|------|
| RC file hooks | ✅ | ✅ | ✅ | ✅ | ❌ |
| Uprobes | ✅ | ✅ | ✅ | ✅ | ✅ |

## Deployment Checklist
1. `/etc/profile.d/owlsm.sh` → Bash login
2. `/etc/bash.bashrc` → Bash interactive
3. `BASH_ENV` in `/etc/environment` → Bash non-interactive
4. `/etc/zsh/zshenv` → All zsh
5. `/etc/fish/config.fish` → Fish interactive
6. Protect all above with LSM `file_permission` hook
7. Block `--norc`/`-f` flags with LSM `bprm_check_security`

## Recommendation
**Uprobes = primary** (kernel-enforced, covers all shells including dash)
**RC files = defense-in-depth** (covers 4/5 shells, provides full pipeline via $BASH_COMMAND)
Both write to same `cmd_map` for unified LSM enrichment.
