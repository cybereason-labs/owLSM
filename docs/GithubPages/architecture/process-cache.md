---
layout: default
title: Process Cache
parent: Architecture
nav_order: 2
---

# Process Cache

This page explains how owLSM process caches work and what are their rules.

---

## Cache Architecture

owLSM maintains two separate process caches:

| Cache | Type | Key | Purpose |
|-------|------|-----|---------|
| **alive_processes** | BPF Hash Map | `pid` | Currently running processes |
| **dead_processes** | BPF LRU Map | `unique_process_id` | Recently terminated processes |

The alive cache uses PID as the key because inline hooks guarantee we see process lifecycle events in order. The dead cache uses a unique process ID (not just PID) because PIDs can be reused after a process exits.

---

## Cache Reliability Rules

To maintain cache consistency, strict access rules are enforced:

### 1. Encapsulated Access

The process caches can **only** be accessed through functions in `process_cache.bpf.h`. Direct map access from other files is prohibited.

### 2. Deep Copy Returns

The process cache API **never** returns a raw pointer to a cached process. Instead, it returns a pointer to a deep copy. This:
- Prevents concurrent modification issues.
- Passes verifier in many cases.
- Prevents undefined states of process objects.

### 3. Inline Hooks Only

Cache modifications are **only** allowed in inline hooks (LSM, fentry, uprobes, etc'). Async hooks (raw_tracepoint, etc.) cannot modify the cache.

This restriction is critical — it allows us to use PID alone as the cache key. Because inline hooks execute synchronously with syscalls:
- FORK hook runs before the child can execute anything
- EXIT hook runs before the PID can be reused
- No race conditions between PID reuse and cache updates

---

## Cache Population

Processes are added to the alive cache in three scenarios:

### 1. Fork Hook

When a new process is created, the **child process** is added to the cache during the fork hook.
### 2. Exec Hook

When a process calls exec, the **current process** entry is updated.

### 3. First Encounter in Any Inline Hook

When an inline hook encounters a process that isn't in the cache, it means this process existed **before owLSM started**. This is the first time we're seeing it.<br>
In this case, the hook populates the cache entry on-demand by reading the process information from kernel structures.

---

## Cache Removal

Processes are removed from the alive cache **only** in the `on_exit` hook (process exit).

When a process exits:
1. The entry is removed from `alive_processes`
2. The entry is moved into `dead_processes` (LRU)

The dead cache serves two purposes:
- **Late event handling**: Some events may reference a terminated process
- **Parent lookups**: A child process may need to reference its terminated parent

The LRU automatically evicts old entries when the dead cache reaches capacity.
