---
layout: default
title: Event Flow
parent: Architecture
nav_order: 3
---

# Event Flow

This page explains how events flow from kernel hooks to userspace output.

---

## Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                               KERNEL                                      │
│                                                                           │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌───────────┐  │
│  │ Inline Hook │───▶│ Fill Event  │───▶│ Match Rules │───▶│   Ring    │  │
│  │  Triggered  │    │   Struct    │    │             │    │  Buffer   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └───────────┘  │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                               USERSPACE                                    │
│                                                                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │Raw C to ptr │───▶│    Sync     │───▶│  Output to  │───▶│    Async    │ │
│  │ C++ Struct  │    │  Enrichers  │    │   stdout    │    │  Enrichers  │ │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘ │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Kernel Stage

When an eBPF inline hook is triggered:

1. **Allocate from ring buffer** — Space is reserved in the event ring buffer
2. **Fill event struct** — Process info, target info, and event-specific data are populated
3. **Match against rules** — The event is evaluated against rules for this event type
4. **Send to userspace** — The event (with match result) is submitted to the ring buffer

All of this happens synchronously within the hook, before the syscall returns.

---

## Userspace Stage

The userspace component processes events with a focus on speed — get events to stdout as fast as possible, defer heavy work for later.

### 1. Raw C to Modern C++ Struct

Events arrive as raw C-style pointers from the ring buffer. They are immediately converted to modern C++ `Event` structs for safe handling.

### 2. Sync Enrichers

Before output, events pass through **synchronous enrichers**. These perform lightweight, essential enrichment that must happen before the event is displayed:

- Assigning matched rule metadata
- Basic field formatting

### 3. Output to stdout

The enriched event is serialized and sent to stdout. At this point, the event is visible to consumers.

### 4. Async Enrichers

After output, events are handed to **asynchronous enrichers** for deferred processing. This is where heavier work happens without blocking event output:

- Future: Adding uprobes based on event patterns
- Future: Tracking user/group creation and management
- Future: Correlation with external data sources

---