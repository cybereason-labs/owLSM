---
layout: default
title: Event Caching
parent: Architecture
nav_order: 4
---

# Event Caching

This page explains how owLSM caches high-frequency events to avoid redundant processing.

---

## The Problem

Certain syscalls generate many repeated events with identical security context. For example:

- **File download**: A large file download triggers hundreds of `write` syscalls to the same file, from the same process, with the same permissions
- **Log reading**: A monitoring tool reading logs triggers repeated `read` syscalls with identical context

Re-evaluating rules and sending events for each of these calls is wasteful — the security decision will be the same every time.

---

## The Solution

For high-frequency events like `READ` and `WRITE`, owLSM uses a hash-based cache to skip redundant processing.

```
                    Event Occurs
                          │
                          ▼
                ┌──────────────────┐
                │ Calculate Hash   │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Hash in Cache?   │
                └────────┬─────────┘
                         │
            ┌────────────┴────────────┐
           YES                        NO
            │                         │
            ▼                         ▼
   ┌─────────────────┐      ┌─────────────────┐
   │ Return Cached   │      │ Full Evaluation │
   │ ALLOW/BLOCK     │      │ + Send Event    │
   └─────────────────┘      └────────┬────────┘
                                     │
     No event sent                   ▼
     No rule eval          ┌─────────────────┐
                           │  Cache Result   │
                           └─────────────────┘
```

---

## How It Works

### 1. Event Hash Calculation

When a cacheable event occurs, a hash is calculated from the event relevant fields:

- Action performer attributes (Process attributes)
- Operation target attributes (Target file, network connection, etc')

### 2. Cache Lookup

The hash is checked against a dedicated **LRU cache** (per event type).
