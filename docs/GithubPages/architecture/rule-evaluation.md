---
layout: default
title: Rule Creation and Evaluation
parent: Architecture
nav_order: 1
---

# Rule Creation and Evaluation

This page explains how owLSM rules flow from human-readable YAML files to kernel-space evaluation.

## Overview

The rule lifecycle consists of three stages:

```
┌─────────────────┐       ┌─────────────────┐      ┌─────────────────┐
│   YAML Rules    │       │   JSON Config   │      │   BPF Maps      │
│   (Sigma-like)  │ ───▶ |   (Serialized)  │ ───▶ │   (Kernel)      │
└─────────────────┘       └─────────────────┘      └─────────────────┘
```

1. **Rules Generator** (Python) — Compiles YAML rules to JSON
2. **Userspace** (C++) — Loads JSON and populates BPF maps
3. **Kernel** (eBPF) — Evaluates rules against runtime events

---

## Stage 1: Rules Generator (YAML → JSON)

The Rules Generator (`Rules/RulesGenerator/`) converts Sigma-like YAML rules into a serialized JSON format.

### Processing Pipeline

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Rules Generator Pipeline                         │
├──────────────────────────────────────────────────────────────────────────┤
│   ┌─────────┐     ┌──────────┐      ┌─────────┐      ┌───────────┐       │
│   │  YAML   │───▶ │ Validate │───▶ │  Parse  │───▶ │ Convert to │      |
│   │  Files  │     │  Schema  │      │   AST   │      │ Postfix   │       │
│   └─────────┘     └──────────┘      └─────────┘      └───────────┘       │
│                                       │              │                   │
│                                       ▼              ▼                   │
│                              ┌────────────────────────────┐              │
│                              │      Output Tables         │              │
│                              │  • id_to_string            │              │
│                              │  • id_to_ip                │              │
│                              │  • id_to_predicate         │              │
│                              │  • rules[]                 │              │
│                              └────────────────────────────┘              │
└──────────────────────────────────────────────────────────────────────────┘
```

### Step 1: Validation

Each YAML file is validated against the owLSM rule schema. Part of the things that are checked:<br>
Required fields, Optional fields, Selection Field, field values, modifiers, etc.


### Step 2: AST Parsing

Using pySigma, the detection logic is walked as an Abstract Syntax Tree (AST). During this traversal, three tables are built:

#### id_to_string Table
Every string value in the rule is assigned a unique ID and stored:

```
id_to_string = {
    0: { value: "/etc/passwd", is_contains: false },
    1: { value: ".ssh",        is_contains: true  },
    2: { value: "curl",        is_contains: false }
}
```

The `is_contains` flag marks strings that use the `contains` modifier — these require special handling with the KMP algorithm later.

#### id_to_ip Table
IP addresses and CIDR ranges are stored separately:

```
id_to_ip = {
    0: { ip: "10.0.0.0", cidr: 8,  ip_type: "ipv4" },
    1: { ip: "2001:db8::", cidr: 32, ip_type: "ipv6" }
}
```

#### id_to_predicate Table
Each comparison in the rule becomes a **predicate**:

```
id_to_predicate = {
    0: { field: "TARGET_FILE_PATH", comparison_type: "CONTAINS",    string_idx: 1 },
    1: { field: "PROCESS_FILENAME", comparison_type: "EXACT_MATCH", string_idx: 2 },
    2: { field: "NETWORK_DST_PORT", comparison_type: "EQUAL",       numerical_value: 443 }
}
```

A predicate has three main members:

| Member | Description |
|--------|-------------|
| `field` | The event field to compare (e.g., `TARGET_FILE_PATH`, `PROCESS_EUID`) |
| `comparison_type` | How to compare: `EXACT_MATCH`, `CONTAINS`, `STARTS_WITH`, `GT`, `CIDR`, etc. |
| `string_idx` / `numerical_value` | For strings/IPs: index into lookup table. For numbers: the actual value |

### Step 3: Postfix Conversion

Each rule's detection logic is converted to **postfix notation** (Reverse Polish Notation) for efficient stack-based evaluation.

#### Why Postfix?

Postfix eliminates the need for parentheses and operator precedence rules. It can be evaluated with a simple stack machine, which is ideal for the constrained eBPF environment.

#### Token Structure

Each element in the postfix array is a **token**:

| Member | Description |
|--------|-------------|
| `operator_type` | One of: `PREDICATE`, `AND`, `OR`, `NOT` |
| `predicate_idx` | Index into `id_to_predicate` (only set when `operator_type` is `PREDICATE`) |

#### Visual Example

```
Rule: target.file.path|contains: ".ssh" AND process.file.filename: "curl"

                    AND
                   /   \
              PRED(0)  PRED(1)
              
Postfix tokens: [ PRED(0), PRED(1), AND ]

Where:
  PRED(0) → id_to_predicate[0] → { field: TARGET_FILE_PATH, contains, string_idx: 1 }
  PRED(1) → id_to_predicate[1] → { field: PROCESS_FILENAME, exact,    string_idx: 2 }
```
 <br>
### Keyword Expansion

Keywords are field-less searches that match against all string fields for an event type.

```yaml
keywords:
    - "malware"
```

This expands to multiple predicates — one for each string field the event type has:

```
For WRITE event:
  keywords: "malware"
  
Expands to:
  target.file.path|contains: "malware" OR
  target.file.filename|contains: "malware" OR
  process.cmd|contains: "malware" OR
  process.file.path|contains: "malware" OR
  ...
```

**Important**: When a rule uses keywords AND specifies multiple event types, the rule is **split** into separate rules (one per event type). This is because different event types have different string fields.<br>
All the rules have the same id, but may have different string fields, thus different tokens.

### Final JSON Schema

After processing all rules, the generator outputs:

```json
{
    "id_to_string": {
        "0": { "value": "/etc/passwd", "is_contains": false },
        ...
    },
    "id_to_ip": {
        "0": { "ip": 8.8.8.0, "cidr": 8 },
        ...
    },
    "id_to_predicate": {
        "0": { "field": TARGET_FILE_PATH, "comparison_type": startswith, "string_idx": 1, "numerical_value": -1 },
        "1": { "field": PROCESS_UID, "comparison_type": EQUAL, "string_idx": -1, "numerical_value": 1000 },
        ...
    },
    "rules": [
        {
            "id": 1,
            "description": "Block curl from reading SSH keys",
            "action": "BLOCK_EVENT",
            "applied_events": ["READ"],
            "min_version": "1.0.0",
            "max_version": "2.0.0",
            "tokens": [
                { "operator_type": PREDICATE, "predicate_idx": 0 },
                { "operator_type": PREDICATE, "predicate_idx": 1 },
                { "operator_type": AND }
            ]
        }, 
        ...
    ]
}
```

This JSON is embedded into the `config.json` file passed to owLSM at runtime.

---

## Stage 2: Userspace (JSON → BPF Maps)

The userspace component (`src/Userspace/`) parses the config and populates kernel BPF maps.

### BPF Maps for Rule Evaluation

| Map | Description |
|-----|-------------|
| `{event}_rules_map` | Per-event-type rule arrays. CHMOD events only check `chmod_rules_map`, and EXEC events only check `exec_rules_map` |
| `predicates_map` | Kernel representation of `id_to_predicate` |
| `rules_strings_map` | kernel representation of id_to_string. However, Strings are structs with char arrays, length and DFA index |
| `rules_ips_map` | kernel representation of id_to_ip |
| `idx_to_DFA_map` | Pre-computed KMP DFA for `contains` strings |
| `predicates_results_cache` | Caches predicate results within an event evaluation |

### KMP DFA Computation

For strings with the `contains` modifier, userspace pre-computes a KMP (Knuth-Morris-Pratt algorithm) DFA (Deterministic Finite Automaton algorithm).<br>
This DFA is stored in `idx_to_DFA_map` and referenced by entries in `rules_strings_map`.
KMP DFA enables O(n) substring matching in the kernel. However, consumes a lot of memory.<br>

### Rule Organization by Event Type

Userspace organizes rules into per-event-type maps:

```cpp
// A rule with applied_events: [CHMOD, READ, WRITE]
// is inserted into all three maps:
chmod_rules_map  → rule
read_rules_map   → rule  
write_rules_map  → rule
```

This ensures that when a CHMOD event occurs, only CHMOD-relevant rules are evaluated.

---

## Stage 3: Kernel Evaluation (BPF Maps → Decision)

When an event occurs, the eBPF program evaluates rules using the populated maps.

### Evaluation Flow

```
─────────────────────────────────────────────────────────────────────────
                        Kernel Rule Evaluation                            
─────────────────────────────────────────────────────────────────────────
Event Occurs (e.g., READ syscall)                    
       │                                             
       ▼                                             
┌─────────────────────────────────────┐              
│  1. Populate event_t struct         │              
│     - process info                  │              
│     - target file info              │              
│     - event-specific data           │              
└──────────────────┬──────────────────┘              
                   ▼                                 
┌─────────────────────────────────────┐              
│  2. Iterate read_rules_map          │              
│     using bpf_for_each_map_elem     │              
└──────────────────┬──────────────────┘              
                   ▼                                 
┌─────────────────────────────────────┐              
│  3. For each rule:                  │              
│     - Push tokens to stack          │              
│     - Evaluate postfix expression   │              
│     - If match → return action      │              
└──────────────────┬──────────────────┘              
                   ▼                                 
┌─────────────────────────────────────┐              
│  4. Apply action                    │              
│     - ALLOW_EVENT                   │              
│     - BLOCK_EVENT                   │              
│     - BLOCK_KILL_PROCESS            │              
│     - etc.                          │              
└─────────────────────────────────────┘              
```

## Postfix Stack Evaluation

The kernel uses a 2 stacks-based algorithm to evaluate postfix expressions.

### Predicate Evaluation

When evaluating a predicate token:

1. **Lookup predicate** from `predicates_map[token.predicate_idx]`

2. **Check cache** — If this predicate was already evaluated for this event, return cached result from `predicates_results_cache`.<br>
Its very likely that different rules (or even the same rule) will have identical predicates. For example, many rules will have:
`target.file.path: "/etc/hosts"`. So using the cache we don't evaluate this predicate twice for the same event.

3. **Compare field** — Use the predicate's field and comparison_type to compare against the event:
   - String fields: exact match, contains (via KMP DFA), starts_with, ends_with
   - Numeric fields: equal, greater than, less than, etc.
   - IP fields: CIDR matching

4. **Cache result** — Store in `predicates_results_cache` for potential reuse

### First Match Wins

Rules are evaluated in order of their `id` (lowest first). **Evaluation stops at the first matching rule**:

```
Rules (sorted by id):
  1: Block SSH key access
  5: Allow all reads from /usr
  10: Block all reads

If rule 1 matches → BLOCK_EVENT, rules 5 and 10 are NOT evaluated
```

This differs from traditional SIEM systems that process all rules. The first-match approach is more efficient. Crucial for inline syscall evaluation.

---

## Summary

The design optimizes for kernel performance:
- **Postfix notation** enables simple stack evaluation
- **Lookup tables** minimize data duplication
- **Per-event-type maps** reduce unnecessary rule checks
- **Predicate caching** avoids redundant evaluations
- **Pre-computed DFAs** enable O(n) string matching
