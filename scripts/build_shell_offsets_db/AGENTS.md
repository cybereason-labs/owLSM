# AGENTS.md - Build Offsets DB

## Overview

A Python scraper that builds an offline SQLite database of function offsets for
stripped shell binaries. owLSM uses this DB at runtime to attach eBPF uprobes
by build ID, without requiring symbols on the target machine.

Currently only **dash** is supported, scraping debug packages from:
- **Debian** (`deb.debian.org/debian-debug`)
- **Ubuntu** (`ddebs.ubuntu.com`) — also covers Linux Mint

Only non-end-of-life versions of dash are available in these pools.

## Project Structure

```
build_shell_offsets_db/
├── AGENTS.md           # This file
├── main.py             # CLI entry point
├── shell_scraper.py    # Base class (Template Method pattern)
├── dash_scraper.py     # Dash subclass (config only, no logic)
└── requirements.txt    # Python dependencies (requests, beautifulsoup4, pyelftools)
```

## Architecture

Uses the **Template Method** pattern. `ShellScraper` (base class) implements
all generic logic: crawl pool URLs, download debug packages, extract ELFs,
read build IDs and offsets, write to SQLite. Subclasses only provide:
- `shell_name()` — e.g. `"dash"`
- `target_functions()` — e.g. `["setprompt", "list"]`
- `pool_sources()` — list of pool URLs and package format info

To add a new shell, create a new subclass. To add a new distro, add a
`PoolSource` entry to the relevant subclass.

---

## DB Table: `offsets`

- **Table name**: `offsets`
- **Schema**: `(build_id TEXT, func_name TEXT, offset INTEGER, PRIMARY KEY (build_id, func_name))`
- **Purpose**: Maps an ELF build ID + function name to its virtual address offset

There is also a `metadata` table for auditing (shell, arch, version, source URL).
### Where the DB is saved

The scraper writes into an **existing** SQLite DB file passed via `--db`.
At runtime, owLSM reads this DB from `<install_dir>/resources/owlsm.db`
(defined by `RESOURCES_DIR_NAME` and `DB_FILE_NAME` in `global_strings.hpp`).

The userspace code uses SQLite `ATTACH DATABASE` to query the `offsets` table
from this resource DB.

---

## Usage

```bash
pip install -r requirements.txt
python main.py --db /path/to/owlsm.db [--dry-run] [--verbose]
```

| Flag        | Description                                      |
|-------------|--------------------------------------------------|
| `--db`      | Path to an existing SQLite DB file (required)    |
| `--dry-run` | Crawl and list packages without downloading      |
| `--verbose` | Enable debug-level logging                       |

The scraper always runs all registered shell scrapers (currently only dash).

---

## Extending

- **New shell**: Create a `ShellScraper` subclass, implement the three abstract
  methods, add it to `main.py`'s `ALL_SCRAPERS` list.
- **New distro**: Add a `PoolSource` entry to the relevant subclass.
- **New package format**: Add an extraction method to `ShellScraper`.
  Currently supported: `deb`, `rpm`.
