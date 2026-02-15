#!/usr/bin/env python3
"""
Creates installation directory structure for owlsm or unit_tests.

Usage:
    scripts/package.py owlsm
    scripts/package.py unit_tests
"""

import subprocess
import shutil
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

# System libraries to exclude (always present on target systems)
EXCLUDE_LIBS = ["linux-vdso", "ld-linux", "libc.so", "libm.so", "libdl.so", "librt.so", "libpthread.so"]

# Fallback search paths for libraries that ldd reports as "not found"
LIBRARY_SEARCH_PATHS = ["/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib", "/lib/x86_64-linux-gnu", "/lib64", "/lib"]

RULES_GENERATOR_SRC = PROJECT_ROOT / "Rules" / "RulesGenerator"
RULES_GENERATOR_FILES = [
    "AST.py",
    "base_config.json",
    "constants.py",
    "create_config.py",
    "main.py",
    "postfix.py",
    "requirements.txt",
    "serializer.py",
    "sigma_rule_loader.py",
]

MODES = {
    "owlsm": {
        "binary": PROJECT_ROOT / "src" / "Userspace" / "owlsm",
        "output": PROJECT_ROOT / "build" / "owlsm",
        "with_rules_generator": True,
        "with_resources": True,
    },
    "unit_tests": {
        "binary": PROJECT_ROOT / "src" / "Tests" / "unit_test" / "unit_tests",
        "output": PROJECT_ROOT / "build" / "unit_tests",
        "with_rules_generator": False,
        "with_resources": False,
    },
}


def find_library(soname):
    """Search common paths for a library that ldd couldn't resolve."""
    for search_dir in LIBRARY_SEARCH_PATHS:
        candidate = Path(search_dir) / soname
        if candidate.is_file():
            return candidate
    return None


def get_shared_libs(binary_path):
    """Use ldd to discover required shared libraries, excluding system libs."""
    result = subprocess.run(["ldd", str(binary_path)], capture_output=True, text=True, check=True)
    libs = []
    for line in result.stdout.splitlines():
        if "=>" not in line:
            continue
        if any(excluded in line for excluded in EXCLUDE_LIBS):
            continue
        parts = line.split()
        soname = parts[0].strip()

        if "not found" in line:
            # ldd couldn't resolve this library - search common paths
            found = find_library(soname)
            if found:
                libs.append(found)
            else:
                print(f"  ERROR: {soname} not found in any search path")
                sys.exit(1)
        elif len(parts) >= 3:
            lib_path = Path(parts[2])
            if lib_path.is_file():
                libs.append(lib_path)
    return libs


def package(mode_name):
    """Create installation directory structure based on the given mode."""
    mode = MODES[mode_name]
    binary_path = mode["binary"]
    output_dir = mode["output"]

    if not binary_path.is_file():
        print(f"Error: Binary not found: {binary_path}")
        sys.exit(1)

    print(f"==> Packaging {binary_path.name} into {output_dir}")

    # Recreate directory structure (handle both file and directory from previous builds)
    if output_dir.exists():
        if output_dir.is_dir():
            shutil.rmtree(output_dir)
        else:
            output_dir.unlink()

    bin_dir = output_dir / "bin"
    lib_dir = output_dir / "lib"
    bin_dir.mkdir(parents=True)
    lib_dir.mkdir(parents=True)

    # Copy binary
    shutil.copy2(binary_path, bin_dir / binary_path.name)

    # Copy shared libraries (resolve symlinks, keep SONAME filename)
    print("==> Copying shared libraries...")
    for lib in get_shared_libs(binary_path):
        print(f"  Copying: {lib}")
        shutil.copy2(lib.resolve(), lib_dir / lib.name)

    # Create empty resources directory
    if mode["with_resources"]:
        (output_dir / "resources").mkdir()
        print("==> Created empty resources directory")

    # Copy RulesGenerator source files only (no tests, no repo-level files)
    if mode["with_rules_generator"]:
        rules_dest = output_dir / "rules_generator"
        rules_dest.mkdir()
        print("==> Copying RulesGenerator source files...")
        for filename in RULES_GENERATOR_FILES:
            src = RULES_GENERATOR_SRC / filename
            if src.is_file():
                shutil.copy2(src, rules_dest / filename)
                print(f"  Copying: {filename}")
            else:
                print(f"  Warning: {filename} not found in {RULES_GENERATOR_SRC}")

    print(f"==> Packaging complete: {output_dir}")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        print(f"Usage: {sys.argv[0]} <{'|'.join(MODES.keys())}>")
        sys.exit(1)

    package(sys.argv[1])


if __name__ == "__main__":
    main()
