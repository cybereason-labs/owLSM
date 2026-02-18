import logging
import os
import re
import sqlite3
import subprocess
import tarfile
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)


@dataclass
class PoolSource:
    debug_pool_url: str
    package_format: str             # "deb" or "rpm"
    filename_pattern: str           # glob-style, e.g. "dash-dbgsym_*"
    architectures: list[str] = field(default_factory=lambda: ["amd64", "i386", "arm64", "armhf"])


@dataclass
class PackageInfo:
    filename: str
    url: str
    version: str
    arch: str


class ShellScraper(ABC):
    """Base class implementing the Template Method for scraping shell debug packages."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._init_db()

    # ── Abstract methods (subclass must implement) ──

    @abstractmethod
    def shell_name(self) -> str:
        """Return the shell name, e.g. 'dash'."""

    @abstractmethod
    def target_functions(self) -> list[str]:
        """Return the list of function names whose offsets we need."""

    @abstractmethod
    def pool_sources(self) -> list[PoolSource]:
        """Return the list of PoolSource entries to crawl."""

    # ── Template method ──

    def run(self, dry_run: bool = False):
        """Orchestrate the full scrape: crawl -> download -> extract -> store."""
        all_packages = []
        for source in self.pool_sources():
            packages = self._crawl_pool(source)
            all_packages.extend(packages)

        logger.info("Found %d debug packages total for %s", len(all_packages), self.shell_name())

        if dry_run:
            for pkg in all_packages:
                logger.info("  [dry-run] %s (version=%s, arch=%s)", pkg.filename, pkg.version, pkg.arch)
            return

        processed = 0
        skipped = 0
        errors = 0

        for pkg in all_packages:
            try:
                with tempfile.TemporaryDirectory() as tmp_dir:
                    pkg_path = self._download_package(pkg, tmp_dir)
                    debug_elf_path = self._extract_debug_elf(pkg_path, pkg, tmp_dir)

                    if debug_elf_path is None:
                        logger.warning("No .debug ELF found in %s, skipping", pkg.filename)
                        errors += 1
                        continue

                    build_id = self._read_build_id(debug_elf_path)
                    if build_id is None:
                        logger.warning("No build ID found in %s, skipping", pkg.filename)
                        errors += 1
                        continue

                    if self._build_id_exists(build_id):
                        logger.debug("Build ID %s already in DB, skipping %s", build_id, pkg.filename)
                        skipped += 1
                        continue

                    offsets = self._read_offsets(debug_elf_path, self.target_functions())
                    if offsets is None:
                        logger.warning("Could not read all offsets from %s, skipping", pkg.filename)
                        errors += 1
                        continue

                    self._store(build_id, offsets, pkg)
                    processed += 1
                    logger.info(
                        "Stored %s: build_id=%s offsets=%s",
                        pkg.filename,
                        build_id,
                        {name: f"0x{off:x}" for name, off in offsets.items()},
                    )

            except Exception:
                logger.exception("Error processing %s", pkg.filename)
                errors += 1

        self._conn.commit()
        logger.info(
            "Done. processed=%d, skipped=%d, errors=%d", processed, skipped, errors
        )

    def close(self):
        self._conn.close()

    # ── DB setup ──

    def _init_db(self):
        cur = self._conn.cursor()

        offsets_exists = cur.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='offsets'"
        ).fetchone() is not None

        metadata_exists = cur.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'"
        ).fetchone() is not None

        if offsets_exists:
            logger.info("Table 'offsets' already exists — dropping and recreating")
            cur.execute("DROP TABLE offsets")

        if metadata_exists:
            logger.info("Table 'metadata' already exists — dropping and recreating")
            cur.execute("DROP TABLE metadata")

        cur.execute(
            """
            CREATE TABLE offsets (
                build_id    TEXT NOT NULL,
                func_name   TEXT NOT NULL,
                offset      INTEGER NOT NULL,
                PRIMARY KEY (build_id, func_name)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE metadata (
                build_id    TEXT NOT NULL PRIMARY KEY,
                shell       TEXT,
                arch        TEXT,
                version     TEXT,
                source_url  TEXT,
                scraped_at  TEXT
            )
            """
        )
        self._conn.commit()

    def _build_id_exists(self, build_id: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM metadata WHERE build_id = ?", (build_id,)
        )
        return cur.fetchone() is not None

    def _store(self, build_id: str, offsets: dict[str, int], pkg: PackageInfo):
        cur = self._conn.cursor()
        for func_name, offset in offsets.items():
            cur.execute(
                "INSERT OR IGNORE INTO offsets (build_id, func_name, offset) VALUES (?, ?, ?)",
                (build_id, func_name, offset),
            )
        cur.execute(
            "INSERT OR IGNORE INTO metadata (build_id, shell, arch, version, source_url, scraped_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                build_id,
                self.shell_name(),
                pkg.arch,
                pkg.version,
                pkg.url,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    # ── Pool crawling ──

    def _crawl_pool(self, source: PoolSource) -> list[PackageInfo]:
        """Fetch the HTML directory listing and extract matching package links."""
        logger.info("Crawling %s", source.debug_pool_url)

        resp = requests.get(source.debug_pool_url, timeout=30)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")
        packages = []

        for link in soup.find_all("a", href=True):
            href = link["href"]
            if not self._matches_package(href, source):
                continue

            version, arch = self._parse_filename(href, source.package_format)
            if version is None:
                continue

            if arch not in source.architectures:
                continue

            full_url = source.debug_pool_url.rstrip("/") + "/" + href
            packages.append(PackageInfo(filename=href, url=full_url, version=version, arch=arch))

        logger.info("  Found %d matching packages from %s", len(packages), source.debug_pool_url)
        return packages

    def _matches_package(self, filename: str, source: PoolSource) -> bool:
        """Check if a filename matches the pattern and is a valid package file."""
        extension_ok = False
        if source.package_format == "deb":
            extension_ok = filename.endswith(".deb") or filename.endswith(".ddeb")
        elif source.package_format == "rpm":
            extension_ok = filename.endswith(".rpm")

        if not extension_ok:
            return False

        # Strip extension for glob matching
        name_without_ext = filename
        for ext in (".ddeb", ".deb", ".rpm"):
            if name_without_ext.endswith(ext):
                name_without_ext = name_without_ext[: -len(ext)]
                break

        return fnmatch(name_without_ext, source.filename_pattern)

    @staticmethod
    def _parse_filename(filename: str, package_format: str) -> tuple[str | None, str | None]:
        """Extract version and architecture from a package filename.

        Debian: dash-dbgsym_0.5.12-6ubuntu5_amd64.ddeb
        RPM:    dash-debuginfo-0.5.12-1.fc39.x86_64.rpm
        """
        if package_format == "deb":
            match = re.match(r".+_(.+)_(.+)\.d?deb$", filename)
            if match:
                return match.group(1), match.group(2)
        elif package_format == "rpm":
            match = re.match(r".+-(.+)\.(\w+)\.rpm$", filename)
            if match:
                return match.group(1), match.group(2)
        return None, None

    # ── Package download ──

    def _download_package(self, pkg: PackageInfo, dest_dir: str) -> str:
        """Download a package file to dest_dir, return the local path."""
        local_path = os.path.join(dest_dir, pkg.filename)
        logger.debug("Downloading %s", pkg.url)

        resp = requests.get(pkg.url, timeout=120, stream=True)
        resp.raise_for_status()

        with open(local_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)

        return local_path

    # ── Package extraction ──

    def _extract_debug_elf(self, pkg_path: str, pkg: PackageInfo, dest_dir: str) -> str | None:
        """Extract the .debug ELF from a package. Returns its path or None."""
        source = self._find_pool_source_for_pkg(pkg)
        if source is None:
            return None

        if source.package_format == "deb":
            return self._extract_deb(pkg_path, dest_dir)
        elif source.package_format == "rpm":
            return self._extract_rpm(pkg_path, dest_dir)

        logger.error("Unsupported package format: %s", source.package_format)
        return None

    def _find_pool_source_for_pkg(self, pkg: PackageInfo) -> PoolSource | None:
        for source in self.pool_sources():
            if pkg.url.startswith(source.debug_pool_url.rstrip("/")):
                return source
        return None

    def _extract_deb(self, deb_path: str, dest_dir: str) -> str | None:
        """Extract .debug ELF from a .deb/.ddeb package."""
        ar_dir = os.path.join(dest_dir, "ar_extract")
        os.makedirs(ar_dir, exist_ok=True)

        subprocess.run(["ar", "x", deb_path], cwd=ar_dir, check=True, capture_output=True)

        data_tar = None
        for name in ["data.tar.xz", "data.tar.gz", "data.tar.zst", "data.tar.bz2"]:
            candidate = os.path.join(ar_dir, name)
            if os.path.exists(candidate):
                data_tar = candidate
                break

        if data_tar is None:
            logger.warning("No data.tar.* found in %s", deb_path)
            return None

        # For zst, decompress first since tarfile doesn't support it natively
        if data_tar.endswith(".zst"):
            decompressed = data_tar.replace(".zst", "")
            subprocess.run(
                ["zstd", "-d", data_tar, "-o", decompressed],
                check=True, capture_output=True,
            )
            data_tar = decompressed

        data_dir = os.path.join(dest_dir, "data_extract")
        os.makedirs(data_dir, exist_ok=True)

        with tarfile.open(data_tar) as tar:
            tar.extractall(path=data_dir)

        return self._find_debug_elf(data_dir)

    def _extract_rpm(self, rpm_path: str, dest_dir: str) -> str | None:
        """Extract .debug ELF from an .rpm package."""
        extract_dir = os.path.join(dest_dir, "rpm_extract")
        os.makedirs(extract_dir, exist_ok=True)

        result = subprocess.run(
            f"rpm2cpio '{rpm_path}' | cpio -idm",
            shell=True, cwd=extract_dir, check=True, capture_output=True,
        )
        if result.returncode != 0:
            logger.warning("rpm2cpio/cpio failed for %s", rpm_path)
            return None

        return self._find_debug_elf(extract_dir)

    @staticmethod
    def _find_debug_elf(root_dir: str) -> str | None:
        """Walk extracted directory tree to find a .debug ELF file."""
        for dirpath, _, filenames in os.walk(root_dir):
            for name in filenames:
                if name.endswith(".debug"):
                    return os.path.join(dirpath, name)
        return None

    # ── ELF reading ──

    @staticmethod
    def _read_build_id(elf_path: str) -> str | None:
        """Read the NT_GNU_BUILD_ID from an ELF file."""
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            section = elf.get_section_by_name(".note.gnu.build-id")
            if section is None:
                return None
            for note in section.iter_notes():
                if note["n_type"] == "NT_GNU_BUILD_ID":
                    return note["n_desc"]
        return None

    @staticmethod
    def _read_offsets(elf_path: str, function_names: list[str]) -> dict[str, int] | None:
        """Read function offsets from the .symtab section.

        For each requested function, first tries an exact name match. If not
        found, falls back to searching for GCC optimization-mangled variants
        (e.g., setprompt.lto_priv.0, func.part.0, func.isra.0). If multiple
        mangled variants exist, uses the first one and logs a warning.

        Returns a dict {func_name: offset} if ALL requested functions are found,
        or None if any are missing.
        """
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                logger.warning("No .symtab in %s", elf_path)
                return None

            # Build a lookup of all function symbols
            all_funcs = {}
            for sym in symtab.iter_symbols():
                if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"] > 0:
                    all_funcs[sym.name] = sym["st_value"]

        offsets = {}
        for target in function_names:
            if target in all_funcs:
                offsets[target] = all_funcs[target]
                continue

            # Fallback: search for GCC-mangled variants (name starts with "target.")
            mangled = [(name, addr) for name, addr in all_funcs.items()
                       if name.startswith(target + ".")]

            if len(mangled) == 1:
                name, addr = mangled[0]
                logger.info("Using mangled symbol '%s' for '%s' in %s", name, target, elf_path)
                offsets[target] = addr
            elif len(mangled) > 1:
                mangled.sort(key=lambda x: x[0])
                name, addr = mangled[0]
                logger.warning(
                    "Multiple mangled symbols for '%s' in %s: %s. Using '%s'",
                    target, elf_path, [n for n, _ in mangled], name,
                )
                offsets[target] = addr

        missing = set(function_names) - set(offsets.keys())
        if missing:
            logger.warning("Missing functions in %s: %s", elf_path, missing)
            return None

        return offsets
