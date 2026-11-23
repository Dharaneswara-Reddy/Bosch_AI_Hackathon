"""Static reachability: does the application's own code import a package?

A deliberately simple, explainable check: search the target's source files (not
``node_modules``, ``vendor`` or tests) for ``require('x')``, ``import ... from 'x'``,
``import 'x'``, Ruby ``require 'x'`` and Python ``import x`` / ``from x import``.
A hit is proof of use; no hit is "not detected", never proof of safety. When no
source files exist (for example when only manifests were fetched) the answer is
"unknown".
"""

import os
import re
from pathlib import Path

from pydantic import BaseModel, Field

SOURCE_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".rb", ".py"})
SKIPPED_DIRS = frozenset(
    {
        "node_modules",
        "vendor",
        ".git",
        "dist",
        "build",
        "coverage",
        "test",
        "tests",
        "__tests__",
        "spec",
        ".venv",
        "venv",
    }
)
MAX_FILES = 5_000
MAX_FILE_BYTES = 1_000_000


class ImportHit(BaseModel):
    package: str
    file: str
    line: int
    text: str


class ReachabilityScan(BaseModel):
    source_files: int = 0
    hits: dict[str, list[ImportHit]] = Field(default_factory=dict)

    @property
    def source_available(self) -> bool:
        return self.source_files > 0


def _patterns(name: str) -> re.Pattern[str]:
    quoted = rf"""['"]{re.escape(name)}(?:/[^'"]*)?['"]"""
    python = re.escape(name.replace("-", "_"))
    return re.compile(
        rf"require\s*\(\s*{quoted}\s*\)|\bfrom\s+{quoted}|\bimport\s+{quoted}"
        rf"|\bimport\s*\(\s*{quoted}\s*\)|^\s*require(?:_relative)?\s+{quoted}"
        rf"|^\s*(?:import|from)\s+{python}\b",
        re.MULTILINE,
    )


def source_files(target: Path) -> list[Path]:
    found: list[Path] = []
    for directory, folders, files in os.walk(target):
        folders[:] = sorted(name for name in folders if name not in SKIPPED_DIRS)
        for name in sorted(files):
            path = Path(directory) / name
            if path.suffix in SOURCE_SUFFIXES and path.stat().st_size <= MAX_FILE_BYTES:
                found.append(path)
                if len(found) >= MAX_FILES:
                    return found
    return found


def _hits(path: Path, relative: str, patterns: dict[str, re.Pattern[str]]) -> list[ImportHit]:
    text = path.read_text(encoding="utf-8", errors="replace")
    hits: list[ImportHit] = []
    for package, pattern in patterns.items():
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            snippet = text.splitlines()[line - 1].strip()[:200]
            hits.append(ImportHit(package=package, file=relative, line=line, text=snippet))
    return hits


def scan_imports(target: Path, packages: set[str]) -> ReachabilityScan:
    """Find where the application imports any of ``packages``."""
    files = source_files(target)
    patterns = {name: _patterns(name) for name in sorted(packages) if name}
    result = ReachabilityScan(source_files=len(files))
    for path in files:
        for hit in _hits(path, path.relative_to(target).as_posix(), patterns):
            result.hits.setdefault(hit.package, []).append(hit)
    return result
