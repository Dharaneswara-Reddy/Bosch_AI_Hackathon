"""Static reachability: does the application's own code import a package?

A deliberately simple, explainable check: search the target's source files (not
``node_modules``, ``vendor`` or tests) for ``require('x')``, ``import ... from 'x'``,
``import 'x'``, Ruby ``require 'x'`` and Python ``import x`` / ``from x import``.
A hit is proof of use; no hit is "not detected", never proof of safety. When no
source files exist (for example when only manifests were fetched) the answer is
"unknown".
"""

import json
import os
import re
from collections import deque
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, Field

from guardian.models import ReachabilityEvidence

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


MAX_CHAIN_DEPTH = int(os.environ.get("GUARDIAN_REACHABILITY_MAX_DEPTH", "8"))
MAX_CHAIN_FILES = int(os.environ.get("GUARDIAN_REACHABILITY_MAX_FILES", "20000"))
JS_IMPORT = re.compile(r"(?:require\s*\(\s*|from\s*|import\s*\(\s*|import\s*)['\"]([^'\"]+)['\"]")
BUILTINS = frozenset(
    {
        "assert",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "constants",
        "crypto",
        "dgram",
        "diagnostics_channel",
        "dns",
        "domain",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "inspector",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "repl",
        "stream",
        "string_decoder",
        "sys",
        "timers",
        "tls",
        "trace_events",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
    }
)
JS_SUFFIXES = frozenset({".js", ".cjs", ".mjs", ".jsx", ".ts", ".json"})


def _package_name(specifier: str) -> str | None:
    if specifier.startswith((".", "/", "#")) or ":" in specifier:
        return None
    parts = specifier.split("/")
    name = "/".join(parts[:2]) if parts[0].startswith("@") and len(parts) > 1 else parts[0]
    return None if name in BUILTINS or name.startswith("node:") else name


def _package_dir(root: Path, importer: Path, name: str) -> Path | None:
    for parent in (importer.parent, *importer.parents):
        candidate = parent / "node_modules" / name
        if candidate.is_dir():
            return candidate
        if parent == root:
            break
    candidate = root / "node_modules" / name
    return candidate if candidate.is_dir() else None


def _entry(directory: Path) -> Path | None:
    manifest = directory / "package.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}

    def export_paths(value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [path for nested in value.values() for path in export_paths(nested)]
        if isinstance(value, list):
            return [path for nested in value for path in export_paths(nested)]
        return []

    choices = export_paths(data.get("exports"))
    choices += [str(data.get("main", "index.js")), "index.js", "index.mjs", "index.cjs"]
    for choice in choices:
        candidate = (directory / choice).resolve()
        if candidate.is_relative_to(directory.resolve()):
            if candidate.is_file():
                return candidate
            for suffix in JS_SUFFIXES:
                if candidate.is_dir() and (candidate / f"index{suffix}").is_file():
                    return candidate / f"index{suffix}"
            for suffix in JS_SUFFIXES:
                if candidate.with_suffix(suffix).is_file():
                    return candidate.with_suffix(suffix)
    return None


def static_dependency_chains(
    root: Path, vulnerable: dict[str, set[str]]
) -> list[ReachabilityEvidence]:
    """Bounded BFS from app imports through installed npm package entrypoints."""
    queue: deque[tuple[Path, list[str], int, Path, int]] = deque()
    direct_scan = scan_imports(root, _installed_package_names(root))
    for name, hits in direct_scan.hits.items():
        for hit in hits:
            if len(queue) >= MAX_CHAIN_FILES:
                break
            app_file = root / hit.file
            queue.append((app_file, [name], 1, app_file, hit.line))
    found: dict[tuple[str, str], ReachabilityEvidence] = {}
    seen: set[Path] = set()
    while queue and len(seen) < MAX_CHAIN_FILES:
        importer, chain, depth, origin, origin_line = queue.popleft()
        name = chain[-1]
        package_dir = _package_dir(root, importer, name)
        if package_dir is None:
            continue
        entry = _entry(package_dir)
        if entry is None or entry in seen:
            continue
        seen.add(entry)
        try:
            package = json.loads((package_dir / "package.json").read_text(encoding="utf-8"))
            version = str(package.get("version", "UNKNOWN"))
        except (OSError, ValueError):
            version = "UNKNOWN"
        expected_versions = vulnerable.get(name, set())
        if name in vulnerable and (version in expected_versions or "UNKNOWN" in expected_versions):
            found[(name, version)] = ReachabilityEvidence(
                package=name,
                version=version,
                source="static_chain",
                chain=chain,
                file=f"{origin.relative_to(root).as_posix()}:{origin_line}",
            )
        if depth >= MAX_CHAIN_DEPTH:
            continue
        try:
            text = entry.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        for match in JS_IMPORT.finditer(text):
            child = _package_name(match.group(1))
            if child and child not in chain and len(queue) + len(seen) < MAX_CHAIN_FILES:
                line = text.count("\n", 0, match.start()) + 1
                queue.append((entry, [*chain, child], depth + 1, entry, line))
    return list(found.values())


def _installed_package_names(root: Path) -> set[str]:
    modules = root / "node_modules"
    if not modules.is_dir():
        return set()
    names: set[str] = set()
    for child in sorted(modules.iterdir()):
        if child.name.startswith("@"):
            names.update(
                name
                for package in sorted(child.iterdir())
                if package.is_dir()
                if (name := _package_name(f"{child.name}/{package.name}")) is not None
            )
        elif child.is_dir():
            name = _package_name(child.name)
            if name:
                names.add(name)
        if len(names) >= MAX_CHAIN_FILES:
            break
    return names


def parse_runtime_trace(
    path: Path, root: Path, observed_during: list[str]
) -> list[ReachabilityEvidence]:
    """Convert hook output paths into package identities, including scoped/nested packages."""
    found: dict[tuple[str, str], ReachabilityEvidence] = {}
    if not path.is_file():
        return []
    if path.stat().st_size > 10 * 1024 * 1024:
        return []

    def source_path(value: str) -> Path:
        container_path = PurePosixPath(value)
        if container_path.is_absolute() and container_path.parts[:2] == ("/", "work"):
            return root.joinpath(*container_path.parts[2:])
        return Path(value)

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:MAX_CHAIN_FILES]:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        resolved = source_path(str(event.get("resolved_path", "")))
        try:
            relative = resolved.resolve().relative_to(root.resolve())
        except (OSError, ValueError):
            continue
        parts = relative.parts
        for index, part in enumerate(parts):
            if part != "node_modules" or index + 1 >= len(parts):
                continue
            name_parts = [parts[index + 1]]
            if name_parts[0].startswith("@") and index + 2 < len(parts):
                name_parts.append(parts[index + 2])
            name = "/".join(name_parts)
            parent_name = None
            try:
                parent_relative = (
                    source_path(str(event.get("parent_path", "")))
                    .resolve()
                    .relative_to(root.resolve())
                )
                parent_parts = parent_relative.parts
                for parent_index, parent_part in enumerate(parent_parts):
                    if parent_part == "node_modules" and parent_index + 1 < len(parent_parts):
                        parent_name = parent_parts[parent_index + 1]
                        if parent_name.startswith("@") and parent_index + 2 < len(parent_parts):
                            parent_name += "/" + parent_parts[parent_index + 2]
            except (OSError, ValueError):
                pass
            manifest = root.joinpath(*parts[: index + 1], *name_parts, "package.json")
            try:
                version = str(
                    json.loads(manifest.read_text(encoding="utf-8")).get("version", "UNKNOWN")
                )
            except (OSError, ValueError):
                version = "UNKNOWN"
            key = (name, version)
            chain = [parent_name, name] if parent_name and parent_name != name else [name]
            found.setdefault(
                key,
                ReachabilityEvidence(
                    package=name,
                    version=version,
                    source="runtime",
                    chain=chain,
                    file=relative.as_posix(),
                    observed_during=observed_during,
                ),
            )
    return list(found.values())
