"""Spot direct npm dependencies close to popular package names."""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardian.detectors._common import (
    DetectionResult,
    components_from,
    coverage_rows,
    ecosystem_list,
    ecosystem_of,
    evidence_record,
    finding_payload,
    json_bytes,
    read_value,
)
from guardian.models import UNKNOWN, CoverageRow, CoverageStatus, GraphArtifact

_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_SKIPPED_DIRS = frozenset({".git", "node_modules", "artifacts"})
_MIN_NAME_LENGTH = 6
_MIN_SCOPED_SUFFIX_LENGTH = 8
_DATA_ROOT = Path(__file__).resolve().parents[2] / "data"


def damerau_levenshtein(left: str, right: str) -> int:
    """Return unrestricted Damerau-Levenshtein edit distance."""
    left = left.casefold()
    right = right.casefold()
    rows, columns = len(left), len(right)
    infinity = rows + columns
    matrix = [[0] * (columns + 2) for _ in range(rows + 2)]
    matrix[0][0] = infinity
    for i in range(rows + 1):
        matrix[i + 1][0] = infinity
        matrix[i + 1][1] = i
    for j in range(columns + 1):
        matrix[0][j + 1] = infinity
        matrix[1][j + 1] = j
    last_seen: dict[str, int] = {}
    for i in range(1, rows + 1):
        last_match_column = 0
        for j in range(1, columns + 1):
            previous_row = last_seen.get(right[j - 1], 0)
            previous_column = last_match_column
            substitution_cost = 1
            if left[i - 1] == right[j - 1]:
                substitution_cost = 0
                last_match_column = j
            matrix[i + 1][j + 1] = min(
                matrix[i][j] + substitution_cost,
                matrix[i + 1][j] + 1,
                matrix[i][j + 1] + 1,
                matrix[previous_row][previous_column]
                + (i - previous_row - 1)
                + 1
                + (j - previous_column - 1),
            )
        last_seen[left[i - 1]] = i
    return matrix[rows + 1][columns + 1]


def _load_names(path: Path) -> set[str]:
    return {
        line.strip().casefold()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


@dataclass
class DirectDependency:
    """A direct dependency name with the manifest lines that declare it."""

    name: str
    declarations: list[tuple[str, int]] = field(default_factory=list)
    component: Any = None


def _declaration_line(lines: list[str], section: str, name: str) -> int:
    header = re.compile(rf'^\s*"{section}"\s*:')
    entry = re.compile(rf'^\s*"{re.escape(name)}"\s*:')
    start = next((i for i, line in enumerate(lines) if header.match(line)), None)
    if start is not None:
        for index in range(start + 1, len(lines)):
            if entry.match(lines[index]):
                return index + 1
    return next((i + 1 for i, line in enumerate(lines) if f'"{name}"' in line), 1)


def _manifest_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = sorted(d for d in subdirectories if d not in _SKIPPED_DIRS)
        if "package.json" in filenames:
            found.append(Path(directory) / "package.json")
    return found


def _read_manifest(path: Path, relative: str) -> tuple[bytes, list[tuple[str, str, int]]] | None:
    raw = path.read_bytes()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    lines = raw.decode("utf-8").splitlines()
    declared: list[tuple[str, str, int]] = []
    for section in _SECTIONS:
        entries = data.get(section) if isinstance(data, dict) else None
        if isinstance(entries, dict):
            declared.extend(
                (name, relative, _declaration_line(lines, section, name)) for name in entries
            )
    return raw, declared


def _manifest_dependencies(
    root: Path,
) -> tuple[dict[str, DirectDependency], dict[str, bytes], list[str]]:
    direct: dict[str, DirectDependency] = {}
    contents: dict[str, bytes] = {}
    unparseable: list[str] = []
    for path in _manifest_files(root):
        relative = path.relative_to(root).as_posix()
        parsed = _read_manifest(path, relative)
        if parsed is None:
            unparseable.append(relative)
            continue
        contents[relative], declared = parsed
        for name, file, line in declared:
            direct.setdefault(name, DirectDependency(name)).declarations.append((file, line))
    return direct, contents, unparseable


def _graph_direct(graph: GraphArtifact) -> list[Any]:
    children = {edge.child_id for edge in graph.edges}
    roots = {edge.parent_id for edge in graph.edges} - children
    direct_ids = {edge.child_id for edge in graph.edges if edge.parent_id in roots}
    return [
        node
        for node in graph.nodes
        if node.ecosystem == "npm" and (node.component_id in direct_ids or node.scope == "direct")
    ]


def _max_distance(name: str) -> int:
    if len(name) < _MIN_NAME_LENGTH:
        return 0
    return 1 if len(name) < _MIN_SCOPED_SUFFIX_LENGTH else 2


def _comparisons(name: str) -> list[tuple[str, int]]:
    folded = name.casefold()
    if not (folded.startswith("@") and "/" in folded):
        return [(folded, _max_distance(folded))]
    scope, suffix = folded.split("/", 1)
    limit = _max_distance(suffix)
    if scope == "@types" or len(suffix) < _MIN_SCOPED_SUFFIX_LENGTH:
        return [(folded, limit)]
    return [(folded, limit), (suffix, limit)]


def _nearest(
    candidate: str, limit: int, popular_by_length: dict[int, list[str]]
) -> tuple[int, str] | None:
    best: tuple[int, str] | None = None
    for length in range(len(candidate) - limit, len(candidate) + limit + 1):
        for name in popular_by_length.get(length, []):
            distance = damerau_levenshtein(candidate, name)
            if 0 < distance <= limit and (best is None or (distance, name) < best):
                best = (distance, name)
    return best


def _suspect(name: str, popular_by_length: dict[int, list[str]]) -> tuple[int, str, int] | None:
    best: tuple[int, str, int] | None = None
    for candidate, limit in _comparisons(name):
        match = _nearest(candidate, limit, popular_by_length) if limit else None
        if match and (best is None or match[0] < best[0]):
            best = (match[0], match[1], limit)
    return best


def _npm_purl(name: str) -> str:
    return "pkg:npm/" + name.replace("@", "%40", 1)


def _collect_direct(
    sbom_components: list[Any],
    graph: GraphArtifact | None,
    manifest_direct: dict[str, DirectDependency],
) -> dict[str, DirectDependency]:
    installed: dict[str, Any] = {}
    for item in sbom_components:
        installed.setdefault(str(read_value(item, "name", "")), item)
    direct = dict(manifest_direct)
    for name, entry in direct.items():
        entry.component = installed.get(name)
    extra = [item for item in installed.values() if read_value(item, "scope") == "direct"]
    extra += _graph_direct(graph) if graph is not None else []
    for item in extra:
        name = str(read_value(item, "name", ""))
        entry = direct.setdefault(name, DirectDependency(name))
        entry.component = entry.component or item
    return direct


def _component_for(entry: DirectDependency) -> Any:
    if entry.component is not None:
        return entry.component
    return {
        "name": entry.name,
        "version": UNKNOWN,
        "ecosystem": "npm",
        "purl": _npm_purl(entry.name),
    }


def _coverage(
    ecosystems: list[str], counts: dict[str, int], status: CoverageStatus, reason: str
) -> list[CoverageRow]:
    rows: list[CoverageRow] = []
    for ecosystem in ecosystems:
        if ecosystem == "npm":
            rows.extend(coverage_rows("typosquat", [ecosystem], status, reason, counts))
        else:
            rows.extend(
                coverage_rows(
                    "typosquat",
                    [ecosystem],
                    CoverageStatus.NOT_COVERED,
                    "Only npm names are configured",
                    counts,
                )
            )
    return rows


def _add_finding(
    result: DetectionResult,
    entry: DirectDependency,
    suspect: tuple[int, str, int],
    contents: dict[str, bytes],
    sbom_bytes: bytes,
) -> None:
    distance, nearest, threshold = suspect
    records = [
        evidence_record("typosquat", file, f"lines:{line}-{line}", contents[file])
        for file, line in entry.declarations
    ] or [evidence_record("typosquat", "sbom.cdx.json", f"/components/{entry.name}", sbom_bytes)]
    first = entry.declarations[0] if entry.declarations else (None, None)
    finding, details = finding_payload(
        "typosquat",
        _component_for(entry),
        "suspected_typosquat",
        [record.evidence_id for record in records],
        nearest_popular_name=nearest,
        distance=distance,
        threshold=threshold,
        package_name=entry.name,
        manifest_file=first[0],
        manifest_line=first[1],
    )
    result.evidence.extend(records)
    result.findings.append(finding)
    result.finding_details[finding.finding_id] = details


def _popular_index(popular: set[str]) -> dict[int, list[str]]:
    by_length: dict[int, list[str]] = defaultdict(list)
    for name in sorted(popular):
        by_length[len(name)].append(name)
    return by_length


def detect(
    sbom: Any,
    *,
    target_path: Path | None = None,
    graph: GraphArtifact | None = None,
    popular_path: Path | None = None,
    allowlist_path: Path | None = None,
) -> DetectionResult:
    components = components_from(sbom)
    ecosystems = ecosystem_list(components)
    npm_components = [item for item in components if ecosystem_of(item) == "npm"]
    counts = {e: sum(ecosystem_of(item) == e for item in components) for e in ecosystems}
    popular = _load_names(popular_path or _DATA_ROOT / "popular" / "npm.txt")
    allowlisted = _load_names(allowlist_path or _DATA_ROOT / "allowlist" / "npm.txt")
    by_length = _popular_index(popular)
    manifest_direct: dict[str, DirectDependency] = {}
    contents: dict[str, bytes] = {}
    unparseable: list[str] = []
    if target_path is not None:
        manifest_direct, contents, unparseable = _manifest_dependencies(Path(target_path))
    direct = _collect_direct(npm_components, graph, manifest_direct)
    sbom_bytes = json_bytes(sbom)
    result = DetectionResult()
    for name, entry in sorted(direct.items()):
        names = [candidate for candidate, _ in _comparisons(name)]
        if not name or name.casefold() in popular or any(c in allowlisted for c in names):
            continue
        suspect = _suspect(name, by_length)
        if suspect is not None:
            _add_finding(result, entry, suspect, contents, sbom_bytes)
    result.coverage = _coverage(ecosystems, counts, *_npm_status(result, direct, unparseable))
    return result


def _npm_status(
    result: DetectionResult, direct: dict[str, DirectDependency], unparseable: list[str]
) -> tuple[CoverageStatus, str]:
    reason = f"Unparseable manifests: {', '.join(unparseable)}" if unparseable else ""
    if result.findings:
        return CoverageStatus.FINDING, reason
    if not direct:
        return (
            CoverageStatus.NOT_COVERED,
            reason or "No manifest or graph identifies direct dependencies",
        )
    return CoverageStatus.PASS, reason
