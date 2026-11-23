"""Spot direct npm dependencies close to popular package names."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from guardian.detectors._common import (
    DetectionResult,
    components_from,
    coverage_rows,
    ecosystem_of,
    ecosystem_list,
    evidence_record,
    finding_payload,
    json_sha256,
    read_value,
)

THRESHOLD = 2
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


def _comparison_name(name: str) -> str:
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[1]
    return name


def detect(
    sbom: Any,
    *,
    popular_path: Path | None = None,
    allowlist_path: Path | None = None,
) -> DetectionResult:
    components = components_from(sbom)
    ecosystems = ecosystem_list(components)
    npm_components = [item for item in components if ecosystem_of(item) == "npm"]
    counts = {ecosystem: sum(ecosystem_of(item) == ecosystem for item in components) for ecosystem in ecosystems}
    popular_file = popular_path or _DATA_ROOT / "popular" / "npm.txt"
    allowlist_file = allowlist_path or _DATA_ROOT / "allowlist" / "npm.txt"
    popular = _load_names(popular_file)
    allowlisted = _load_names(allowlist_file)
    findings: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for index, component in enumerate(npm_components):
        if read_value(component, "scope") != "direct":
            continue
        name = str(read_value(component, "name", ""))
        normalized = name.casefold()
        candidate = _comparison_name(name).casefold()
        if not name or normalized in allowlisted or candidate in allowlisted or candidate in popular:
            continue
        choices = sorted((damerau_levenshtein(candidate, popular_name), popular_name) for popular_name in popular)
        if not choices:
            continue
        distance, nearest = choices[0]
        if distance == 0 or distance > THRESHOLD:
            continue
        component_digest = json_sha256(component).encode("ascii")
        record = evidence_record(
            "typosquat",
            "sbom.cdx.json",
            f"/components/{index}",
            component_digest,
            component_purl=read_value(component, "purl", "UNKNOWN"),
        )
        evidence.append(record)
        findings.append(
            finding_payload(
                "typosquat",
                component,
                "suspected_typosquat",
                [record["evidence_id"]],
                nearest_popular_name=nearest,
                distance=distance,
                threshold=THRESHOLD,
                package_name=name,
            )
        )
    result: list[dict[str, Any]] = []
    for ecosystem in ecosystems:
        status = "finding" if ecosystem == "npm" and findings else ("pass" if ecosystem == "npm" else "not_covered")
        result.extend(coverage_rows("typosquat", [ecosystem], status, "" if ecosystem == "npm" else "Only npm names are configured", counts))
    return DetectionResult(findings=findings, evidence=evidence, coverage=result)
