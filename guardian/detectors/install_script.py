"""Detect new or changed npm lockfile entries with install scripts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from guardian.detectors._common import (
    DetectionResult,
    coverage_rows,
    evidence_record,
    finding_payload,
)
from guardian.models import UNKNOWN, CoverageStatus


def _read_lockfile(value: Path | dict[str, Any] | None) -> tuple[dict[str, Any] | None, bytes]:
    if value is None:
        return None, b""
    if isinstance(value, Path):
        content = value.read_bytes()
        loaded = json.loads(content.decode("utf-8"))
        return loaded if isinstance(loaded, dict) else None, content
    content = json.dumps(value, sort_keys=True).encode("utf-8")
    return value, content


def _entries(lockfile: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not lockfile:
        return {}
    packages = lockfile.get("packages")
    if isinstance(packages, dict):
        return {
            str(path): value for path, value in packages.items() if isinstance(value, dict) and path
        }
    # npm lockfile v1 stores entries recursively under ``dependencies``.
    found: dict[str, dict[str, Any]] = {}

    def walk(dependencies: Any, prefix: str = "") -> None:
        if not isinstance(dependencies, dict):
            return
        for name, value in dependencies.items():
            if not isinstance(value, dict):
                continue
            key = f"{prefix}{name}"
            found[key] = value
            walk(value.get("dependencies"), f"{key}/node_modules/")

    walk(lockfile.get("dependencies"))
    return found


def _entry_name(entry_path: str) -> str:
    marker = "node_modules/"
    if marker in entry_path:
        name = entry_path.rsplit(marker, 1)[1]
    else:
        name = entry_path
    return name


def _component(entry_path: str, entry: dict[str, Any]) -> dict[str, Any]:
    name = _entry_name(entry_path)
    version = str(entry.get("version", UNKNOWN))
    purl_name = quote(name, safe="/")
    return {
        "component_id": f"pkg:npm/{purl_name}@{version}",
        "name": name,
        "version": version,
        "ecosystem": "npm",
        "purl": f"pkg:npm/{purl_name}@{version}",
        "scope": "unknown",
    }


def detect(
    lockfile: Path | dict[str, Any] | None,
    *,
    baseline_lockfile: Path | dict[str, Any] | None,
    ecosystems: list[str],
) -> DetectionResult:
    normalized = sorted(set(ecosystems)) or ["any"]
    counts = {ecosystem: 0 for ecosystem in normalized}
    if "npm" not in normalized:
        return DetectionResult(
            coverage=coverage_rows(
                "install_script",
                normalized,
                CoverageStatus.NOT_COVERED,
                "Install scripts are checked for npm only",
                counts,
            )
        )
    current_data, current_bytes = _read_lockfile(lockfile)
    baseline_data, _ = _read_lockfile(baseline_lockfile)
    if current_data is None or baseline_data is None:
        return DetectionResult(
            coverage=coverage_rows(
                "install_script",
                normalized,
                CoverageStatus.NOT_APPLICABLE,
                "Current or baseline npm lockfile is unavailable",
                counts,
            )
        )
    current_entries = _entries(current_data)
    baseline_entries = _entries(baseline_data)
    findings = []
    evidence = []
    finding_details: dict[str, dict[str, Any]] = {}
    for entry_path, entry in sorted(current_entries.items()):
        if entry.get("hasInstallScript") is not True:
            continue
        previous = baseline_entries.get(entry_path)
        unchanged = (
            previous is not None
            and previous.get("hasInstallScript") is True
            and previous.get("version") == entry.get("version")
        )
        if unchanged:
            continue
        component = _component(entry_path, entry)
        record = evidence_record(
            "install_script",
            lockfile.name if isinstance(lockfile, Path) else "package-lock.json",
            f"/packages/{entry_path}",
            current_bytes,
        )
        evidence.append(record)
        finding, details = finding_payload(
            "install_script",
            component,
            "install_script_change",
            [record.evidence_id],
            package_name=component["name"],
            version=component["version"],
            lockfile_entry=entry_path,
            baseline_version=(previous or {}).get("version", UNKNOWN),
        )
        findings.append(finding)
        finding_details[finding.finding_id] = details
    counts["npm"] = len(current_entries)
    coverage = [
        row
        for ecosystem in normalized
        for row in coverage_rows(
            "install_script",
            [ecosystem],
            (CoverageStatus.FINDING if findings else CoverageStatus.PASS)
            if ecosystem == "npm"
            else CoverageStatus.NOT_COVERED,
            "" if ecosystem == "npm" else "Install scripts are checked for npm only",
            counts,
        )
    ]
    return DetectionResult(
        findings=findings,
        evidence=evidence,
        coverage=coverage,
        finding_details=finding_details,
    )
