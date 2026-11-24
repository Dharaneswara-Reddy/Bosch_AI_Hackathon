"""Detect npm lockfile entries whose integrity or source changed without a version change."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from guardian.detectors._common import (
    DetectionResult,
    coverage_rows,
    evidence_record,
    finding_payload,
)
from guardian.detectors.install_script import _component, _entries, _read_lockfile
from guardian.models import UNKNOWN, CoverageRow, CoverageStatus, Finding

DETECTOR = "lockfile_integrity"


def _host(entry: dict[str, Any]) -> str | None:
    resolved = entry.get("resolved")
    return urlparse(resolved).hostname if isinstance(resolved, str) else None


def _is_registry_entry(entry: dict[str, Any]) -> bool:
    resolved = entry.get("resolved")
    return (
        entry.get("link") is not True
        and isinstance(resolved, str)
        and resolved.startswith(("http://", "https://"))
    )


def _anomalies(entry: dict[str, Any], previous: dict[str, Any] | None) -> list[str]:
    found = []
    if _is_registry_entry(entry) and not entry.get("integrity"):
        found.append("missing_integrity")
    if previous is None or previous.get("version") != entry.get("version"):
        return found
    old, new = previous.get("integrity"), entry.get("integrity")
    if old and new and old != new:
        found.append("integrity_change")
    if _host(previous) and _host(entry) and _host(previous) != _host(entry):
        found.append("resolved_source_change")
    return found


def _unavailable(
    ecosystems: list[str], current_data: dict[str, Any] | None, counts: dict[str, int]
) -> DetectionResult | None:
    if "npm" in ecosystems and current_data is not None:
        return None
    reason = (
        "Lockfile integrity is checked for npm only"
        if "npm" not in ecosystems
        else "No npm lockfile available"
    )
    status = (
        CoverageStatus.NOT_COVERED if "npm" not in ecosystems else CoverageStatus.NOT_APPLICABLE
    )
    return DetectionResult(coverage=coverage_rows(DETECTOR, ecosystems, status, reason, counts))


def _anomaly_finding(
    anomaly: str,
    entry_path: str,
    entry: dict[str, Any],
    previous: dict[str, Any] | None,
    evidence_id: str,
) -> tuple[Finding, dict[str, Any]]:
    component = _component(entry_path, entry)
    return finding_payload(
        DETECTOR,
        component,
        anomaly,
        [evidence_id],
        package_name=component["name"],
        version=component["version"],
        lockfile_entry=entry_path,
        baseline_integrity=(previous or {}).get("integrity", UNKNOWN),
        current_integrity=entry.get("integrity", UNKNOWN),
        baseline_host=_host(previous or {}) or UNKNOWN,
        current_host=_host(entry) or UNKNOWN,
    )


def _coverage(
    ecosystems: list[str], status: CoverageStatus, counts: dict[str, int]
) -> list[CoverageRow]:
    return [
        row
        for ecosystem in ecosystems
        for row in coverage_rows(
            DETECTOR,
            [ecosystem],
            status if ecosystem == "npm" else CoverageStatus.NOT_COVERED,
            "" if ecosystem == "npm" else "Lockfile integrity is checked for npm only",
            counts,
        )
    ]


def detect(
    lockfile: Path | dict[str, Any] | None,
    *,
    baseline_lockfile: Path | dict[str, Any] | None,
    ecosystems: list[str],
) -> DetectionResult:
    normalized = sorted(set(ecosystems)) or ["any"]
    counts = {ecosystem: 0 for ecosystem in normalized}
    current_data, current_bytes = _read_lockfile(lockfile)
    skipped = _unavailable(normalized, current_data, counts)
    if skipped is not None:
        return skipped
    baseline_entries = _entries(_read_lockfile(baseline_lockfile)[0])
    entries = _entries(current_data)
    result = DetectionResult()
    for entry_path, entry in sorted(entries.items()):
        previous = baseline_entries.get(entry_path)
        for anomaly in _anomalies(entry, previous):
            record = evidence_record(
                DETECTOR,
                lockfile.name if isinstance(lockfile, Path) else "package-lock.json",
                f"/packages/{entry_path}",
                current_bytes,
            )
            finding, details = _anomaly_finding(
                anomaly, entry_path, entry, previous, record.evidence_id
            )
            result.evidence.append(record)
            result.findings.append(finding)
            result.finding_details[finding.finding_id] = details
    counts["npm"] = len(entries)
    status = CoverageStatus.FINDING if result.findings else CoverageStatus.PASS
    result.coverage = _coverage(normalized, status, counts)
    return result
