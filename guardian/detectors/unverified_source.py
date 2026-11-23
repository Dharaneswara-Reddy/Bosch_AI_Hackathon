"""Install scripts in npm packages that did not come from the npm registry.

A package installed from a local path (``file:``/``link``) or a git URL skips the
registry's provenance and malware checks; if it also declares an install script,
it can run arbitrary code at install time. That combination is a classic way to
plant a malicious dependency, so it is flagged as ``unverified_install_script``.
No baseline is needed. Packages whose own ``package.json`` declares
``"guardian": {"synthetic": true}`` are labelled as synthetic test fixtures.
"""

import json
from pathlib import Path
from typing import Any

from guardian.detectors._common import (
    DetectionResult,
    coverage_rows,
    evidence_record,
    finding_payload,
)
from guardian.models import CoverageStatus

DETECTOR = "unverified_source"
REGISTRY_PREFIXES = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")
SYNTHETIC_NOTE = "SYNTHETIC test package for the Guardian demo: inert, never installed or run."


def _source(entry: dict[str, Any]) -> str | None:
    """Non-registry source of an installed package, or None if it came from the registry."""
    if entry.get("link") is True:
        return f"local path {entry.get('resolved', '')}".strip()
    resolved = str(entry.get("resolved", ""))
    if resolved.startswith(("file:", "git+", "git:", "github:")):
        return resolved
    return None


def _is_synthetic(package_dir: Path) -> bool:
    manifest = package_dir / "package.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    marker = data.get("guardian") if isinstance(data, dict) else None
    return isinstance(marker, dict) and marker.get("synthetic") is True


def _suspects(packages: dict[str, Any]) -> list[tuple[str, dict[str, Any], str, str]]:
    """(installed path, package entry, source, entry key holding the install script)."""
    suspects = []
    for key, entry in sorted(packages.items()):
        if not key.startswith("node_modules/") or not isinstance(entry, dict):
            continue
        source = _source(entry)
        target_key = str(entry.get("resolved", "")) if entry.get("link") is True else key
        target = packages.get(target_key, entry)
        if source and isinstance(target, dict) and target.get("hasInstallScript") is True:
            suspects.append((key, target, source, target_key))
    return suspects


def detect_lockfile(lockfile: Path, root: Path) -> DetectionResult:
    content = lockfile.read_bytes()
    data = json.loads(content)
    packages = data.get("packages", {}) if isinstance(data, dict) else {}
    relative = lockfile.relative_to(root).as_posix()
    result = DetectionResult()
    for key, entry, source, script_key in _suspects(packages):
        name = key.rsplit("node_modules/", 1)[-1]
        version = str(entry.get("version", "0.0.0"))
        component = {"purl": f"pkg:npm/{name.replace('@', '%40', 1)}@{version}"}
        record = evidence_record(DETECTOR, relative, f"/packages/{script_key}", content)
        finding, details = finding_payload(
            DETECTOR,
            component,
            "unverified_install_script",
            [record.evidence_id],
            package=name,
            version=version,
            source=source,
            lockfile=relative,
        )
        synthetic = _is_synthetic(lockfile.parent / script_key)
        if synthetic:
            finding.risk_note = SYNTHETIC_NOTE
        result.findings.append(finding)
        result.evidence.append(record)
        result.finding_details[finding.finding_id] = {**details, "synthetic": synthetic}
    return result


def detect(root: Path | None, lockfiles: list[Path]) -> DetectionResult:
    if root is None or not lockfiles:
        reason = "No npm lockfile found" if root is not None else "Target is not a folder"
        return DetectionResult(
            coverage=coverage_rows(DETECTOR, ["npm"], CoverageStatus.NOT_APPLICABLE, reason)
        )
    combined = DetectionResult()
    for lockfile in lockfiles:
        partial = detect_lockfile(lockfile, root)
        combined.findings.extend(partial.findings)
        combined.evidence.extend(partial.evidence)
        combined.finding_details.update(partial.finding_details)
    status = CoverageStatus.FINDING if combined.findings else CoverageStatus.PASS
    combined.coverage = coverage_rows(DETECTOR, ["npm"], status, "", {"npm": len(lockfiles)})
    return combined
