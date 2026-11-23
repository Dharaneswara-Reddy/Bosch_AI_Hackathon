"""Find GitHub Actions references not pinned to a full commit SHA."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from guardian.detectors._common import (
    DetectionResult,
    coverage_rows,
    ecosystem_list,
    evidence_record,
    finding_payload,
)

_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<value>[^\s#]+)", re.IGNORECASE)
_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


def _workflows(root: Path) -> list[Path]:
    directory = root / ".github" / "workflows"
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.rglob("*")
        if path.is_file() and path.suffix.casefold() in {".yml", ".yaml"}
    )


def _action_component(action: str) -> dict[str, Any]:
    return {
        "component_id": f"github-action:{action}",
        "purl": f"pkg:githubaction/{action.replace('@', '%40')}",
        "name": action,
        "version": "UNKNOWN",
        "ecosystem": "github-actions",
        "scope": "unknown",
    }


def detect(target_path: Path, *, ecosystems: list[str] | None = None) -> DetectionResult:
    root = Path(target_path)
    known_ecosystems = ecosystem_list([], ecosystems)
    findings = []
    evidence = []
    finding_details: dict[str, dict[str, Any]] = {}
    for workflow in _workflows(root):
        raw = workflow.read_bytes()
        relative = workflow.relative_to(root).as_posix()
        lines = raw.decode("utf-8", errors="replace").splitlines()
        for line_number, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#"):
                continue
            match = _USES.match(line)
            if not match:
                continue
            action = match.group("value").strip("'\"")
            if action.startswith("./"):
                continue
            ref = action.rsplit("@", 1)[1] if "@" in action else ""
            if _FULL_SHA.fullmatch(ref):
                continue
            record = evidence_record("ci_pin", relative, f"lines:{line_number}-{line_number}", raw)
            evidence.append(record)
            finding, details = finding_payload(
                "ci_pin",
                _action_component(action),
                "unpinned_ci_action",
                [record.evidence_id],
                action=action,
                file=relative,
                line=line_number,
            )
            findings.append(finding)
            finding_details[finding.finding_id] = details
    counts = {ecosystem: 0 for ecosystem in known_ecosystems}
    return DetectionResult(
        findings=findings,
        evidence=evidence,
        coverage=coverage_rows(
            "ci_pin", known_ecosystems, "finding" if findings else "pass", "", counts
        ),
        finding_details=finding_details,
    )
