"""Find Dockerfile base images that are not pinned by digest."""

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

_FROM = re.compile(r"^\s*FROM\s+(?:(?:--platform=\S+)\s+)?(?P<image>\S+)", re.IGNORECASE)


def _dockerfiles(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and (path.name == "Dockerfile" or path.name.startswith("Dockerfile."))
    )


def _image_component(image: str) -> dict[str, Any]:
    return {
        "component_id": f"container:{image}",
        "purl": f"pkg:docker/{image}",
        "name": image,
        "version": "UNKNOWN",
        "ecosystem": "docker",
        "scope": "unknown",
    }


def detect(target_path: Path, *, ecosystems: list[str] | None = None) -> DetectionResult:
    root = Path(target_path)
    known_ecosystems = ecosystem_list([], ecosystems)
    findings = []
    evidence = []
    finding_details: dict[str, dict[str, Any]] = {}
    for dockerfile in _dockerfiles(root):
        raw = dockerfile.read_bytes()
        lines = raw.decode("utf-8", errors="replace").splitlines()
        relative = dockerfile.relative_to(root).as_posix()
        for line_number, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#"):
                continue
            match = _FROM.match(line)
            if not match:
                continue
            image = match.group("image")
            if image.casefold() == "scratch" or "@sha256:" in image:
                continue
            pointer = f"lines:{line_number}-{line_number}"
            record = evidence_record("image_pin", relative, pointer, raw)
            evidence.append(record)
            last_part = image.rsplit("/", 1)[-1]
            tag = last_part.partition(":")[2] if ":" in last_part else ""
            finding, details = finding_payload(
                "image_pin",
                _image_component(image),
                "unpinned_base_image",
                [record.evidence_id],
                image=image,
                file=relative,
                line=line_number,
                tag_warning="latest or missing tag" if not tag or tag == "latest" else "",
            )
            findings.append(finding)
            finding_details[finding.finding_id] = details
    counts = {ecosystem: 0 for ecosystem in known_ecosystems}
    status = "finding" if findings else "pass"
    return DetectionResult(
        findings=findings,
        evidence=evidence,
        coverage=coverage_rows("image_pin", known_ecosystems, status, "", counts),
        finding_details=finding_details,
    )
