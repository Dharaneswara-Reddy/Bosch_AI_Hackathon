"""Shared output helpers using the P5-owned Pydantic data contract."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from guardian.models import UNKNOWN, CoverageRow, Evidence, Finding, finding_id

JsonObject = dict[str, Any]


@dataclass
class DetectionResult:
    """Findings, evidence drafts and coverage emitted by one detector."""

    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    coverage: list[CoverageRow] = field(default_factory=list)
    finding_details: dict[str, JsonObject] = field(default_factory=dict)
    artifacts: dict[str, bytes] = field(default_factory=dict)

    @property
    def coverage_rows(self) -> list[CoverageRow]:
        """Expose the coverage name expected by the shared runner."""
        return self.coverage


class DetectorContext(Protocol):
    """Structural view of the shared runner context required by plugins."""

    target_path: Path | None
    sbom: Path
    baseline: Path | None
    out: Path
    result: Any
    evidence: Any


def read_value(value: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a Pydantic-like object or a mapping."""
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def components_from(sbom: Any) -> list[Any]:
    components = read_value(sbom, "components", [])
    return list(components) if isinstance(components, (list, tuple)) else []


def ecosystem_of(component: Any) -> str:
    ecosystem = read_value(component, "ecosystem")
    if isinstance(ecosystem, str) and ecosystem:
        return ecosystem
    purl = read_value(component, "purl", "")
    if isinstance(purl, str) and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].split("@", 1)[0]
    return UNKNOWN


def purl_of(component: Any) -> str:
    purl = read_value(component, "purl") or read_value(component, "bom-ref")
    if isinstance(purl, str) and purl:
        return purl
    name = str(read_value(component, "name", UNKNOWN))
    version = str(read_value(component, "version", UNKNOWN))
    ecosystem = ecosystem_of(component)
    return f"pkg:{ecosystem}/{name}@{version}"


def package_identity(component: Any) -> tuple[str, str]:
    ecosystem = ecosystem_of(component)
    name = read_value(component, "name")
    if not isinstance(name, str) or not name:
        purl = purl_of(component).split("?", 1)[0]
        body = purl[4:] if purl.startswith("pkg:") else purl
        path = body.split("/", 1)
        ecosystem = path[0] if path else ecosystem
        name_and_version = path[1] if len(path) > 1 else UNKNOWN
        name = name_and_version.rsplit("@", 1)[0]
    return ecosystem, name.casefold()


def ecosystem_list(components: Iterable[Any], supplied: Iterable[str] | None = None) -> list[str]:
    found = {ecosystem_of(component) for component in components}
    found.discard(UNKNOWN)
    if supplied is not None:
        found.update(item for item in supplied if item and item != UNKNOWN)
    return sorted(found) or ["any"]


def coverage_rows(
    detector: str,
    ecosystems: Iterable[str],
    status: str,
    reason: str = "",
    components_seen: dict[str, int] | None = None,
) -> list[CoverageRow]:
    counts = components_seen or {}
    return [
        CoverageRow(
            detector=detector,
            ecosystem=ecosystem,
            status=status,
            reason=reason,
            components_seen=counts.get(ecosystem, 0),
        )
        for ecosystem in ecosystems
    ]


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def evidence_record(
    detector: str,
    file: str,
    pointer: str,
    content: bytes,
) -> Evidence:
    evidence_id = hashlib.sha256(
        f"{detector}\0{file}\0{pointer}\0{sha256_bytes(content)}".encode()
    ).hexdigest()[:24]
    return Evidence(
        evidence_id=evidence_id,
        tool=f"guardian:{detector}",
        tool_version="1",
        file=file,
        pointer=pointer,
        sha256=sha256_bytes(content),
        collected_at=datetime.now(UTC),
    )


def finding_payload(
    detector: str,
    component: Any,
    anomaly_type: str,
    evidence_ids: Iterable[str],
    **details: Any,
) -> tuple[Finding, JsonObject]:
    purl = purl_of(component) if component is not None else UNKNOWN
    component_id = read_value(component, "component_id") or read_value(component, "bom-ref") or purl
    finding = Finding(
        finding_id=finding_id(detector, purl, anomaly_type, []),
        kind="anomaly",
        component_id=str(component_id),
        purl=purl,
        advisory_id=None,
        aliases=[],
        anomaly_type=anomaly_type,
        confirmed_by=[],
        source_severity=UNKNOWN,
        fixed_versions=[],
        match_basis="purl",
        dependency_path=[],
        path_count=None,
        evidence_ids=list(evidence_ids),
        state="under_investigation",
        risk_level="unknown",
        risk_rule_id=None,
        confidence="low",
    )
    return finding, details


def relative_file(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
