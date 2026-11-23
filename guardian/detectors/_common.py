"""Shared, serializable output helpers for anomaly detectors.

The P5-owned ``guardian.models`` contract is not present on this branch yet.
Detector payloads intentionally use the contract's field names so the runner
can validate them with the shared Pydantic models at the stage boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


UNKNOWN = "UNKNOWN"
JsonObject = dict[str, Any]


@dataclass
class DetectionResult:
    """Findings, evidence drafts and coverage emitted by one detector."""

    findings: list[JsonObject] = field(default_factory=list)
    evidence: list[JsonObject] = field(default_factory=list)
    coverage: list[JsonObject] = field(default_factory=list)


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
) -> list[JsonObject]:
    counts = components_seen or {}
    return [
        {
            "detector": detector,
            "ecosystem": ecosystem,
            "status": status,
            "reason": reason,
            "components_seen": counts.get(ecosystem, 0),
        }
        for ecosystem in ecosystems
    ]


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def json_sha256(value: Any) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, default=str).encode("utf-8"))


def evidence_record(
    detector: str,
    file: str,
    pointer: str,
    content: bytes,
    **details: Any,
) -> JsonObject:
    record: JsonObject = {
        "evidence_id": hashlib.sha256(
            f"{detector}\0{file}\0{pointer}\0{sha256_bytes(content)}".encode("utf-8")
        ).hexdigest()[:24],
        "tool": f"guardian:{detector}",
        "tool_version": "1",
        "file": file,
        "pointer": pointer,
        "sha256": sha256_bytes(content),
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
    record.update(details)
    return record


def finding_payload(
    detector: str,
    component: Any,
    anomaly_type: str,
    evidence_ids: Iterable[str],
    **details: Any,
) -> JsonObject:
    purl = purl_of(component) if component is not None else UNKNOWN
    component_id = read_value(component, "component_id") or read_value(component, "bom-ref") or purl
    identity = json.dumps([detector, purl, anomaly_type, []], separators=(",", ":"))
    finding: JsonObject = {
        "finding_id": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        "kind": "anomaly",
        "component_id": component_id,
        "advisory_id": UNKNOWN,
        "aliases": [],
        "anomaly_type": anomaly_type,
        "confirmed_by": [],
        "source_severity": UNKNOWN,
        "fixed_versions": [],
        "match_basis": "purl",
        "dependency_path": [],
        "path_count": UNKNOWN,
        "evidence_ids": list(evidence_ids),
        "state": "under_investigation",
        "risk_level": UNKNOWN,
        "risk_rule_id": UNKNOWN,
        "confidence": "low",
        "details": details,
    }
    return finding


def relative_file(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
