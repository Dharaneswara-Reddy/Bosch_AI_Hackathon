"""Shared data contract. Every stage reads and writes these models.

Owned by P5. Change only by agreement with the whole team.
"""

import hashlib
import json
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

UNKNOWN = "UNKNOWN"


class ScanStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class LlmStatus(StrEnum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class Resolution(StrEnum):
    LOCKFILE = "lockfile"
    RESOLVED = "resolved"
    IMAGE = "image"
    MANIFEST_ONLY = "manifest-only"


class Scope(StrEnum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class EdgeSource(StrEnum):
    RESOLVER = "resolver"
    SBOM = "sbom"


class FindingKind(StrEnum):
    VULNERABILITY = "vulnerability"
    MALICIOUS = "malicious"
    ANOMALY = "anomaly"


class MatchBasis(StrEnum):
    PURL = "purl"
    CPE = "cpe"
    UNKNOWN = "unknown"


class FindingState(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNDER_INVESTIGATION = "under_investigation"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ClaimKind(StrEnum):
    EVIDENCE = "evidence"
    INFERENCE = "inference"


class CoverageStatus(StrEnum):
    FINDING = "finding"
    PASS = "pass"
    NOT_APPLICABLE = "n/a"
    NOT_COVERED = "not_covered"
    ERROR = "error"


class Scan(BaseModel):
    scan_id: str
    target: str
    commit_sha: str = UNKNOWN
    lockfile_hash: str = UNKNOWN
    resolution: Resolution = Resolution.MANIFEST_ONLY
    scanner_versions: dict[str, str] = Field(default_factory=dict)
    db_built_at: dict[str, str] = Field(default_factory=dict)
    started_at: datetime
    ended_at: datetime | None = None
    status: ScanStatus = ScanStatus.PARTIAL
    llm_status: LlmStatus = LlmStatus.UNAVAILABLE


class Component(BaseModel):
    component_id: str
    purl: str
    name: str
    version: str = UNKNOWN
    ecosystem: str = UNKNOWN
    scope: Scope = Scope.UNKNOWN
    dev: bool | None = None
    source_file: str = UNKNOWN


class Edge(BaseModel):
    parent_id: str
    child_id: str
    edge_source: EdgeSource


class Evidence(BaseModel):
    evidence_id: str
    tool: str
    tool_version: str
    file: str
    pointer: str = ""
    sha256: str
    url: str | None = None
    collected_at: datetime | None = None


class Finding(BaseModel):
    finding_id: str
    kind: FindingKind
    component_id: str
    purl: str
    advisory_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    anomaly_type: str | None = None
    confirmed_by: list[str] = Field(default_factory=list)
    source_severity: str = UNKNOWN
    severities: dict[str, str] = Field(default_factory=dict)
    fixed_versions: list[str] = Field(default_factory=list)
    match_basis: MatchBasis = MatchBasis.UNKNOWN
    dependency_path: list[str] = Field(default_factory=list)
    path_count: int | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    state: FindingState = FindingState.AFFECTED
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_rule_id: str | None = None
    confidence: Confidence | None = None


class AgentClaim(BaseModel):
    claim_id: str
    step: str
    text: str
    evidence_ids: list[str] = Field(default_factory=list)
    kind: ClaimKind
    validated: bool = False
    rejected_reason: str | None = None
    uncertainty: str | None = None


class CoverageRow(BaseModel):
    detector: str
    ecosystem: str
    status: CoverageStatus
    reason: str = ""
    components_seen: int = 0


def finding_id(detector: str, purl: str, advisory_or_anomaly: str, path: list[str]) -> str:
    identity = json.dumps([detector, purl, advisory_or_anomaly, path], separators=(",", ":"))
    return hashlib.sha256(identity.encode()).hexdigest()[:16]
