"""Shared, validated contracts for Guardian's pipeline artifacts."""

import hashlib
import json
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

UNKNOWN = "UNKNOWN"
Unknown = Literal["UNKNOWN"]


class ScanStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class LLMStatus(StrEnum):
    COMPLETE = "complete"
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


class FindingKind(StrEnum):
    VULNERABILITY = "vulnerability"
    MALICIOUS = "malicious"
    ANOMALY = "anomaly"


class FindingState(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNDER_INVESTIGATION = "under_investigation"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CoverageStatus(StrEnum):
    FINDING = "finding"
    PASS = "pass"
    NA = "n/a"
    NOT_COVERED = "not_covered"
    ERROR = "error"


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ToolRun(Contract):
    tool: str
    command: list[str]
    exit_code: int
    duration_s: float = Field(ge=0)
    file: str
    sha256: str
    tool_version: str = UNKNOWN


class Scan(Contract):
    scan_id: str
    target: str
    commit_sha: str = UNKNOWN
    lockfile_hash: str = UNKNOWN
    resolution: Resolution | Unknown = UNKNOWN
    scanner_versions: dict[str, str] = Field(default_factory=dict)
    db_built_at: dict[str, str] = Field(default_factory=dict)
    started_at: str = UNKNOWN
    ended_at: str = UNKNOWN
    status: ScanStatus = ScanStatus.PARTIAL
    llm_status: LLMStatus = LLMStatus.UNAVAILABLE
    tools: list[ToolRun] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)
    cached_age_minutes: float | None = None


class Component(Contract):
    component_id: str
    purl: str
    name: str
    version: str = UNKNOWN
    ecosystem: str = UNKNOWN
    scope: Scope = Scope.UNKNOWN
    dev: bool | Unknown = UNKNOWN
    source_file: str = UNKNOWN


class Edge(Contract):
    parent_id: str
    child_id: str
    edge_source: Literal["resolver", "sbom"]


class Evidence(Contract):
    evidence_id: str
    tool: str
    tool_version: str = UNKNOWN
    file: str
    pointer: str
    sha256: str
    url: str | None = None
    collected_at: str
    db_built_at: str = UNKNOWN


class Finding(Contract):
    finding_id: str
    kind: FindingKind
    component_id: str = UNKNOWN
    advisory_id: str = UNKNOWN
    aliases: list[str] = Field(default_factory=list)
    anomaly_type: str = UNKNOWN
    confirmed_by: list[str] = Field(default_factory=list)
    source_severity: dict[str, str] | str = UNKNOWN
    fixed_versions: list[str] = Field(default_factory=list)
    match_basis: Literal["purl", "cpe", "UNKNOWN"] = UNKNOWN
    dependency_path: list[str] = Field(default_factory=list)
    path_count: int | Unknown = UNKNOWN
    evidence_ids: list[str] = Field(default_factory=list)
    state: FindingState = FindingState.UNDER_INVESTIGATION
    risk_level: RiskLevel | Unknown = UNKNOWN
    risk_rule_id: str = UNKNOWN
    confidence: Confidence | Unknown = UNKNOWN
    dev: bool | Unknown = UNKNOWN
    image_tag: str | None = UNKNOWN
    risk_note: str | None = None


class AgentClaim(Contract):
    claim_id: str
    step: str
    text: str
    evidence_ids: list[str] = Field(default_factory=list)
    kind: Literal["evidence", "inference"]
    validated: bool = False
    rejected_reason: str | None = None
    uncertainty: str = UNKNOWN


class CoverageRow(Contract):
    detector: str
    ecosystem: str
    status: CoverageStatus
    reason: str = UNKNOWN
    components_seen: int = Field(default=0, ge=0)


class GraphArtifact(Contract):
    nodes: list[Component] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)


class FindingsArtifact(Contract):
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    claims: list[AgentClaim] = Field(default_factory=list)


class EcosystemCoverage(Contract):
    components: int = Field(ge=0)
    resolver_percent: float = Field(ge=0, le=100)
    scanner_percent: float = Field(ge=0, le=100)


class CoverageArtifact(Contract):
    rows: list[CoverageRow] = Field(default_factory=list)
    ecosystems: dict[str, EcosystemCoverage] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class RunResult(FindingsArtifact):
    scan: Scan
    graph: GraphArtifact = Field(default_factory=GraphArtifact)
    coverage: CoverageArtifact = Field(default_factory=CoverageArtifact)


def finding_id(
    detector: str, purl: str, advisory_or_anomaly: str, dependency_path: list[str]
) -> str:
    identity = json.dumps(
        [detector, purl, advisory_or_anomaly, dependency_path], separators=(",", ":")
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()
