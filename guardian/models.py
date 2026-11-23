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


class RelevanceVerdict(StrEnum):
    RELEVANT = "relevant"
    LIKELY_RELEVANT = "likely_relevant"
    LOW_RELEVANCE = "low_relevance"
    UNKNOWN = "unknown"


class Reachability(StrEnum):
    CONFIRMED = "confirmed"
    NOT_DETECTED = "not_detected"
    UNKNOWN = "unknown"


class CoverageStatus(StrEnum):
    FINDING = "finding"
    PASS = "pass"
    NOT_APPLICABLE = "n/a"
    NOT_COVERED = "not_covered"
    ERROR = "error"


class ToolRun(BaseModel):
    tool: str
    command: list[str]
    exit_code: int
    duration_s: float = Field(ge=0)
    file: str
    sha256: str
    tool_version: str = UNKNOWN


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
    tools: list[ToolRun] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)
    cached_age_minutes: float | None = None


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
    db_built_at: str = UNKNOWN


class RelevanceSignal(BaseModel):
    """One evidence-backed fact used to decide whether a finding matters."""

    name: str
    value: str
    detail: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class Relevance(BaseModel):
    """Code-computed relevance of a vulnerability or malicious-package finding."""

    verdict: RelevanceVerdict = RelevanceVerdict.UNKNOWN
    reachability: Reachability = Reachability.UNKNOWN
    introduced_by: str | None = None
    path_labels: list[str] = Field(default_factory=list)
    signals: list[RelevanceSignal] = Field(default_factory=list)
    summary: str = ""


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
    image_tag: str | None = None
    risk_note: str | None = None
    relevance: Relevance | None = None


class AgentClaim(BaseModel):
    claim_id: str
    step: str
    text: str
    evidence_ids: list[str] = Field(default_factory=list)
    kind: ClaimKind
    validated: bool = False
    rejected_reason: str | None = None
    uncertainty: str | None = None


class AgentTrace(BaseModel):
    """One agent hand-off: what it consumed, what it produced, how much was accepted."""

    agent: str
    consumed: list[str] = Field(default_factory=list)
    produced: list[str] = Field(default_factory=list)
    accepted: int = 0
    rejected: int = 0
    llm_calls: int = 0
    error: str | None = None
    provider: str | None = None


class CoverageRow(BaseModel):
    detector: str
    ecosystem: str
    status: CoverageStatus
    reason: str = ""
    components_seen: int = 0


class GraphArtifact(BaseModel):
    nodes: list[Component] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)


class FindingsArtifact(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    claims: list[AgentClaim] = Field(default_factory=list)
    agent_trace: list[AgentTrace] = Field(default_factory=list)


class EcosystemCoverage(BaseModel):
    components: int = Field(ge=0)
    resolver_percent: float = Field(ge=0, le=100)
    scanner_percent: float = Field(ge=0, le=100)


class CoverageArtifact(BaseModel):
    rows: list[CoverageRow] = Field(default_factory=list)
    ecosystems: dict[str, EcosystemCoverage] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class RunResult(FindingsArtifact):
    scan: Scan
    graph: GraphArtifact = Field(default_factory=GraphArtifact)
    coverage: CoverageArtifact = Field(default_factory=CoverageArtifact)


def finding_id(detector: str, purl: str, advisory_or_anomaly: str, path: list[str]) -> str:
    identity = json.dumps([detector, purl, advisory_or_anomaly, path], separators=(",", ":"))
    return hashlib.sha256(identity.encode()).hexdigest()[:16]
