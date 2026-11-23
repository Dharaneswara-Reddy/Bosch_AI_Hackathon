"""Typed hand-offs between the agents.

Each agent reads only the objects produced by the agents before it and writes
new objects that cite their inputs by ID. Nothing an agent writes is a fact:
facts live in ``ReviewContext`` (tool output) and are copied into evidence packs.
"""

from __future__ import annotations

import operator
from enum import StrEnum
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from guardian.models import AgentClaim, AgentTrace, Relevance


class FixAction(StrEnum):
    UPGRADE = "upgrade"
    UPGRADE_PARENT = "upgrade_parent"
    PIN_VERSION = "pin_version"
    REMOVE_DEPENDENCY = "remove_dependency"
    REPLACE_DEPENDENCY = "replace_dependency"
    PIN_ACTION_SHA = "pin_action_sha"
    PIN_IMAGE_DIGEST = "pin_image_digest"
    ESCALATE_REVIEW = "escalate_review"


class EvidencePack(BaseModel):
    """Everything one agent may know about one finding (built by triage, from tool output only)."""

    pack_id: str
    finding_id: str
    kind: str
    package: str
    version: str
    purl: str
    advisory_id: str | None
    aliases: list[str]
    anomaly_type: str | None
    source_severity: str
    fixed_versions: list[str]
    dependency_path: list[str]
    direct_dependency: str | None
    path_count: int | None
    risk_level: str
    risk_rule_id: str | None
    state: str
    reachability: str = "unknown"
    relevance: Relevance | None = None
    evidence: list[dict[str, Any]]
    evidence_ids: list[str]


class PackageGroup(BaseModel):
    """All findings of one package (platform builds merged): the unit of one parallel branch."""

    group_id: str
    package: str
    top_risk: str
    finding_ids: list[str]


class RemediationCandidate(BaseModel):
    """Fix options computed by code; the planner may only choose among these."""

    finding_id: str
    allowed_actions: list[FixAction]
    allowed_target_versions: list[str]
    upgrade_parent: str | None
    major_version_change: bool
    evidence_ids: list[str]


class RemediationProposal(BaseModel):
    proposal_id: str
    finding_id: str
    action: FixAction
    target_version: str | None
    rationale: str
    rollback: str
    breaking_change_risk: str
    evidence_ids: list[str]
    requires_human_approval: bool = True
    validated: bool = False
    rejected_reason: str | None = None


class RiskAdjustment(BaseModel):
    """The risk analyst's proposed one-level change, kept with its verdict and never merged."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    from_level: Literal["critical", "high", "medium", "low"]
    to_level: Literal["critical", "high", "medium", "low"]
    direction: Literal["raise", "lower"]
    reason: str = Field(min_length=1, max_length=300)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    status: Literal["accepted", "rejected"] = "accepted"
    rejected_reason: str | None = None


class BranchInput(TypedDict):
    """What one parallel branch receives from the fan-out: one package group and its packs."""

    group: PackageGroup
    group_packs: list[EvidencePack]
    project: str


class GuardianState(TypedDict, total=False):
    """Graph state. Branch outputs (``pending``, ``adjustments``, ``trace``, ``errors``)
    accumulate through reducers when the branches fan in; every other key is replaced."""

    groups: list[PackageGroup]
    packs: list[EvidencePack]
    project_text: str
    pending: Annotated[list[AgentClaim], operator.add]
    adjustments: Annotated[list[RiskAdjustment], operator.add]
    reviewed_adjustments: list[RiskAdjustment]
    agreement: dict[str, bool]
    claims: list[AgentClaim]
    candidates: list[RemediationCandidate]
    proposals: list[RemediationProposal]
    revision_round: int
    trace: Annotated[list[AgentTrace], operator.add]
    errors: Annotated[dict[str, str], operator.or_]
