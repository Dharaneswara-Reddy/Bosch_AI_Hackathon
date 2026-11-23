"""Typed hand-offs between the agents.

Each agent reads only the objects produced by the agents before it and writes
new objects that cite their inputs by ID. Nothing an agent writes is a fact:
facts live in ``ReviewContext`` (tool output) and are copied into evidence packs.
"""

from __future__ import annotations

import operator
from enum import StrEnum
from typing import Annotated, Any, TypedDict

from pydantic import BaseModel

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


class GuardianState(TypedDict, total=False):
    """Graph state. ``trace`` and ``errors`` accumulate; every other key is replaced."""

    packs: list[EvidencePack]
    project_text: str
    pending: list[AgentClaim]
    claims: list[AgentClaim]
    candidates: list[RemediationCandidate]
    proposals: list[RemediationProposal]
    revision_round: int
    trace: Annotated[list[AgentTrace], operator.add]
    errors: Annotated[dict[str, str], operator.or_]
