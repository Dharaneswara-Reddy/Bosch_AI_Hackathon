"""Typed hand-offs between the agents.

Each agent reads only the objects produced by the agents before it and writes
new objects that cite their inputs by ID. Nothing an agent writes is a fact:
facts live in ``ReviewContext`` (tool output) and are copied into evidence packs.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from pydantic import BaseModel

from guardian.models import (
    AgentClaim,
    AgentTrace,
    FixAction,
    Relevance,
    RemediationProposal,
    RiskAdjustment,
)

__all__ = ["FixAction", "RemediationProposal"]


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
