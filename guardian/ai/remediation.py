"""Remediation candidates and proposal validation (deterministic, no LLM).

1. ``build_candidates``: for each finding with accepted analysis, code decides
   which actions are allowed and which target versions exist (from scanner
   ``fixed_versions`` only) and flags major-version jumps.
2. The planner agent chooses among those options and writes the rationale.
3. ``validate_proposal``: rejects any proposal outside the allowed options,
   with an invented version, a downplayed breaking-change risk, foreign
   evidence, auto-apply language, or text that fails the claim validator.
Every proposal requires human approval; nothing here applies a fix.
"""

from __future__ import annotations

import hashlib
import re

from guardian.ai.context import ReviewContext
from guardian.ai.schemas import LLMProposal
from guardian.ai.state import EvidencePack, FixAction, RemediationCandidate, RemediationProposal
from guardian.ai.validator import validate
from guardian.models import AgentClaim, ClaimKind

A = FixAction
ANOMALY_ACTIONS: dict[str, list[FixAction]] = {
    "unexpected_dependency": [A.REMOVE_DEPENDENCY, A.ESCALATE_REVIEW],
    "suspected_typosquat": [A.REPLACE_DEPENDENCY, A.REMOVE_DEPENDENCY, A.ESCALATE_REVIEW],
    "install_script_change": [A.PIN_VERSION, A.REMOVE_DEPENDENCY, A.ESCALATE_REVIEW],
    "unverified_install_script": [A.REMOVE_DEPENDENCY, A.REPLACE_DEPENDENCY, A.ESCALATE_REVIEW],
    "dependency_update": [A.PIN_VERSION, A.ESCALATE_REVIEW],
    "unpinned_ci_action": [A.PIN_ACTION_SHA, A.ESCALATE_REVIEW],
    "integrity_change": [A.PIN_VERSION, A.REMOVE_DEPENDENCY, A.ESCALATE_REVIEW],
    "resolved_source_change": [A.PIN_VERSION, A.REMOVE_DEPENDENCY, A.ESCALATE_REVIEW],
    "missing_integrity": [A.PIN_VERSION, A.ESCALATE_REVIEW],
    "unpinned_base_image": [A.PIN_IMAGE_DIGEST, A.ESCALATE_REVIEW],
}
# Fixes are made in manifests and lockfiles, so fix proposals may name these files
# even though no scanner evidence points at them.
MANIFEST_FILES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Gemfile",
        "Gemfile.lock",
        "requirements.txt",
        "poetry.lock",
        "pyproject.toml",
        "uv.lock",
        "Pipfile.lock",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "composer.json",
        "composer.lock",
        "Dockerfile",
    }
)
AUTO_APPLY = re.compile(
    r"(?i)\b(?:auto(?:matically)?[- ]?(?:appl(?:y|ied)|merg(?:e|ed)|deploy(?:ed)?)|"
    r"(?:appl(?:y|ied)|merg(?:e|ed)|deploy(?:ed)?|install(?:ed)?)\s+(?:\w+\s+){0,3}?"
    r"without (?:human )?(?:approval|review)|no (?:approval|review) (?:is )?(?:needed|required))\b"
)


def _major(version: str) -> int | None:
    match = re.match(r"v?(\d+)", version)
    return int(match.group(1)) if match else None


def _actions(pack: EvidencePack) -> list[FixAction]:
    if pack.kind == "malicious":
        return [A.REMOVE_DEPENDENCY, A.ESCALATE_REVIEW]
    if pack.kind == "anomaly":
        return ANOMALY_ACTIONS.get(pack.anomaly_type or "", [A.ESCALATE_REVIEW])
    if not pack.fixed_versions:
        return [A.REPLACE_DEPENDENCY, A.REMOVE_DEPENDENCY, A.ESCALATE_REVIEW]
    direct = pack.direct_dependency in (None, pack.package)
    return (
        [A.UPGRADE, A.ESCALATE_REVIEW]
        if direct
        else [A.UPGRADE_PARENT, A.UPGRADE, A.ESCALATE_REVIEW]
    )


def build_candidate(pack: EvidencePack) -> RemediationCandidate:
    current = _major(pack.version)
    majors = {_major(v) for v in pack.fixed_versions}
    upgrade_parent = (
        None if pack.direct_dependency in (None, pack.package) else pack.direct_dependency
    )
    return RemediationCandidate(
        finding_id=pack.finding_id,
        allowed_actions=_actions(pack),
        allowed_target_versions=list(pack.fixed_versions),
        upgrade_parent=upgrade_parent if pack.kind != "anomaly" else None,
        major_version_change=current is not None and bool(majors) and current not in majors,
        evidence_ids=list(pack.evidence_ids),
    )


def build_candidates(packs: list[EvidencePack], accepted: set[str]) -> list[RemediationCandidate]:
    """Only findings whose analysis passed validation get fix options."""
    return [build_candidate(p) for p in packs if p.finding_id in accepted]


def _structural_reasons(proposal: LLMProposal, candidate: RemediationCandidate) -> list[str]:
    reasons = []
    if proposal.action not in candidate.allowed_actions:
        allowed = ", ".join(a.value for a in candidate.allowed_actions)
        reasons.append(f"action {proposal.action.value} is not allowed here (allowed: {allowed})")
    if (
        proposal.action == A.UPGRADE
        and proposal.target_version not in candidate.allowed_target_versions
    ):
        reasons.append(f"target version {proposal.target_version} is not a scanner-reported fix")
    if proposal.action != A.UPGRADE and proposal.target_version is not None:
        reasons.append("only an upgrade may name a target version")
    if candidate.major_version_change and proposal.breaking_change_risk in ("low", "unknown"):
        reasons.append("major version change but breaking-change risk was not marked medium/high")
    foreign = sorted(set(proposal.evidence_ids) - set(candidate.evidence_ids))
    if foreign:
        reasons.append(f"cites evidence of another finding: {', '.join(foreign)}")
    return reasons


def proposal_text(proposal: LLMProposal, pack: EvidencePack, parent: str | None) -> str:
    target = {
        A.UPGRADE: f"upgrade {pack.package} from {pack.version} to {proposal.target_version}",
        A.UPGRADE_PARENT: (
            f"upgrade {parent} so that it no longer pulls {pack.package} {pack.version}"
        ),
    }.get(proposal.action, f"{proposal.action.value.replace('_', ' ')} for {pack.package}")
    return (
        f"Proposed fix: {target}. {proposal.rationale} Rollback: {proposal.rollback} "
        "Requires human approval before it is applied in a sandbox branch."
    )


def validate_proposal(
    proposal: LLMProposal,
    candidates: dict[str, RemediationCandidate],
    packs: dict[str, EvidencePack],
    ctx: ReviewContext,
) -> tuple[RemediationProposal, AgentClaim]:
    candidate, pack = candidates.get(proposal.finding_id), packs.get(proposal.finding_id)
    reasons = [] if candidate else [f"no remediation candidate for finding {proposal.finding_id}"]
    parent = candidate.upgrade_parent if candidate else None
    text = proposal_text(proposal, pack, parent) if pack else proposal.rationale
    if candidate:
        reasons += _structural_reasons(proposal, candidate)
    if AUTO_APPLY.search(f"{proposal.rationale} {proposal.rollback}"):
        reasons.append("claims the fix is applied without human approval")
    allowed = MANIFEST_FILES | ({_source_file(ctx, proposal.finding_id)} - {""})
    claim = validate(_as_claim(text, proposal), ctx, frozenset(allowed))
    reasons += [claim.rejected_reason] if claim.rejected_reason else []
    accepted = not reasons
    result = RemediationProposal(
        proposal_id=claim.claim_id,
        finding_id=proposal.finding_id,
        action=proposal.action,
        target_version=proposal.target_version,
        rationale=proposal.rationale,
        rollback=proposal.rollback,
        breaking_change_risk=proposal.breaking_change_risk,
        evidence_ids=list(proposal.evidence_ids),
        validated=accepted,
        rejected_reason=None if accepted else "; ".join(reasons),
    )
    return result, claim.model_copy(
        update={"validated": accepted, "rejected_reason": result.rejected_reason}
    )


def _source_file(ctx: ReviewContext, finding_id: str) -> str:
    finding = ctx.findings.get(finding_id)
    component = ctx.component(finding.component_id) if finding else None
    if component is None or component.source_file in ("", "UNKNOWN"):
        return ""
    return component.source_file.rsplit("/", 1)[-1]


def _as_claim(text: str, proposal: LLMProposal) -> AgentClaim:
    digest = hashlib.sha256(f"{proposal.finding_id}|{text}".encode()).hexdigest()[:16]
    return AgentClaim(
        claim_id=f"fix-{digest}",
        step="remediation_planner",
        text=text,
        evidence_ids=list(proposal.evidence_ids),
        kind=ClaimKind.INFERENCE,
        uncertainty=f"breaking-change risk: {proposal.breaking_change_risk}; needs human approval",
    )
