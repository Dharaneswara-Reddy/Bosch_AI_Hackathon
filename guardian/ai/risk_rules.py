"""Deterministic limits on the risk analyst (plain code, no AI).

The analyst may only propose a one-level change. Code rejects it, keeping the reason,
when the step is wrong, a floor would be broken, a citation is not the finding's own
evidence, or the reason text fails the evidence validator.
"""

from __future__ import annotations

from collections.abc import Collection

from guardian.ai.context import RISK_ORDER, ReviewContext, as_text
from guardian.ai.validator import validate
from guardian.models import AgentClaim, ClaimKind, Finding, FindingKind, RiskAdjustment

LEVELS = tuple(RISK_ORDER)
HIGH = RISK_ORDER["high"]


def _signal(finding: Finding, name: str) -> str:
    signals = finding.relevance.signals if finding.relevance else []
    return next((s.value for s in signals if s.name == name), "unknown")


def step_problems(raw: RiskAdjustment, finding: Finding) -> list[str]:
    current = as_text(finding.risk_level).lower()
    if current not in RISK_ORDER:
        return [f"finding has no current risk level ('{current}')"]
    problems = []
    if raw.from_level != current:
        problems.append(f"from_level {raw.from_level} does not match current level {current}")
    delta = RISK_ORDER[raw.to_level] - RISK_ORDER[current]
    if abs(delta) != 1:
        problems.append("to_level must be exactly one level from the current level")
    elif (delta > 0) != (raw.direction == "lower"):
        problems.append(f"direction {raw.direction} contradicts {current} -> {raw.to_level}")
    return problems


def floor_problems(raw: RiskAdjustment, finding: Finding) -> list[str]:
    if RISK_ORDER[raw.to_level] <= RISK_ORDER[raw.from_level]:
        return []
    if finding.kind == FindingKind.MALICIOUS:
        return ["a malicious package is never lowered"]
    exploited = _signal(finding, "known_exploited") == "yes"
    if exploited and _signal(finding, "dependency_scope") == "production":
        if RISK_ORDER[raw.to_level] > HIGH:
            return ["a known exploited production dependency never drops below high"]
    return []


def _citation_problems(raw: RiskAdjustment, ctx: ReviewContext, finding: Finding) -> list[str]:
    if not raw.evidence_ids:
        return ["an adjustment must cite evidence"]
    own = set(finding.evidence_ids)
    return [
        f"evidence {e} does not belong to finding {finding.finding_id}"
        if e in ctx.evidence
        else f"evidence ID not found: {e}"
        for e in raw.evidence_ids
        if e not in own
    ]


def _reason_problems(raw: RiskAdjustment, ctx: ReviewContext) -> list[str]:
    claim = AgentClaim(
        claim_id=f"risk-{raw.finding_id}",
        step="risk_analyst",
        text=raw.reason,
        evidence_ids=raw.evidence_ids,
        kind=ClaimKind.EVIDENCE,
    )
    checked = validate(claim, ctx)
    return [f"reason: {checked.rejected_reason}"] if not checked.validated else []


def check_adjustment(
    raw: RiskAdjustment, ctx: ReviewContext, scope: Collection[str]
) -> RiskAdjustment:
    """Return the adjustment marked accepted, or rejected with every failing reason.

    ``scope`` holds the finding IDs of the package group the analyst was given.
    """
    finding = ctx.findings.get(raw.finding_id) if raw.finding_id in scope else None
    if finding is None:
        return _verdict(raw, [f"unknown finding {raw.finding_id}"])
    problems = step_problems(raw, finding)
    problems += floor_problems(raw, finding) if not problems else []
    problems += _citation_problems(raw, ctx, finding)
    problems += _reason_problems(raw, ctx) if not problems else []
    return _verdict(raw, problems)


def _verdict(raw: RiskAdjustment, problems: list[str]) -> RiskAdjustment:
    if problems:
        return raw.model_copy(update={"status": "rejected", "rejected_reason": "; ".join(problems)})
    return raw.model_copy(update={"status": "accepted", "rejected_reason": None})
