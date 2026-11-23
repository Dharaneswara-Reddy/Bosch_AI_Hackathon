"""Confidence score (0-1) and the human-review gate for each finding.

Five code-computed factors are weighted by the policy. A sixth, analyst and critic agreement,
counts only for findings the AI reviewed (present in the agreement map); every other finding is
normalised over the five code-computed factors.
"""

from collections.abc import Mapping

from guardian.models import (
    Finding,
    FindingKind,
    MatchBasis,
    Reachability,
    RiskLevel,
    SsvcDecision,
)
from guardian.policy import RiskPolicy

FACTOR_GAPS = {
    "version_confirmed": "installed version not confirmed inside the affected range",
    "path_resolved": "dependency path not resolved from a lockfile",
    "scanners_agree": "only one scanner reported it",
    "exploit_data": "no exploit data (EPSS or KEV)",
    "reachability_known": "reachability unknown",
}


def _factors(finding: Finding) -> dict[str, bool]:
    return {
        "version_confirmed": finding.match_basis == MatchBasis.PURL,
        "path_resolved": bool(finding.dependency_path),
        "scanners_agree": {"grype", "osv"} <= set(finding.confirmed_by),
        "exploit_data": finding.epss is not None or finding.known_exploited is not None,
        "reachability_known": finding.relevance is not None
        and finding.relevance.reachability != Reachability.UNKNOWN,
    }


def _ai_reasons(finding: Finding, agreement: Mapping[str, bool]) -> list[str]:
    reasons: list[str] = []
    before, after = finding.engine_risk_level, finding.risk_level
    if finding.ai_adjusted and before != after:
        if after == RiskLevel.CRITICAL:
            reasons.append(f"AI risk analyst moved the level into critical (from {before})")
        elif before == RiskLevel.CRITICAL:
            reasons.append(f"AI risk analyst moved the level out of critical (to {after})")
    if agreement.get(finding.finding_id) is False:
        reasons.append("analyst and critic disagree on the risk adjustment")
    return reasons


def apply_confidence(
    finding: Finding, policy: RiskPolicy, agreement: Mapping[str, bool] | None = None
) -> Finding:
    agreement = agreement or {}
    must_act = finding.ssvc_decision == SsvcDecision.ACT
    act_reason = "decision is Act: a human confirms before action"
    ai_reasons = _ai_reasons(finding, agreement)
    if finding.kind == FindingKind.ANOMALY:
        reasons = ([act_reason] if must_act else []) + ai_reasons
        return finding.model_copy(update={
            "confidence_score": None, "review_required": bool(reasons), "review_reasons": reasons,
        })
    weights = policy.confidence_weights.model_dump()
    present = _factors(finding)
    earned = sum(weights[name] for name, ok in present.items() if ok)
    total = policy.confidence_weights.total
    if finding.finding_id in agreement:
        total = policy.confidence_weights.total_reviewed
        if agreement[finding.finding_id]:
            earned += weights["analyst_critic_agreement"]
    score = round(earned / total, 2)
    low = score < policy.review_confidence_threshold
    reasons = []
    if low:
        reasons.append(
            f"confidence {score:.2f} is below the {policy.review_confidence_threshold:.2f} "
            "review threshold"
        )
        reasons.extend(FACTOR_GAPS[name] for name, ok in present.items() if not ok)
    if must_act:
        reasons.append(act_reason)
    reasons.extend(ai_reasons)
    return finding.model_copy(update={
        "confidence_score": score, "review_required": bool(reasons), "review_reasons": reasons,
    })
