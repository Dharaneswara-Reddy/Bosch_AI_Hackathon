"""Confidence score (0-1) and the human-review gate for each finding.

Five code-computed factors are weighted by the policy. The sixth design factor, analyst and
critic agreement (0.15), is computed in the AI review stage; this score is normalised over the
five factors available here so it stays comparable once that factor is added.
"""

from guardian.models import Finding, FindingKind, MatchBasis, Reachability, SsvcDecision
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


def apply_confidence(finding: Finding, policy: RiskPolicy) -> Finding:
    must_act = finding.ssvc_decision == SsvcDecision.ACT
    act_reason = "decision is Act: a human confirms before action"
    if finding.kind == FindingKind.ANOMALY:
        return finding.model_copy(update={
            "confidence_score": None, "review_required": must_act,
            "review_reasons": [act_reason] if must_act else [],
        })
    weights = policy.confidence_weights.model_dump()
    present = _factors(finding)
    earned = sum(weights[name] for name, ok in present.items() if ok)
    score = round(earned / policy.confidence_weights.total, 2)
    low = score < policy.review_confidence_threshold
    reasons: list[str] = []
    if low:
        reasons.append(
            f"confidence {score:.2f} is below the {policy.review_confidence_threshold:.2f} "
            "review threshold"
        )
        reasons.extend(FACTOR_GAPS[name] for name, ok in present.items() if not ok)
    if must_act:
        reasons.append(act_reason)
    return finding.model_copy(update={
        "confidence_score": score, "review_required": low or must_act, "review_reasons": reasons,
    })
