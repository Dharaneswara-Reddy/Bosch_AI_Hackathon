"""Apply the risk analyst's accepted adjustments to findings (plain code, no AI).

The engine's level stays on the finding as ``engine_risk_level`` so both are always shown.
"""

from collections.abc import Iterable

from guardian.ai.risk_rules import floor_problems, step_problems
from guardian.models import Finding, RiskAdjustment, RiskLevel


def _apply(finding: Finding, adjustment: RiskAdjustment) -> Finding:
    if step_problems(adjustment, finding) or floor_problems(adjustment, finding):
        return finding
    return finding.model_copy(update={
        "risk_level": RiskLevel(adjustment.to_level),
        "engine_risk_level": finding.risk_level,
        "ai_adjusted": True,
        "ai_adjustment_reason": adjustment.reason,
        "ai_adjustment_evidence_ids": list(adjustment.evidence_ids),
        "risk_reasons": [*finding.risk_reasons, f"AI risk analyst: {adjustment.reason}"],
    })


def apply_adjustments(
    findings: Iterable[Finding], adjustments: Iterable[RiskAdjustment]
) -> list[Finding]:
    """Return the findings with each accepted adjustment applied; rejected ones are ignored.

    Level and floor checks are repeated here, so an adjustment the findings no longer allow is
    dropped rather than applied.
    """
    accepted = {a.finding_id: a for a in adjustments if a.status == "accepted"}
    return [
        _apply(f, accepted[f.finding_id]) if f.finding_id in accepted else f for f in findings
    ]
