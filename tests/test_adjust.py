from guardian.adjust import apply_adjustments
from guardian.models import (
    Finding,
    FindingKind,
    Relevance,
    RelevanceSignal,
    RiskAdjustment,
    RiskLevel,
)

REASON = "The advisory only applies when the legacy parser is enabled."


def finding(level: RiskLevel = RiskLevel.MEDIUM, **extra: object) -> Finding:
    return Finding(
        finding_id="f1", component_id="lib", purl="pkg:npm/lib@1", kind=FindingKind.VULNERABILITY,
        risk_level=level, risk_reasons=["engine reason"], **extra,
    )


def adjustment(**updates: object) -> RiskAdjustment:
    fields = {
        "finding_id": "f1", "from_level": "medium", "to_level": "high", "direction": "raise",
        "reason": REASON, "evidence_ids": ["ev-1"], "status": "accepted",
    }
    return RiskAdjustment.model_validate({**fields, **updates})


def test_accepted_adjustment_sets_level_and_keeps_the_engine_level() -> None:
    [result] = apply_adjustments([finding()], [adjustment()])
    assert result.risk_level == RiskLevel.HIGH
    assert result.engine_risk_level == RiskLevel.MEDIUM
    assert result.ai_adjusted is True
    assert result.ai_adjustment_evidence_ids == ["ev-1"]
    assert result.risk_reasons == ["engine reason", f"AI risk analyst: {REASON}"]


def test_rejected_adjustment_changes_nothing() -> None:
    original = finding()
    rejected = adjustment(status="rejected", rejected_reason="two levels")
    assert apply_adjustments([original], [rejected]) == [original]


def test_adjustment_not_starting_at_the_current_level_is_skipped() -> None:
    original = finding(RiskLevel.LOW)
    assert apply_adjustments([original], [adjustment()]) == [original]


def test_floor_is_enforced_again_for_known_exploited_production_findings() -> None:
    signals = [RelevanceSignal(name="known_exploited", value="yes"),
               RelevanceSignal(name="dependency_scope", value="production")]
    original = finding(RiskLevel.HIGH, relevance=Relevance(signals=signals))
    lower = adjustment(from_level="high", to_level="medium", direction="lower")
    assert apply_adjustments([original], [lower]) == [original]


def test_unrelated_findings_pass_through() -> None:
    other = finding().model_copy(update={"finding_id": "f2"})
    assert apply_adjustments([other], [adjustment()]) == [other]
