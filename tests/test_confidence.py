from guardian.confidence import apply_confidence
from guardian.models import (
    Exploitation,
    Finding,
    Reachability,
    Relevance,
    SsvcDecision,
)
from guardian.policy import RiskPolicy

POLICY = RiskPolicy()


def vuln(**extra: object) -> Finding:
    return Finding(
        finding_id="x", component_id="lib", purl="pkg:npm/lib@1", kind="vulnerability",
        ssvc_decision=SsvcDecision.TRACK_STAR, **extra,
    )


FULL = {
    "match_basis": "purl", "confirmed_by": ["grype", "osv"], "dependency_path": ["app", "lib"],
    "epss": 0.01, "relevance": Relevance(reachability=Reachability.NOT_DETECTED),
}


def test_all_five_factors_present_scores_one_and_needs_no_review() -> None:
    result = apply_confidence(vuln(**FULL), POLICY)
    assert result.confidence_score == 1.0
    assert result.review_required is False
    assert result.review_reasons == []


def test_scores_normalise_over_the_five_computed_factors() -> None:
    finding = vuln(**{**FULL, "confirmed_by": ["grype"]})
    assert apply_confidence(finding, POLICY).confidence_score == round(0.7 / 0.85, 2)


def test_low_confidence_requires_review_and_names_missing_factors() -> None:
    result = apply_confidence(vuln(match_basis="cpe"), POLICY)
    assert result.confidence_score == 0.0
    assert result.review_required is True
    assert "confidence 0.00 is below the 0.60 review threshold" in result.review_reasons
    assert "installed version not confirmed inside the affected range" in result.review_reasons
    assert "reachability unknown" in result.review_reasons


def test_act_decision_always_requires_review_even_when_confident() -> None:
    finding = vuln(**FULL).model_copy(update={"ssvc_decision": SsvcDecision.ACT})
    result = apply_confidence(finding, POLICY)
    assert result.confidence_score == 1.0
    assert result.review_required is True
    assert result.review_reasons == ["decision is Act: a human confirms before action"]


def test_kev_counts_as_exploit_data_even_without_epss() -> None:
    finding = vuln(**{**FULL, "epss": None, "known_exploited": False})
    assert apply_confidence(finding, POLICY).confidence_score == 1.0


def test_exploitation_field_is_not_used_as_exploit_data() -> None:
    finding = vuln(**{**FULL, "epss": None}).model_copy(
        update={"exploitation": Exploitation.UNKNOWN}
    )
    assert apply_confidence(finding, POLICY).confidence_score == round(0.7 / 0.85, 2)


def test_anomalies_have_no_score_and_review_only_when_act() -> None:
    anomaly = Finding(
        finding_id="x", component_id="lib", purl="pkg:npm/lib@1", kind="anomaly",
        ssvc_decision=SsvcDecision.ATTEND,
    )
    result = apply_confidence(anomaly, POLICY)
    assert result.confidence_score is None and result.review_required is False
    act = anomaly.model_copy(update={"ssvc_decision": SsvcDecision.ACT})
    assert apply_confidence(act, POLICY).review_required is True


def reviewed(**extra: object) -> Finding:
    return vuln(**{**FULL, **extra})


def test_agreement_is_the_sixth_factor_for_ai_reviewed_findings() -> None:
    finding = reviewed(confirmed_by=["grype"])
    assert apply_confidence(finding, POLICY, {"x": True}).confidence_score == round(0.85 / 1.0, 2)
    assert apply_confidence(finding, POLICY, {"x": False}).confidence_score == round(0.7 / 1.0, 2)


def test_findings_the_ai_did_not_review_keep_five_factor_scores() -> None:
    finding = reviewed(confirmed_by=["grype"])
    result = apply_confidence(finding, POLICY, {"other": True})
    assert result.confidence_score == round(0.7 / 0.85, 2)


def adjusted(before: str, after: str) -> Finding:
    return reviewed(ai_adjusted=True, engine_risk_level=before, risk_level=after)


def test_ai_move_into_critical_requires_review() -> None:
    result = apply_confidence(adjusted("high", "critical"), POLICY, {"x": True})
    assert result.review_required is True
    assert "AI risk analyst moved the level into critical (from high)" in result.review_reasons


def test_ai_move_out_of_critical_requires_review() -> None:
    result = apply_confidence(adjusted("critical", "high"), POLICY, {"x": True})
    assert "AI risk analyst moved the level out of critical (to high)" in result.review_reasons


def test_ai_move_between_other_levels_does_not_require_review() -> None:
    result = apply_confidence(adjusted("medium", "high"), POLICY, {"x": True})
    assert result.review_required is False


def test_critic_disagreement_on_an_adjusted_finding_requires_review() -> None:
    result = apply_confidence(adjusted("medium", "high"), POLICY, {"x": False})
    assert result.review_required is True
    assert "analyst and critic disagree on the risk adjustment" in result.review_reasons
