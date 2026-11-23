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
