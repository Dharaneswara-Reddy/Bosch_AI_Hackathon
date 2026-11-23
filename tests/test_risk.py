import pytest

from guardian.models import (
    Automatable,
    Exploitation,
    Exposure,
    Finding,
    Reachability,
    Relevance,
    SsvcDecision,
    TechnicalImpact,
)
from guardian.policy import RiskPolicy
from guardian.risk import assess

POLICY = RiskPolicy()
NETWORK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"


def vuln(severity: str = "Medium", **extra: object) -> Finding:
    return Finding(
        finding_id="x",
        component_id="lib",
        purl="pkg:npm/lib@1",
        kind="vulnerability",
        source_severity=severity,
        severities={"grype": severity},
        **extra,
    )


def test_cvss_medium_in_kev_in_production_is_critical() -> None:
    finding = vuln("Medium", known_exploited=True, cvss_vector=LOCAL)
    result = assess(finding, dev=False, policy=POLICY)
    assert result.exploitation == Exploitation.ACTIVE
    assert result.ssvc_decision == SsvcDecision.ACT
    assert (result.risk_level, result.risk_rule_id) == ("critical", "SSVC-ACT")
    assert "in CISA KEV" in result.risk_reasons
    assert "production dependency" in result.risk_reasons


def test_automatable_total_impact_in_production_attends_without_exploitation() -> None:
    remote = vuln("Critical", epss=0.001, epss_percentile=0.2, cvss_vector=NETWORK)
    assert assess(remote, dev=False, policy=POLICY).ssvc_decision == SsvcDecision.ATTEND
    local = vuln(
        "High",
        epss=0.001,
        epss_percentile=0.2,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
    )
    assert assess(local, dev=False, policy=POLICY).ssvc_decision == SsvcDecision.TRACK_STAR


def test_cvss_critical_without_exploitation_in_dev_is_not_critical() -> None:
    finding = vuln("Critical", epss=0.001, epss_percentile=0.2, cvss_vector=NETWORK)
    result = assess(finding, dev=True, policy=POLICY)
    assert result.exploitation == Exploitation.NONE
    assert result.exposure == Exposure.SMALL
    assert result.risk_level in {"low", "medium"}
    assert result.ssvc_decision == SsvcDecision.TRACK

    """Missing data is not safety: unknown exploit data and scope keep the old R-CVE-U medium."""
    """Missing data is not safety: unknown exploit data and scope keep the old R-CVE-U medium."""
    result = assess(vuln("UNKNOWN"), dev=None, policy=POLICY)
    assert result.exploitation == Exploitation.UNKNOWN
    assert result.exposure == Exposure.LIMITED
    assert result.risk_level == "medium"
    assert result.ssvc_decision == SsvcDecision.TRACK_STAR
    assert result.state == "under_investigation"


def test_unknown_exploitation_with_total_impact_in_production_is_high() -> None:
    result = assess(vuln("Critical"), dev=False, policy=POLICY)
    assert (result.ssvc_decision, result.risk_level) == (SsvcDecision.ATTEND, "high")


@pytest.mark.parametrize(
    "epss, percentile, expected",
    [
        (0.1, 0.5, Exploitation.LIKELY),
        (0.05, 0.95, Exploitation.LIKELY),
        (0.05, 0.5, Exploitation.NONE),
        (None, None, Exploitation.UNKNOWN),
    ],
)
def test_exploitation_thresholds(epss, percentile, expected) -> None:
    result = assess(vuln(epss=epss, epss_percentile=percentile), dev=False, policy=POLICY)
    assert result.exploitation == expected


def test_likely_exploitation_with_total_impact_in_production_attends() -> None:
    result = assess(vuln("High", epss=0.5, epss_percentile=0.99), dev=False, policy=POLICY)
    assert (result.ssvc_decision, result.risk_rule_id) == (SsvcDecision.ATTEND, "SSVC-ATTEND")
    assert "EPSS 0.50 (99th percentile)" in result.risk_reasons


def test_active_exploitation_on_dev_dependency_attends() -> None:
    result = assess(vuln("High", known_exploited=True), dev=True, policy=POLICY)
    assert (result.ssvc_decision, result.risk_level) == (SsvcDecision.ATTEND, "high")


def test_likely_partial_impact_is_track_star() -> None:
    finding = vuln("Low", epss=0.5, epss_percentile=0.99, cvss_vector=LOCAL)
    result = assess(finding, dev=False, policy=POLICY)
    assert (result.ssvc_decision, result.risk_rule_id) == (
        SsvcDecision.TRACK_STAR,
        "SSVC-TRACK-STAR",
    )


@pytest.mark.parametrize(
    "vector, expected",
    [
        (NETWORK, Automatable.YES),
        (LOCAL, Automatable.NO),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L", Automatable.NO),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L", Automatable.YES),
        (None, Automatable.UNKNOWN),
    ],
)
def test_automatable_from_cvss_vector(vector, expected) -> None:
    assert assess(vuln(cvss_vector=vector), dev=False, policy=POLICY).automatable == expected


def test_technical_impact_from_vector_when_severity_is_low() -> None:
    total = assess(vuln("Low", cvss_vector=NETWORK), dev=False, policy=POLICY)
    partial = assess(vuln("Low", cvss_vector=LOCAL), dev=False, policy=POLICY)
    assert total.technical_impact == TechnicalImpact.TOTAL
    assert partial.technical_impact == TechnicalImpact.PARTIAL


def test_confirmed_reachability_in_production_is_open_exposure() -> None:
    finding = vuln(relevance=Relevance(reachability=Reachability.CONFIRMED))
    assert assess(finding, dev=False, policy=POLICY).exposure == Exposure.OPEN
    assert assess(finding, dev=None, policy=POLICY).exposure == Exposure.LIMITED


def test_score_orders_exploited_exposed_above_unexploited_dev() -> None:
    hot = vuln("High", cvss_score=7.5, epss=0.9, epss_percentile=0.99)
    cold = vuln("High", cvss_score=7.5, epss=0.001, epss_percentile=0.1)
    hot, cold = assess(hot, dev=False, policy=POLICY), assess(cold, dev=True, policy=POLICY)
    assert 0 <= cold.risk_score < hot.risk_score <= 100


def test_malicious_package_is_always_act() -> None:
    finding = Finding(
        finding_id="x",
        component_id="lib",
        purl="pkg:npm/lib@1",
        kind="malicious",
    )
    result = assess(finding, dev=True, policy=POLICY)
    assert (result.risk_rule_id, result.risk_level) == ("R-MAL", "critical")
    assert result.ssvc_decision == SsvcDecision.ACT
    assert result.risk_reasons


@pytest.mark.parametrize(
    "anomaly, tag, rule, level, decision",
    [
        ("suspected_typosquat", None, "R-AN-1", "high", SsvcDecision.ATTEND),
        ("unpinned_base_image", "latest", "R-AN-2", "medium", SsvcDecision.TRACK_STAR),
        ("unpinned_base_image", "3", "R-AN-3", "low", SsvcDecision.TRACK),
    ],
)
def test_anomalies_keep_their_levels_with_consistent_decision(anomaly, tag, rule, level, decision):
    finding = assess(
        Finding(
            finding_id="x",
            component_id="lib",
            purl="pkg:npm/lib@1",
            kind="anomaly",
            anomaly_type=anomaly,
            image_tag=tag,
        ),
        dev=None,
        policy=POLICY,
    )
    assert (finding.risk_rule_id, finding.risk_level, finding.ssvc_decision) == (
        rule,
        level,
        decision,
    )
    assert finding.risk_reasons
    assert finding.state == "under_investigation"


def test_unknown_anomaly_type_is_rejected() -> None:
    finding = Finding(
        finding_id="x",
        component_id="lib",
        purl="pkg:npm/lib@1",
        kind="anomaly",
        anomaly_type="odd",
    )
    with pytest.raises(ValueError, match="odd"):
        assess(finding, dev=None, policy=POLICY)


def test_cpe_match_is_low_confidence_enum() -> None:
    finding = vuln(match_basis="cpe", confirmed_by=["grype", "osv"])
    finding = assess(finding, dev=None, policy=POLICY)
    assert finding.confidence == "low"
