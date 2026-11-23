"""Deterministic risk engine: CISA's SSVC decision tree over evidence-backed signals.

Four decision points (exploitation, exposure, automatable, technical impact) map to an SSVC
decision, which maps to a Guardian level. Missing data is ``unknown``, never "safe".
"""

from typing import NamedTuple

from guardian.models import (
    UNKNOWN,
    Automatable,
    Confidence,
    Exploitation,
    Exposure,
    Finding,
    FindingState,
    Reachability,
    RiskLevel,
    SsvcDecision,
    TechnicalImpact,
)
from guardian.policy import RiskPolicy

LEVELS = (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
DECISION_LEVEL = {
    SsvcDecision.ACT: RiskLevel.CRITICAL,
    SsvcDecision.ATTEND: RiskLevel.HIGH,
    SsvcDecision.TRACK_STAR: RiskLevel.MEDIUM,
    SsvcDecision.TRACK: RiskLevel.LOW,
}
DECISION_RULE = {
    SsvcDecision.ACT: "SSVC-ACT",
    SsvcDecision.ATTEND: "SSVC-ATTEND",
    SsvcDecision.TRACK_STAR: "SSVC-TRACK-STAR",
    SsvcDecision.TRACK: "SSVC-TRACK",
}
LEVEL_DECISION = {level: decision for decision, level in DECISION_LEVEL.items()}
SEVERITY_BASE = {
    RiskLevel.CRITICAL: 9.5, RiskLevel.HIGH: 8.0, RiskLevel.MEDIUM: 5.5, RiskLevel.LOW: 2.5,
}
IMPACT_METRICS = ("C", "I", "A", "VC", "VI", "VA")
EXPLOIT_LIKELY_ANOMALIES = {"install_script_change", "unverified_install_script"}
ANOMALY_REASONS = {
    "suspected_typosquat": "name resembles a popular package (suspected typosquat)",
    "install_script_change": "install script changed",
    "unverified_install_script": "install script could not be verified",
    "unexpected_dependency": "dependency not declared in the manifest",
    "unpinned_base_image": "base image is not pinned to a digest",
    "dependency_update": "dependency changed versus the baseline",
    "unpinned_ci_action": "CI action is not pinned to a commit",
}


class _Signals(NamedTuple):
    exposure: Exposure
    automatable: Automatable
    impact: TechnicalImpact


def _highest_severity(finding: Finding) -> RiskLevel | None:
    labels = {s.strip().lower() for s in [finding.source_severity, *finding.severities.values()]}
    return next((level for level in reversed(LEVELS) if level in labels), None)


def _metrics(vector: str | None) -> dict[str, str]:
    if not vector:
        return {}
    return dict(part.split(":", 1) for part in vector.split("/") if ":" in part)


def _exploitation(finding: Finding, policy: RiskPolicy) -> Exploitation:
    if finding.known_exploited:
        return Exploitation.ACTIVE
    epss, percentile = finding.epss, finding.epss_percentile
    if epss is None and percentile is None:
        return Exploitation.UNKNOWN
    over_epss = (epss or 0) >= policy.epss_threshold
    if over_epss or (percentile or 0) >= policy.epss_percentile_threshold:
        return Exploitation.LIKELY
    return Exploitation.NONE


def _exposure(finding: Finding, dev: bool | None) -> Exposure:
    if dev is True:
        return Exposure.SMALL
    reach = finding.relevance.reachability if finding.relevance else Reachability.UNKNOWN
    return Exposure.OPEN if dev is False and reach == Reachability.CONFIRMED else Exposure.LIMITED


def _automatable(vector: str | None) -> Automatable:
    metrics = _metrics(vector)
    if not metrics:
        return Automatable.UNKNOWN
    network = metrics.get("AV") == "N" and metrics.get("UI") == "N"
    return Automatable.YES if network else Automatable.NO


def _impact(vector: str | None, severity: RiskLevel | None) -> TechnicalImpact:
    metrics = _metrics(vector)
    high = severity in {RiskLevel.CRITICAL, RiskLevel.HIGH} or any(
        metrics.get(key) == "H" for key in IMPACT_METRICS
    )
    return TechnicalImpact.TOTAL if high else TechnicalImpact.PARTIAL


def _decide(exploit: Exploitation, exposure: Exposure, impact: TechnicalImpact) -> SsvcDecision:
    production = exposure != Exposure.SMALL
    total = impact == TechnicalImpact.TOTAL
    if exploit == Exploitation.ACTIVE:
        return SsvcDecision.ACT if production else SsvcDecision.ATTEND
    if exploit == Exploitation.LIKELY:
        return SsvcDecision.ATTEND if production and total else SsvcDecision.TRACK_STAR
    if exploit == Exploitation.NONE:
        return SsvcDecision.TRACK_STAR if production and total else SsvcDecision.TRACK
    if production:
        return SsvcDecision.ATTEND if total else SsvcDecision.TRACK_STAR
    return SsvcDecision.TRACK_STAR if total else SsvcDecision.TRACK


def _score(base: float, percentile: float | None, exposure: Exposure, policy: RiskPolicy) -> int:
    """0-100: base CVSS x10 x ((1-w)+w*EPSS percentile, 0.5 if unknown) x exposure factor."""
    weight = policy.epss_weight
    pct = 0.5 if percentile is None else percentile
    factor: float = getattr(policy.exposure_factor, exposure.value)
    return round(min(100.0, base * 10 * ((1 - weight) + weight * pct) * factor))


def _ordinal(number: int) -> str:
    if 10 <= number % 100 <= 20:
        return f"{number}th"
    return f"{number}{ {1: 'st', 2: 'nd', 3: 'rd'}.get(number % 10, 'th') }"


def _scope_reason(dev: bool | None) -> str:
    if dev is None:
        return "scope unknown (treated as production)"
    return "development dependency" if dev else "production dependency"


def _vuln_reasons(
    f: Finding, severity: RiskLevel | None, dev: bool | None, signals: _Signals
) -> list[str]:
    reasons: list[str] = []
    if f.known_exploited:
        reasons.append("in CISA KEV")
    if f.epss is not None:
        pct = f" ({_ordinal(round((f.epss_percentile or 0) * 100))} percentile)" if (
            f.epss_percentile is not None
        ) else ""
        reasons.append(f"EPSS {f.epss:.2f}{pct}")
    if f.epss is None and not f.known_exploited:
        reasons.append("no exploitation data available (treated conservatively)")
    reasons.append(_scope_reason(dev))
    if signals.exposure == Exposure.OPEN:
        reasons.append("imported by application code")
    if signals.automatable == Automatable.YES:
        reasons.append("network-exploitable without user interaction")
    if signals.impact == TechnicalImpact.TOTAL:
        label = severity.value if severity else "per CVSS"
        reasons.append(f"high technical impact (severity {label})")
    return reasons


def _vulnerability(f: Finding, dev: bool | None, policy: RiskPolicy) -> dict[str, object]:
    severity = _highest_severity(f)
    exploit = _exploitation(f, policy)
    exposure = _exposure(f, dev)
    impact = _impact(f.cvss_vector, severity)
    decision = _decide(exploit, exposure, impact)
    base = f.cvss_score or SEVERITY_BASE.get(severity or RiskLevel.MEDIUM, 5.5)
    percentile = 1.0 if exploit == Exploitation.ACTIVE else f.epss_percentile
    automatable = _automatable(f.cvss_vector)
    signals = _Signals(exposure, automatable, impact)
    state = FindingState.AFFECTED if severity or f.cvss_vector else FindingState.UNDER_INVESTIGATION
    return {
        "exploitation": exploit, "exposure": exposure, "automatable": automatable,
        "technical_impact": impact, "ssvc_decision": decision,
        "risk_score": _score(base, percentile, exposure, policy),
        "risk_reasons": _vuln_reasons(f, severity, dev, signals), "state": state,
        "risk_rule_id": DECISION_RULE[decision], "risk_level": DECISION_LEVEL[decision],
    }


def _malicious(dev: bool | None) -> dict[str, object]:
    return {
        "exploitation": Exploitation.ACTIVE, "exposure": _exposure_for_scope(dev),
        "ssvc_decision": SsvcDecision.ACT, "risk_score": 100, "state": FindingState.AFFECTED,
        "risk_reasons": ["known malicious package", _scope_reason(dev)],
        "risk_rule_id": "R-MAL", "risk_level": RiskLevel.CRITICAL,
    }


def _exposure_for_scope(dev: bool | None) -> Exposure:
    return Exposure.SMALL if dev is True else Exposure.LIMITED


def _anomaly_rule(finding: Finding) -> tuple[str, RiskLevel]:
    kind = finding.anomaly_type
    if kind in {"suspected_typosquat", "install_script_change", "unverified_install_script"}:
        return "R-AN-1", RiskLevel.HIGH
    if kind == "unexpected_dependency" or (
        kind == "unpinned_base_image" and finding.image_tag in {None, "", "latest", UNKNOWN}
    ):
        return "R-AN-2", RiskLevel.MEDIUM
    if kind in {"dependency_update", "unpinned_ci_action", "unpinned_base_image"}:
        return "R-AN-3", RiskLevel.LOW
    raise ValueError(f"No configured risk rule for anomaly {kind!r}")


def _anomaly(f: Finding, dev: bool | None, policy: RiskPolicy) -> dict[str, object]:
    rule, level = _anomaly_rule(f)
    exposure = _exposure_for_scope(dev)
    exploit = (
        Exploitation.LIKELY if f.anomaly_type in EXPLOIT_LIKELY_ANOMALIES else Exploitation.UNKNOWN
    )
    return {
        "exploitation": exploit, "exposure": exposure, "ssvc_decision": LEVEL_DECISION[level],
        "risk_score": _score(SEVERITY_BASE[level], None, exposure, policy),
        "risk_reasons": [ANOMALY_REASONS.get(str(f.anomaly_type), "supply-chain anomaly"),
                         _scope_reason(dev)],
        "state": FindingState.UNDER_INVESTIGATION, "risk_rule_id": rule, "risk_level": level,
    }


def _confidence(finding: Finding) -> Confidence:
    if finding.match_basis == "cpe":
        return Confidence.LOW
    if finding.match_basis == "purl" and {"grype", "osv"} <= set(finding.confirmed_by):
        return Confidence.HIGH
    return Confidence.MEDIUM


def assess(finding: Finding, *, dev: bool | None, policy: RiskPolicy) -> Finding:
    if finding.kind == "malicious":
        update = _malicious(dev)
    elif finding.kind == "vulnerability":
        update = _vulnerability(finding, dev, policy)
    else:
        update = _anomaly(finding, dev, policy)
    return finding.model_copy(update={**update, "confidence": _confidence(finding)})
