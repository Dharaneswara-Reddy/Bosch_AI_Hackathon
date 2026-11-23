"""Deterministic risk classification for scanner and detector findings."""

from guardian.models import UNKNOWN, Confidence, Finding, FindingState, RiskLevel

LEVELS = (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
CVE_RULES = {
    RiskLevel.CRITICAL: "R-CVE-1",
    RiskLevel.HIGH: "R-CVE-2",
    RiskLevel.MEDIUM: "R-CVE-3",
    RiskLevel.LOW: "R-CVE-4",
}


def _rule(finding: Finding) -> tuple[str, RiskLevel, FindingState]:
    affected = FindingState.AFFECTED
    investigation = FindingState.UNDER_INVESTIGATION
    if finding.kind == "malicious":
        return "R-MAL", RiskLevel.CRITICAL, affected
    if finding.kind == "vulnerability":
        severities = [finding.source_severity, *finding.severities.values()]
        normalized = {severity.strip().lower() for severity in severities}
        for level in reversed(LEVELS):
            if level in normalized:
                return CVE_RULES[level], level, affected
        return "R-CVE-U", RiskLevel.MEDIUM, investigation
    kind = finding.anomaly_type
    if kind in {"suspected_typosquat", "install_script_change"}:
        return "R-AN-1", RiskLevel.HIGH, investigation
    if kind == "unexpected_dependency" or (
        kind == "unpinned_base_image" and finding.image_tag in {None, "", "latest", UNKNOWN}
    ):
        return "R-AN-2", RiskLevel.MEDIUM, investigation
    if kind in {"dependency_update", "unpinned_ci_action", "unpinned_base_image"}:
        return "R-AN-3", RiskLevel.LOW, investigation
    raise ValueError(f"No configured risk rule for anomaly {kind!r}")


def assess(finding: Finding, *, dev: bool | None = None) -> Finding:
    rule, level, state = _rule(finding)
    note = None
    if dev is True and level != RiskLevel.LOW:
        level = LEVELS[LEVELS.index(level) - 1]
        note = "Risk lowered one level for a development dependency."
    confidence = Confidence.MEDIUM
    if finding.match_basis == "cpe":
        confidence = Confidence.LOW
    elif finding.match_basis == "purl" and {"grype", "osv"} <= set(finding.confirmed_by):
        confidence = Confidence.HIGH
    return finding.model_copy(update={
        "risk_rule_id": rule, "risk_level": level, "state": state,
        "confidence": confidence, "risk_note": note,
    })
