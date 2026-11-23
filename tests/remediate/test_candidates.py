from guardian.models import (
    Component,
    Finding,
    FindingKind,
    FixAction,
    GraphArtifact,
    RemediationProposal,
    RiskLevel,
    RunResult,
    Scan,
    Scope,
)
from guardian.remediate.candidates import merge_proposals, rule_based_proposals


def _component(name: str, version: str, scope: Scope = Scope.DIRECT) -> Component:
    purl = f"pkg:npm/{name}@{version}"
    return Component(component_id=purl, purl=purl, name=name, version=version, ecosystem="npm",
                     scope=scope)


def _vuln(fid: str, component: Component, fixed: list[str], level: RiskLevel,
          advisory: str = "CVE-1") -> Finding:
    return Finding(
        finding_id=fid, kind=FindingKind.VULNERABILITY, component_id=component.component_id,
        purl=component.purl, advisory_id=advisory, fixed_versions=fixed, risk_level=level,
        evidence_ids=["ev1"])


def _run(components: list[Component], findings: list[Finding]) -> RunResult:
    from datetime import UTC, datetime

    return RunResult(scan=Scan(scan_id="s", target="t", started_at=datetime.now(UTC)),
                     graph=GraphArtifact(nodes=components), findings=findings)


def test_direct_vulnerable_package_gets_a_validated_upgrade() -> None:
    lodash = _component("lodash", "4.17.4")
    run = _run([lodash], [_vuln("f1", lodash, ["4.17.21"], RiskLevel.HIGH, "CVE-2021-23337")])
    [proposal] = rule_based_proposals(run)
    assert proposal.action is FixAction.UPGRADE
    assert proposal.target_version == "4.17.21"
    assert proposal.finding_id == "f1"
    assert proposal.validated and proposal.requires_human_approval
    assert "CVE-2021-23337" in proposal.rationale
    assert proposal.rollback == "Revert lodash to 4.17.4."
    assert proposal.evidence_ids == ["ev1"]


def test_one_proposal_per_package_targets_a_version_that_fixes_every_finding() -> None:
    lodash = _component("lodash", "4.17.4")
    run = _run([lodash], [
        _vuln("low", lodash, ["4.17.5"], RiskLevel.LOW, "CVE-A"),
        _vuln("top", lodash, ["4.17.21"], RiskLevel.HIGH, "CVE-B"),
    ])
    [proposal] = rule_based_proposals(run)
    assert (proposal.finding_id, proposal.target_version) == ("top", "4.17.21")
    assert "CVE-A" in proposal.rationale and "CVE-B" in proposal.rationale


def test_same_major_fix_is_preferred_and_major_jump_is_flagged() -> None:
    a = _component("a", "1.0.0")
    b = _component("b", "1.0.0")
    run = _run([a, b], [
        _vuln("fa", a, ["2.0.0", "1.2.3"], RiskLevel.HIGH),
        _vuln("fb", b, ["3.0.0"], RiskLevel.HIGH),
    ])
    by_finding = {p.finding_id: p for p in rule_based_proposals(run)}
    assert by_finding["fa"].target_version == "1.2.3"
    assert by_finding["fa"].breaking_change_risk == "low"
    assert by_finding["fb"].breaking_change_risk == "medium"


def test_transitive_or_unfixable_findings_get_no_rule_based_proposal() -> None:
    inner = _component("inner", "1.0.0", Scope.TRANSITIVE)
    nofix = _component("nofix", "1.0.0")
    run = _run([inner, nofix], [
        _vuln("f1", inner, ["2.0.0"], RiskLevel.HIGH),
        _vuln("f2", nofix, [], RiskLevel.HIGH),
    ])
    assert rule_based_proposals(run) == []


def test_ai_proposal_takes_precedence_for_the_same_finding() -> None:
    lodash = _component("lodash", "4.17.4")
    run = _run([lodash], [_vuln("f1", lodash, ["4.17.21"], RiskLevel.HIGH)])
    ai = RemediationProposal(
        proposal_id="ai-1", finding_id="f1", action=FixAction.UPGRADE, target_version="4.17.21",
        rationale="AI rationale.", rollback="Revert.", breaking_change_risk="low", evidence_ids=[],
        validated=True,
    )
    merged = merge_proposals([ai], rule_based_proposals(run))
    assert merged == [ai]
    other = _vuln("f2", lodash, ["4.17.21"], RiskLevel.LOW)
    run.findings.append(other)
    assert len(merge_proposals([ai], rule_based_proposals(run))) == 1
