from datetime import UTC, datetime

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
from guardian.remediate.reduction import ExpectedReduction, expected_reduction

LODASH = Component(component_id="l", purl="pkg:npm/lodash@4.17.4", name="lodash",
                   version="4.17.4", ecosystem="npm", scope=Scope.DIRECT)
OTHER = Component(component_id="o", purl="pkg:npm/other@1.0.0", name="other", version="1.0.0",
                  ecosystem="npm", scope=Scope.TRANSITIVE)


def _finding(fid: str, component: Component, fixed: list[str], level: RiskLevel,
             advisory: str | None, kind: FindingKind = FindingKind.VULNERABILITY) -> Finding:
    return Finding(finding_id=fid, kind=kind, component_id=component.component_id,
                   purl=component.purl, advisory_id=advisory, fixed_versions=fixed,
                   risk_level=level)


def _proposal(finding_id: str, target: str | None, action: FixAction = FixAction.UPGRADE
              ) -> RemediationProposal:
    return RemediationProposal(
        proposal_id="p", finding_id=finding_id, action=action, target_version=target,
        rationale="r", rollback="b", breaking_change_risk="low", evidence_ids=[])


def _run(findings: list[Finding]) -> RunResult:
    return RunResult(scan=Scan(scan_id="s", target="t", started_at=datetime.now(UTC)),
                     graph=GraphArtifact(nodes=[LODASH, OTHER]), findings=findings)


def test_counts_the_findings_the_target_fixes_by_level_and_what_remains() -> None:
    run = _run([
        _finding("a", LODASH, ["4.17.5"], RiskLevel.HIGH, "CVE-A"),
        _finding("b", LODASH, ["4.17.12"], RiskLevel.HIGH, "CVE-B"),
        _finding("c", LODASH, ["4.17.19"], RiskLevel.MEDIUM, "CVE-C"),
        _finding("d", LODASH, ["4.18.0"], RiskLevel.CRITICAL, "CVE-D"),
        _finding("e", LODASH, [], RiskLevel.LOW, "CVE-E"),
        _finding("x", OTHER, ["2.0.0"], RiskLevel.HIGH, "CVE-X"),
    ])
    result = expected_reduction(_proposal("a", "4.17.21"), run)
    assert result == ExpectedReduction(
        fixes={"high": 2, "medium": 1}, finding_ids=["a", "b", "c"],
        advisories=["CVE-A", "CVE-B", "CVE-C"], remaining_on_package=2)


def test_a_target_is_checked_against_the_fixed_line_of_its_own_major() -> None:
    run = _run([_finding("a", LODASH, ["1.2.3", "2.0.5"], RiskLevel.HIGH, "CVE-A")])
    assert expected_reduction(_proposal("a", "2.0.0"), run) == ExpectedReduction(
        fixes={}, finding_ids=[], advisories=[], remaining_on_package=1)
    for target in ("2.0.5", "1.9.0"):
        result = expected_reduction(_proposal("a", target), run)
        assert result is not None and result.finding_ids == ["a"]


def test_transitive_override_counts_the_transitive_packages_findings() -> None:
    run = _run([_finding("x", OTHER, ["2.0.0"], RiskLevel.HIGH, "CVE-X")])
    result = expected_reduction(_proposal("x", "2.0.0", FixAction.PIN_VERSION), run)
    assert result is not None and result.fixes == {"high": 1}


def test_findings_without_an_advisory_still_count_and_are_not_listed() -> None:
    run = _run([_finding("a", LODASH, ["4.17.5"], RiskLevel.LOW, None)])
    result = expected_reduction(_proposal("a", "4.17.5"), run)
    assert result is not None and result.fixes == {"low": 1} and result.advisories == []


def test_no_expectation_without_a_target_or_a_vulnerability_finding() -> None:
    run = _run([_finding("m", LODASH, [], RiskLevel.HIGH, None, FindingKind.MALICIOUS)])
    assert expected_reduction(_proposal("m", "1.0.0"), run) is None
    assert expected_reduction(_proposal("m", None), run) is None
    assert expected_reduction(_proposal("missing", "1.0.0"), run) is None
