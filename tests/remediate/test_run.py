from datetime import UTC, datetime
from pathlib import Path

import pytest

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
from guardian.remediate.diff import FindingRef, RescanDiff
from guardian.remediate.run import (
    FixPlanError,
    FixRun,
    FixStatus,
    load_fix,
    resolve_target,
    save_fix,
    verification_summary,
)
from guardian.remediate.sandbox import StepResult, TestRun


def _proposal(
    action: FixAction = FixAction.UPGRADE, target: str | None = "2.0.0"
) -> RemediationProposal:
    return RemediationProposal(
        proposal_id="p1", finding_id="f1", action=action, target_version=target, rationale="r",
        rollback="b", breaking_change_risk="low", evidence_ids=[])


def _result(kind: FindingKind = FindingKind.VULNERABILITY) -> RunResult:
    node = Component(component_id="c1", purl="pkg:npm/lib@1.0.0", name="lib", version="1.0.0",
                     ecosystem="npm")
    finding = Finding(finding_id="f1", kind=kind, component_id="c1", purl=node.purl)
    return RunResult(scan=Scan(scan_id="s", target="t", started_at=datetime.now(UTC)),
                     graph=GraphArtifact(nodes=[node]), findings=[finding])


def test_resolve_target_names_package_and_versions() -> None:
    target = resolve_target(_proposal(), _result())
    assert (target.ecosystem, target.package, target.from_version, target.to_version) == (
        "npm", "lib", "1.0.0", "2.0.0")


@pytest.mark.parametrize("proposal", [
    _proposal(FixAction.REMOVE_DEPENDENCY, None),
    _proposal(FixAction.UPGRADE, None),
    _proposal().model_copy(update={"finding_id": "missing"}),
])
def test_resolve_target_rejects_proposals_that_cannot_be_applied(
    proposal: RemediationProposal,
) -> None:
    with pytest.raises(FixPlanError):
        resolve_target(proposal, _result())


def test_fix_run_round_trips_through_fix_json(tmp_path: Path) -> None:
    run = FixRun(scan_id="s", proposal=_proposal(), status=FixStatus.AWAITING_APPROVAL)
    save_fix(tmp_path, run)
    assert (tmp_path / "fixes" / "p1" / "fix.json").is_file()
    assert load_fix(tmp_path, "p1") == run
    assert load_fix(tmp_path, "other") is None


def _ref(advisory: str, level: RiskLevel) -> FindingRef:
    return FindingRef(finding_id=advisory, advisory_id=advisory, package="lib", version="1",
                      risk_level=level)


def test_summary_is_plain_english_and_deterministic() -> None:
    diff = RescanDiff(counts_before={}, counts_after={},
                      fixed=[_ref("CVE-1", RiskLevel.HIGH), _ref("CVE-2", RiskLevel.HIGH)])
    run = FixRun(
        scan_id="s", proposal=_proposal(), status=FixStatus.VERIFIED, diff=diff,
        build=StepResult(status="passed"),
        tests=TestRun(status="not_run", reason="only manifests were fetched; no source to test"),
    )
    assert verification_summary(run) == (
        "Fixed 2 High (CVE-1, CVE-2). No new findings. Build check passed. "
        "Tests not run: only manifests were fetched; no source to test.")


def test_summary_mentions_new_findings_and_failed_build() -> None:
    diff = RescanDiff(counts_before={}, counts_after={},
                      introduced=[_ref("CVE-9", RiskLevel.CRITICAL)])
    run = FixRun(scan_id="s", proposal=_proposal(), status=FixStatus.VERIFIED, diff=diff,
                 build=StepResult(status="failed", detail="ETARGET"),
                 tests=TestRun(status="passed"))
    assert verification_summary(run) == (
        "No findings were fixed. Introduced 1 new finding: 1 Critical (CVE-9). "
        "Build check failed: ETARGET. Tests passed.")


def _transitive_result() -> RunResult:
    nodes = [
        Component(component_id="root", purl="pkg:npm/app@1", name="app", version="1",
                  ecosystem="npm", scope=Scope.DIRECT),
        Component(component_id="parent", purl="pkg:npm/ej@0.1.3", name="ej", version="0.1.3",
                  ecosystem="npm", scope=Scope.DIRECT),
        Component(component_id="child", purl="pkg:npm/jws@0.2.6", name="jws", version="0.2.6",
                  ecosystem="npm", scope=Scope.TRANSITIVE),
    ]
    finding = Finding(finding_id="f1", kind=FindingKind.VULNERABILITY, component_id="child",
                      purl="pkg:npm/jws@0.2.6", dependency_path=["root", "parent", "child"])
    return RunResult(scan=Scan(scan_id="s", target="t", started_at=datetime.now(UTC)),
                     graph=GraphArtifact(nodes=nodes), findings=[finding])


@pytest.mark.parametrize("action", [FixAction.PIN_VERSION, FixAction.UPGRADE])
def test_resolve_target_names_the_direct_parent_of_a_transitive_package(
    action: FixAction,
) -> None:
    target = resolve_target(_proposal(action, "3.2.3"), _transitive_result())
    assert (target.package, target.from_version, target.to_version) == ("jws", "0.2.6", "3.2.3")
    assert (target.transitive, target.parent, target.parent_version) == (True, "ej", "0.1.3")


def test_resolve_target_has_no_parent_for_a_direct_package() -> None:
    target = resolve_target(_proposal(FixAction.PIN_VERSION), _result())
    assert not target.transitive and target.parent is None and target.package == "lib"


def test_resolve_target_still_refuses_an_ai_parent_upgrade_without_a_package() -> None:
    with pytest.raises(FixPlanError):
        resolve_target(_proposal(FixAction.UPGRADE_PARENT), _transitive_result())
