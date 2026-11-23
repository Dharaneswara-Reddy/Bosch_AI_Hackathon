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
)
from guardian.remediate.diff import FindingRef, RescanDiff
from guardian.remediate.run import (
    FixPlanError,
    FixRun,
    FixStatus,
    failure_summary,
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


def _failed_tests(**extra: object) -> TestRun:
    return TestRun(status="failed", passed=1, failed=2, total=3,
                   failed_tests=["auth rejects a missing token", "server answers"], **extra)


def test_failing_tests_make_the_summary_say_not_safe_to_apply() -> None:
    diff = RescanDiff(counts_before={}, counts_after={}, fixed=[_ref("CVE-1", RiskLevel.HIGH)])
    run = FixRun(scan_id="s", proposal=_proposal(), diff=diff, build=StepResult(status="passed"),
                 tests=_failed_tests())
    assert failure_summary(run) == (
        "Tests failed: 2 of 3 — the upgrade breaks auth rejects a missing token, "
        "server answers; not safe to apply.")
    assert verification_summary(run).startswith("Tests failed: 2 of 3 — the upgrade breaks")
    assert "Fixed 1 High (CVE-1)" in verification_summary(run)


def test_a_failing_application_build_is_not_safe_to_apply() -> None:
    run = FixRun(scan_id="s", proposal=_proposal(),
                 app_build=TestRun(status="failed", reason="npm run build failed (exit 2)"))
    assert failure_summary(run) == "Build failed: npm run build failed (exit 2); not safe to apply."


def test_a_passing_run_has_no_failure_summary_and_reports_counts() -> None:
    diff = RescanDiff(counts_before={}, counts_after={})
    run = FixRun(scan_id="s", proposal=_proposal(), diff=diff, build=StepResult(status="passed"),
                 app_build=TestRun(status="passed"),
                 tests=TestRun(status="passed", passed=7, total=7))
    assert failure_summary(run) is None
    assert verification_summary(run) == (
        "No findings were fixed. No new findings. Build check passed. Build passed. "
        "Tests passed (7 of 7).")
