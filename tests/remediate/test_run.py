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
from guardian.remediate.app_run import AppRun
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


def _with_app(app: AppRun) -> FixRun:
    return FixRun(scan_id="s", proposal=_proposal(), build=StepResult(status="passed"),
                  diff=RescanDiff(counts_before={}, counts_after={}),
                  tests=TestRun(status="passed", passed=7, total=7), app_run=app)


def test_a_running_app_adds_the_health_and_image_scan_lines() -> None:
    run = _with_app(AppRun(
        status="passed", health_url="http://127.0.0.1:49153/health", http_status=200,
        image_vulns={"critical": 1, "high": 2, "medium": 4}, image_only_serious=2))
    assert failure_summary(run) is None
    assert verification_summary(run).endswith(
        "Tests passed (7 of 7). App started in a container and answered /health with 200. "
        "Image scan: 1 critical, 2 high (2 from the base image).")


def test_an_unscanned_image_is_named_in_the_summary() -> None:
    run = _with_app(AppRun(
        status="passed", health_url="http://127.0.0.1:1/health", http_status=200,
        image_error="image scan failed: db missing"))
    assert verification_summary(run).endswith(
        "answered /health with 200. Image scan unavailable: image scan failed: db missing.")


def test_an_app_that_did_not_start_is_not_safe_to_apply() -> None:
    run = _with_app(AppRun(status="failed", reason="image build failed: boom"))
    assert failure_summary(run) == "App did not start: image build failed: boom; not safe to apply."


def test_an_app_run_that_was_not_run_is_left_out_of_the_summary() -> None:
    run = _with_app(AppRun(status="not_run", reason="no Dockerfile"))
    assert failure_summary(run) is None
    assert verification_summary(run).endswith("Tests passed (7 of 7).")
