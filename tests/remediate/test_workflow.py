import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from langgraph.checkpoint.memory import MemorySaver

from guardian.fetch import MANIFEST_NAME, FetchResult
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
from guardian.remediate.app_run import AppRun, run_application
from guardian.remediate.run import Decision, FixRun, FixStatus, load_fix
from guardian.remediate.sandbox import CommandResult, Runner
from guardian.remediate.workflow import (
    AppFn,
    FixDeps,
    build_fix_graph,
    is_waiting,
    open_checkpointer,
    resume_fix,
    start_fix,
)

SCAN_ID = "scan1"


def _run(version: str, with_finding: bool) -> RunResult:
    purl = f"pkg:npm/lodash@{version}"
    node = Component(component_id=purl, purl=purl, name="lodash", version=version,
                     ecosystem="npm", scope=Scope.DIRECT)
    findings = [Finding(
        finding_id="f1", kind=FindingKind.VULNERABILITY, component_id=purl, purl=purl,
        advisory_id="CVE-2021-23337", risk_level=RiskLevel.HIGH, fixed_versions=["4.17.21"],
    )] if with_finding else []
    return RunResult(scan=Scan(scan_id="s", target="t", started_at=datetime.now(UTC)),
                     graph=GraphArtifact(nodes=[node]), findings=findings)


def _write_out(out: Path, run: RunResult) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "run.json").write_text(run.scan.model_dump_json(), encoding="utf-8")
    (out / "coverage.json").write_text(run.coverage.model_dump_json(), encoding="utf-8")
    (out / "graph.json").write_text(run.graph.model_dump_json(), encoding="utf-8")
    (out / "findings.json").write_text(
        json.dumps({"findings": [f.model_dump(mode="json") for f in run.findings]}),
        encoding="utf-8")


class Harness:
    def __init__(
        self, work_dir: Path, engine: str | None = None, app: AppFn | None = None
    ) -> None:
        self.work_dir = work_dir
        self.container_results: list[CommandResult] = []
        self.container_calls: list[list[str]] = []
        self.commands: list[list[str]] = []
        self.scanned: list[Path] = []
        self.fail_resolution = False
        repo = work_dir / "repo"
        repo.mkdir(parents=True)
        (repo / "package.json").write_text(
            json.dumps({"dependencies": {"lodash": "4.17.4"}}), encoding="utf-8")
        _write_out(work_dir / "out", _run("4.17.4", with_finding=True))
        self.graph = build_fix_graph(
            work_dir, MemorySaver(),
            FixDeps(runner=self.command, scan=self.scan, engine=engine, capture=self.capture,
                    app=app or run_application))

    def capture(self, command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
        self.container_calls.append(list(command))
        return self.container_results.pop(0) if self.container_results else CommandResult(0, "")

    def add_project_with_scripts(self) -> None:
        repo = self.work_dir / "repo"
        (repo / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "4.17.4"},
            "scripts": {"build": "node build.js", "test": "node --test"}}), encoding="utf-8")
        (repo / "app.js").write_text("module.exports = 1", encoding="utf-8")

    def command(self, command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
        self.commands.append(list(command))
        if self.fail_resolution:
            return CommandResult(1, "ETARGET")
        (cwd / "package-lock.json").write_text("{}", encoding="utf-8")
        return CommandResult(0, "")

    def scan(self, target: Path, out: Path) -> RunResult:
        self.scanned.append(target)
        result = _run("4.17.21", with_finding=False)
        _write_out(out, result)
        return result

    def proposal(self, action: FixAction = FixAction.UPGRADE) -> RemediationProposal:
        return RemediationProposal(
            proposal_id="p1", finding_id="f1", action=action, target_version="4.17.21",
            rationale="r", rollback="b", breaking_change_risk="low", evidence_ids=[],
            validated=True)

    def repo_manifest(self) -> str:
        return (self.work_dir / "repo" / "package.json").read_text(encoding="utf-8")


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path / "scan")


def test_nothing_is_applied_before_approval(harness: Harness) -> None:
    run = start_fix(harness.graph, SCAN_ID, harness.proposal())
    assert run.status is FixStatus.AWAITING_APPROVAL
    assert run.target is not None and run.target.package == "lodash"
    assert is_waiting(harness.graph, SCAN_ID, "p1")
    assert harness.commands == [] and harness.scanned == []
    assert not (harness.work_dir / "fixes" / "p1" / "sandbox").exists()
    stored = load_fix(harness.work_dir, "p1")
    assert stored is not None and stored.status is FixStatus.AWAITING_APPROVAL


def test_rejection_records_the_reviewer_and_changes_nothing(harness: Harness) -> None:
    start_fix(harness.graph, SCAN_ID, harness.proposal())
    run = resume_fix(harness.graph, SCAN_ID, "p1", Decision(
        approved=False, reviewer="ana", note="too risky before release"))
    assert run.status is FixStatus.REJECTED
    assert run.decision is not None and run.decision.reviewer == "ana"
    assert "ana" in run.summary and "too risky before release" in run.summary
    assert harness.commands == [] and harness.scanned == []
    assert not is_waiting(harness.graph, SCAN_ID, "p1")
    stored = load_fix(harness.work_dir, "p1")
    assert stored is not None and stored.status is FixStatus.REJECTED


def test_approval_applies_in_a_sandbox_rescans_and_diffs(harness: Harness) -> None:
    original = harness.repo_manifest()
    start_fix(harness.graph, SCAN_ID, harness.proposal())
    run = resume_fix(harness.graph, SCAN_ID, "p1", Decision(approved=True, reviewer="ana"))
    sandbox = harness.work_dir / "fixes" / "p1" / "sandbox"
    assert run.status is FixStatus.VERIFIED, run.error
    assert json.loads((sandbox / "package.json").read_text())["dependencies"]["lodash"] == "4.17.21"
    assert harness.repo_manifest() == original
    assert harness.scanned == [sandbox]
    assert (harness.work_dir / "fixes" / "p1" / "out" / "findings.json").is_file()
    assert run.diff is not None and [f.advisory_id for f in run.diff.fixed] == ["CVE-2021-23337"]
    assert run.build is not None and run.build.status == "passed"
    assert run.tests is not None and run.tests.status == "not_run"
    assert run.summary == (
        "Fixed 1 High (CVE-2021-23337). No new findings. Build check passed. "
        "Tests not run: only manifests were fetched; no source to test.")
    stored = load_fix(harness.work_dir, "p1")
    assert stored is not None and stored.status is FixStatus.VERIFIED


def test_failed_resolution_stops_before_the_rescan(harness: Harness) -> None:
    harness.fail_resolution = True
    start_fix(harness.graph, SCAN_ID, harness.proposal())
    run = resume_fix(harness.graph, SCAN_ID, "p1", Decision(approved=True, reviewer="ana"))
    assert run.status is FixStatus.FAILED
    assert run.error is not None and "ETARGET" in run.error
    assert harness.scanned == []


def test_unplannable_proposal_fails_at_start_without_waiting(harness: Harness) -> None:
    run = start_fix(harness.graph, SCAN_ID,
                    harness.proposal(FixAction.REMOVE_DEPENDENCY))
    assert run.status is FixStatus.FAILED
    assert run.error is not None and "manually" in run.error
    assert not is_waiting(harness.graph, SCAN_ID, "p1")


def test_unsupported_ecosystem_is_reported_after_approval(harness: Harness) -> None:
    purl = "pkg:cargo/serde@1.0.0"
    node = Component(component_id=purl, purl=purl, name="serde", version="1.0.0",
                     ecosystem="cargo", scope=Scope.DIRECT)
    run = _run("1", with_finding=True)
    run.graph = GraphArtifact(nodes=[node])
    run.findings[0].component_id = purl
    run.findings[0].purl = purl
    _write_out(harness.work_dir / "out", run)
    start_fix(harness.graph, SCAN_ID, harness.proposal())
    done = resume_fix(harness.graph, SCAN_ID, "p1", Decision(approved=True, reviewer="ana"))
    assert done.status is FixStatus.FAILED
    assert done.apply is not None and done.apply.status == "unsupported"
    assert harness.scanned == []


def test_a_pending_approval_survives_a_restart(tmp_path: Path) -> None:
    db = tmp_path / "checkpoints.sqlite"
    first = Harness(tmp_path / "scan")
    first.graph = build_fix_graph(
        first.work_dir, open_checkpointer(db),
        FixDeps(runner=first.command, scan=first.scan, engine=None))
    start_fix(first.graph, SCAN_ID, first.proposal())

    restarted = build_fix_graph(
        first.work_dir, open_checkpointer(db),
        FixDeps(runner=first.command, scan=first.scan, engine=None))
    assert is_waiting(restarted, SCAN_ID, "p1")
    run = resume_fix(restarted, SCAN_ID, "p1", Decision(approved=True, reviewer="ana"))
    assert run.status is FixStatus.VERIFIED, run.error


TAP_FAIL = "not ok 1 - auth rejects a missing token\nok 2 - lodash\n# tests 2\n# pass 1\n# fail 1\n"


def _approve(harness: Harness) -> FixRun:
    start_fix(harness.graph, SCAN_ID, harness.proposal())
    return resume_fix(harness.graph, SCAN_ID, "p1", Decision(approved=True, reviewer="ana"))


def test_failing_tests_mark_the_fix_failed_but_keep_the_rescan(tmp_path: Path) -> None:
    harness = Harness(tmp_path / "scan", engine="docker")
    harness.add_project_with_scripts()
    harness.container_results = [CommandResult(0, ""), CommandResult(0, ""),
        CommandResult(0, "built"), CommandResult(0, ""), CommandResult(1, TAP_FAIL),
        CommandResult(0, "")]
    run = _approve(harness)
    assert run.status is FixStatus.FAILED
    assert run.summary.startswith(
        "Tests failed: 1 of 2 — the upgrade breaks auth rejects a missing token; "
        "not safe to apply.")
    assert run.diff is not None and [f.advisory_id for f in run.diff.fixed] == ["CVE-2021-23337"]
    assert run.app_build is not None and run.app_build.status == "passed"
    stored = load_fix(harness.work_dir, "p1")
    assert stored is not None and stored.status is FixStatus.FAILED


def test_passing_build_and_tests_verify_the_fix(tmp_path: Path) -> None:
    harness = Harness(tmp_path / "scan", engine="docker")
    harness.add_project_with_scripts()
    harness.container_results = [CommandResult(0, ""), CommandResult(0, ""),
        CommandResult(0, "built"), CommandResult(0, ""),
        CommandResult(0, "# tests 7\n# pass 7\n# fail 0\n"), CommandResult(0, "")]
    run = _approve(harness)
    assert run.status is FixStatus.VERIFIED, run.error
    assert run.tests is not None and (run.tests.passed, run.tests.total) == (7, 7)
    assert run.summary.endswith("Build check passed. Build passed. Tests passed (7 of 7).")
    assert run.source is not None and run.source.status == "unsupported"


def test_a_failed_source_clone_is_named_in_the_tests_not_run_reason(tmp_path: Path) -> None:
    harness = Harness(tmp_path / "scan", engine="docker")
    manifest = FetchResult(url="https://github.com/acme/shop", ref="main",
                           commit_sha="b" * 40, dest=harness.work_dir / "repo")
    (harness.work_dir / MANIFEST_NAME).write_text(manifest.model_dump_json(), encoding="utf-8")
    harness.container_results = [CommandResult(128, "fatal: repository not found")]
    run = _approve(harness)
    assert run.status is FixStatus.VERIFIED, run.error
    assert run.source is not None and run.source.status == "failed"
    assert run.tests is not None and run.tests.status == "not_run"
    assert "repository not found" in run.tests.reason


def _transitive_scan(harness: Harness) -> None:
    nodes = [
        Component(component_id="parent", purl="pkg:npm/ej@0.1.3", name="ej", version="0.1.3",
                  ecosystem="npm", scope=Scope.DIRECT),
        Component(component_id="child", purl="pkg:npm/jws@0.2.6", name="jws", version="0.2.6",
                  ecosystem="npm", scope=Scope.TRANSITIVE),
    ]
    finding = Finding(finding_id="f1", kind=FindingKind.VULNERABILITY, component_id="child",
                      purl="pkg:npm/jws@0.2.6", dependency_path=["root", "parent", "child"],
                      fixed_versions=["3.2.3"], risk_level=RiskLevel.HIGH)
    base = _run("1", with_finding=False)
    base.graph = GraphArtifact(nodes=nodes)
    base.findings = [finding]
    _write_out(harness.work_dir / "out", base)
    (harness.work_dir / "repo" / "package.json").write_text(
        json.dumps({"dependencies": {"ej": "0.1.3"}}), encoding="utf-8")


def _approve_transitive(tmp_path: Path, lookup: Callable[[str, str, str, str], str | None]) -> str:
    harness = Harness(tmp_path / "scan")
    _transitive_scan(harness)
    deps = FixDeps(runner=harness.command, scan=harness.scan, engine=None, parent_lookup=lookup)
    graph = build_fix_graph(harness.work_dir, MemorySaver(), deps)
    proposal = harness.proposal(FixAction.PIN_VERSION).model_copy(
        update={"target_version": "3.2.3"})
    start_fix(graph, SCAN_ID, proposal)
    run = resume_fix(graph, SCAN_ID, "p1", Decision(approved=True, reviewer="ana"))
    assert run.status is FixStatus.VERIFIED, run.error
    assert run.apply is not None
    return (harness.work_dir / "fixes" / "p1" / "sandbox" / "package.json").read_text("utf-8")


def test_transitive_fix_applies_the_parent_upgrade_the_lookup_found(tmp_path: Path) -> None:
    manifest = json.loads(_approve_transitive(tmp_path, lambda *_: "7.7.8"))
    assert manifest["dependencies"]["ej"] == "7.7.8" and "overrides" not in manifest


def test_transitive_fix_falls_back_to_an_override(tmp_path: Path) -> None:
    manifest = json.loads(_approve_transitive(tmp_path, lambda *_: None))
    assert manifest["overrides"] == {"jws": "3.2.3"} and manifest["dependencies"]["ej"] == "0.1.3"


TESTS_OK = "# tests 7\n# pass 7\n# fail 0\n"


class FakeApp:
    def __init__(self, result: AppRun) -> None:
        self.result = result
        self.calls: list[tuple[Path, str, set[str]]] = []

    def __call__(
        self, root: Path, folder: Path, proposal_id: str, source_ids: set[str], capture: Runner,
        engine: str,
    ) -> AppRun:
        self.calls.append((root, proposal_id, source_ids))
        return self.result


def _app_harness(tmp_path: Path, app: FakeApp, tests_output: str = TESTS_OK) -> Harness:
    harness = Harness(tmp_path / "scan", engine="docker", app=app)
    harness.add_project_with_scripts()
    (harness.work_dir / "repo" / "Dockerfile").write_text("FROM node:20-slim\n", encoding="utf-8")
    harness.container_results = [CommandResult(0, ""), CommandResult(0, ""),
        CommandResult(0, "built"), CommandResult(0, ""),
        CommandResult(0 if tests_output == TESTS_OK else 1, tests_output), CommandResult(0, "")]
    return harness


def test_the_fixed_app_is_run_after_the_tests_and_summarised(tmp_path: Path) -> None:
    app = FakeApp(AppRun(status="passed", health_url="http://127.0.0.1:5/health", http_status=200,
                         image_vulns={"critical": 0, "high": 3}, image_only_serious=3))
    harness = _app_harness(tmp_path, app)
    run = _approve(harness)
    assert run.status is FixStatus.VERIFIED, run.error
    assert run.app_run is not None and run.app_run.http_status == 200
    sandbox = harness.work_dir / "fixes" / "p1" / "sandbox"
    assert [(call[0], call[1]) for call in app.calls] == [(sandbox, "p1")]
    assert run.summary.endswith(
        "App started in a container and answered /health with 200. "
        "Image scan: 0 critical, 3 high (3 from the base image).")
    stored = load_fix(harness.work_dir, "p1")
    assert stored is not None and stored.app_run is not None


def test_an_app_that_does_not_start_fails_the_fix_but_keeps_the_rescan(tmp_path: Path) -> None:
    app = FakeApp(AppRun(status="failed", reason="the container did not answer /health"))
    run = _approve(_app_harness(tmp_path, app))
    assert run.status is FixStatus.FAILED
    assert run.summary.startswith(
        "App did not start: the container did not answer /health; not safe to apply.")
    assert run.diff is not None and run.diff.fixed


def test_the_app_is_not_run_when_the_tests_failed(tmp_path: Path) -> None:
    app = FakeApp(AppRun(status="passed"))
    run = _approve(_app_harness(tmp_path, app, tests_output=TAP_FAIL))
    assert app.calls == []
    assert run.app_run is not None and run.app_run.status == "not_run"
    assert "tests did not pass" in run.app_run.reason


def test_the_app_is_not_run_without_a_dockerfile(tmp_path: Path) -> None:
    app = FakeApp(AppRun(status="passed"))
    harness = _app_harness(tmp_path, app)
    (harness.work_dir / "repo" / "Dockerfile").unlink()
    run = _approve(harness)
    assert app.calls == []
    assert run.app_run is not None and "no Dockerfile" in run.app_run.reason
    assert run.status is FixStatus.VERIFIED
