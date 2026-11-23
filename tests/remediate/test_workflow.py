import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from langgraph.checkpoint.memory import MemorySaver

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
from guardian.remediate.run import Decision, FixStatus, load_fix
from guardian.remediate.sandbox import CommandResult
from guardian.remediate.workflow import (
    FixDeps,
    build_fix_graph,
    is_waiting,
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
    def __init__(self, work_dir: Path, ecosystem_ok: bool = True) -> None:
        self.work_dir = work_dir
        self.commands: list[list[str]] = []
        self.scanned: list[Path] = []
        self.fail_resolution = False
        repo = work_dir / "repo"
        repo.mkdir(parents=True)
        (repo / "package.json").write_text(
            json.dumps({"dependencies": {"lodash": "4.17.4"}}), encoding="utf-8")
        _write_out(work_dir / "out", _run("4.17.4", with_finding=True))
        self.graph = build_fix_graph(
            work_dir, MemorySaver(), FixDeps(runner=self.command, scan=self.scan, engine=None))

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
