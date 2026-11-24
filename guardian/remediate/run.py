"""The persisted state of one fix: proposal, approval, sandbox steps and rescan result."""

import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel

from guardian.models import (
    Component,
    Finding,
    FixAction,
    RemediationProposal,
    RiskLevel,
    RunResult,
    Scope,
)
from guardian.remediate.app_run import AppRun
from guardian.remediate.diff import FindingRef, RescanDiff
from guardian.remediate.sandbox import FixTarget, StepResult, TestRun

FIX_FILE = "fix.json"


class FixPlanError(ValueError):
    """The proposal cannot be turned into an automatic, sandboxed change."""


class FixStatus(StrEnum):
    PROPOSED = "proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    REJECTED = "rejected"
    RUNNING = "running"
    VERIFIED = "verified"
    FAILED = "failed"


_TERMINAL = (FixStatus.VERIFIED, FixStatus.FAILED, FixStatus.REJECTED)


class Decision(BaseModel):
    approved: bool
    reviewer: str
    note: str = ""
    decided_at: datetime | None = None


class FixRun(BaseModel):
    scan_id: str
    proposal: RemediationProposal
    status: FixStatus = FixStatus.PROPOSED
    decision: Decision | None = None
    target: FixTarget | None = None
    apply: StepResult | None = None
    build: StepResult | None = None
    source: StepResult | None = None
    app_build: TestRun | None = None
    tests: TestRun | None = None
    app_run: AppRun | None = None
    diff: RescanDiff | None = None
    summary: str = ""
    error: str | None = None
    completed_at: datetime | None = None


APPLICABLE_ACTIONS = frozenset({FixAction.UPGRADE, FixAction.PIN_VERSION})


def _direct_parent(finding: Finding, nodes: dict[str, Component]) -> Component | None:
    path = finding.dependency_path
    return nodes.get(path[1]) if len(path) > 2 else None


def resolve_target(proposal: RemediationProposal, run: RunResult) -> FixTarget:
    if proposal.action not in APPLICABLE_ACTIONS or not proposal.target_version:
        raise FixPlanError(
            f"'{proposal.action.value}' cannot be applied automatically; only an upgrade or "
            "version pin with a target version can. Make this change manually and rescan."
        )
    finding = next((f for f in run.findings if f.finding_id == proposal.finding_id), None)
    nodes = {n.component_id: n for n in run.graph.nodes}
    node = nodes.get(finding.component_id) if finding else None
    if finding is None or node is None:
        raise FixPlanError(f"Finding {proposal.finding_id} is not in this scan's results.")
    transitive = node.scope is Scope.TRANSITIVE
    parent = _direct_parent(finding, nodes) if transitive else None
    return FixTarget(
        ecosystem=node.ecosystem, package=node.name, from_version=node.version,
        to_version=proposal.target_version, transitive=transitive,
        parent=parent.name if parent else None,
        parent_version=parent.version if parent else None)


def save_fix(work_dir: Path, run: FixRun) -> None:
    if run.completed_at is None and run.status in _TERMINAL:
        stored = load_fix(work_dir, run.proposal.proposal_id)
        stamp = stored.completed_at if stored else None
        run = run.model_copy(update={"completed_at": stamp or datetime.now(UTC)})
    folder = work_dir / "fixes" / run.proposal.proposal_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / FIX_FILE).write_text(run.model_dump_json(indent=2), encoding="utf-8")


def load_fix(work_dir: Path, proposal_id: str) -> FixRun | None:
    path = work_dir / "fixes" / proposal_id / FIX_FILE
    return FixRun.model_validate_json(path.read_text(encoding="utf-8")) if path.is_file() else None


def _by_level(refs: list[FindingRef]) -> str:
    parts = []
    for level in RiskLevel:
        count = sum(1 for ref in refs if ref.risk_level is level)
        if count:
            parts.append(f"{count} {level.value.capitalize()}")
    return ", ".join(parts)


def _advisories(refs: list[FindingRef]) -> str:
    return ", ".join(sorted({r.advisory_id or r.finding_id for r in refs}))


def _outcome(diff: RescanDiff) -> str:
    fixed = (
        f"Fixed {_by_level(diff.fixed)} ({_advisories(diff.fixed)})."
        if diff.fixed else "No findings were fixed."
    )
    new = diff.introduced
    if not new:
        return f"{fixed} No new findings."
    noun = "finding" if len(new) == 1 else "findings"
    return f"{fixed} Introduced {len(new)} new {noun}: {_by_level(new)} ({_advisories(new)})."


def _step_text(label: str, status: str, detail: str, shown: str) -> str:
    return f"{label} {status}" + (f": {detail}" if status == shown and detail else "")


def _tests_text(tests: TestRun) -> str:
    status = tests.status.replace("_", " ")
    text = _step_text("Tests", status, tests.reason, "not run" if status == "not run" else "failed")
    if tests.status == "passed" and tests.total is not None:
        text += f" ({tests.passed} of {tests.total})"
    return text


def failure_summary(run: FixRun) -> str | None:
    build, tests = run.app_build, run.tests
    if build and build.status == "failed":
        return f"Build failed: {build.reason}; not safe to apply."
    if tests and tests.status == "failed":
        if tests.failed is None or tests.total is None:
            return f"Tests failed: {tests.reason}; not safe to apply."
        names = ", ".join(tests.failed_tests) or "its tests"
        return (f"Tests failed: {tests.failed} of {tests.total} — the upgrade breaks {names}; "
                "not safe to apply.")
    app = run.app_run
    if app and app.status == "failed":
        return f"App did not start: {app.reason}; not safe to apply."
    return None


def app_text(app: AppRun) -> str:
    if app.status != "passed":
        return f"Application {app.status.replace('_', ' ')}: {app.reason}."
    path = urlparse(app.health_url).path
    text = f"App started in a container and answered {path} with {app.http_status}."
    if app.image_vulns is None:
        return f"{text} Image scan unavailable: {app.image_error}."
    counts = app.image_vulns
    return (f"{text} Image scan: {counts.get('critical', 0)} critical, {counts.get('high', 0)} "
            f"high ({app.image_only_serious} from the base image).")


def verification_summary(run: FixRun) -> str:
    if run.diff is None:
        return run.error or ""
    build = run.build or StepResult(status="failed", detail="not run")
    tests = run.tests or TestRun(status="not_run", reason="not run")
    failure = failure_summary(run)
    parts = [failure] if failure else []
    parts += [_outcome(run.diff), _step_text("Build check", build.status, build.detail, "failed")
              + "."]
    app = run.app_build
    if app is not None and app.status != "not_run":
        parts.append(_step_text("Build", app.status, app.reason, "failed") + ".")
    if not failure:
        parts.append(_tests_text(tests) + ".")
    if run.app_run is not None and run.app_run.status == "passed":
        parts.append(app_text(run.app_run))
    return " ".join(parts)


def load_run(out_dir: Path) -> RunResult:
    def read(name: str) -> dict[str, object]:
        data: dict[str, object] = json.loads((out_dir / name).read_text(encoding="utf-8"))
        return data

    return RunResult.model_validate({
        "scan": read("run.json"), "coverage": read("coverage.json"),
        "graph": read("graph.json"), **read("findings.json"),
    })
