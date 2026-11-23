"""The persisted state of one fix: proposal, approval, sandbox steps and rescan result."""

import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from guardian.models import FixAction, RemediationProposal, RiskLevel, RunResult
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
    tests: TestRun | None = None
    diff: RescanDiff | None = None
    summary: str = ""
    error: str | None = None
    completed_at: datetime | None = None


def resolve_target(proposal: RemediationProposal, run: RunResult) -> FixTarget:
    if proposal.action is not FixAction.UPGRADE or not proposal.target_version:
        raise FixPlanError(
            f"'{proposal.action.value}' cannot be applied automatically; only an upgrade "
            "with a target version can. Make this change manually and rescan."
        )
    finding = next((f for f in run.findings if f.finding_id == proposal.finding_id), None)
    nodes = {n.component_id: n for n in run.graph.nodes}
    node = nodes.get(finding.component_id) if finding else None
    if node is None:
        raise FixPlanError(f"Finding {proposal.finding_id} is not in this scan's results.")
    return FixTarget(ecosystem=node.ecosystem, package=node.name, from_version=node.version,
                     to_version=proposal.target_version)


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


def verification_summary(run: FixRun) -> str:
    if run.diff is None:
        return run.error or ""
    build = run.build or StepResult(status="failed", detail="not run")
    tests = run.tests or TestRun(status="not_run", reason="not run")
    status = tests.status.replace("_", " ")
    return " ".join([
        _outcome(run.diff),
        _step_text("Build check", build.status, build.detail, "failed") + ".",
        _step_text("Tests", status, tests.reason, "not run" if status == "not run" else "failed")
        + ".",
    ])


def load_run(out_dir: Path) -> RunResult:
    def read(name: str) -> dict[str, object]:
        data: dict[str, object] = json.loads((out_dir / name).read_text(encoding="utf-8"))
        return data

    return RunResult.model_validate({
        "scan": read("run.json"), "coverage": read("coverage.json"),
        "graph": read("graph.json"), **read("findings.json"),
    })
