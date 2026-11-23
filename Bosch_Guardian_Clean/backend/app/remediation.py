"""Fix workflow API: list proposed fixes, start one, then approve or reject it."""

import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException
from langgraph.checkpoint.sqlite import SqliteSaver
from pydantic import BaseModel, Field

from guardian.models import RemediationProposal
from guardian.remediate.run import (
    Decision,
    FixPlanError,
    FixRun,
    FixStatus,
    load_fix,
    load_run,
    resolve_target,
    save_fix,
)
from guardian.remediate.sandbox import FixTarget
from guardian.remediate.workflow import (
    FixDeps,
    Graph,
    build_fix_graph,
    is_waiting,
    open_checkpointer,
    resume_fix,
    start_fix,
)
from guardian.report.render import render

from . import pipeline
from .schemas import ScanRecord

router = APIRouter(prefix="/scan/{scan_id}/fixes", tags=["fixes"])
CHECKPOINT_FILE: Final = "checkpoints.sqlite"
_CHECKPOINTERS: Final[dict[Path, SqliteSaver]] = {}
_CHECKPOINTERS_LOCK: Final = threading.Lock()


class DecisionRequest(Decision):
    reviewer: str = Field(min_length=1, max_length=80)
    note: str = Field(default="", max_length=500)


class FixEntry(BaseModel):
    proposal: RemediationProposal
    source: Literal["ai", "rule"]
    status: FixStatus
    target: FixTarget | None
    unavailable_reason: str | None
    result: FixRun | None


def fix_deps() -> FixDeps:
    return FixDeps()


def _finished(scan_id: str) -> ScanRecord:
    record = pipeline.SCANS.get(scan_id)
    if record is None:
        raise HTTPException(404, "Scan not found")
    if record.status == "running" or not (record.work_dir / "out" / "run.json").is_file():
        raise HTTPException(409, record.error or "Scan has no result yet; wait for it to finish")
    return record


def _checkpointer(record: ScanRecord) -> SqliteSaver:
    path = record.work_dir.parent / CHECKPOINT_FILE
    with _CHECKPOINTERS_LOCK:
        if path not in _CHECKPOINTERS:
            _CHECKPOINTERS[path] = open_checkpointer(path)
        return _CHECKPOINTERS[path]


def close_checkpointers() -> None:
    with _CHECKPOINTERS_LOCK:
        for saver in _CHECKPOINTERS.values():
            saver.conn.close()
        _CHECKPOINTERS.clear()


def _graph(record: ScanRecord) -> Graph:
    return build_fix_graph(record.work_dir, _checkpointer(record), fix_deps())


def _proposal(record: ScanRecord, proposal_id: str) -> RemediationProposal:
    for proposal in load_run(record.work_dir / "out").proposals:
        if proposal.proposal_id == proposal_id:
            return proposal
    raise HTTPException(404, f"No fix proposal '{proposal_id}' in this scan")


def _resume_and_report(
    graph: Graph, record: ScanRecord, proposal_id: str, decision: Decision
) -> FixRun:
    run = resume_fix(graph, record.scan_id, proposal_id, decision)
    render(record.work_dir / "out")
    return run


@router.get("")
def list_fixes(scan_id: str) -> list[FixEntry]:
    record = _finished(scan_id)
    run = load_run(record.work_dir / "out")
    entries = []
    for proposal in run.proposals:
        target, reason = None, None
        try:
            target = resolve_target(proposal, run)
        except FixPlanError as error:
            reason = str(error)
        stored = load_fix(record.work_dir, proposal.proposal_id)
        entries.append(FixEntry(
            proposal=proposal, source="rule" if proposal.proposal_id.startswith("rule-") else "ai",
            status=stored.status if stored else FixStatus.PROPOSED, target=target,
            unavailable_reason=reason, result=stored,
        ))
    return entries


@router.post("/{proposal_id}/start")
def start(scan_id: str, proposal_id: str) -> FixRun:
    record = _finished(scan_id)
    proposal = _proposal(record, proposal_id)
    stored = load_fix(record.work_dir, proposal_id)
    graph = _graph(record)
    if stored and stored.status is FixStatus.RUNNING:
        raise HTTPException(409, "This fix is already running; poll GET /fixes for its status")
    if stored and is_waiting(graph, scan_id, proposal_id):
        return stored
    run = start_fix(graph, scan_id, proposal)
    if run.status is FixStatus.FAILED:
        raise HTTPException(422, run.error or "This fix cannot be applied automatically")
    return run


@router.post("/{proposal_id}/decision")
def decide(
    scan_id: str, proposal_id: str, body: DecisionRequest, background: BackgroundTasks
) -> FixRun:
    record = _finished(scan_id)
    _proposal(record, proposal_id)
    graph = _graph(record)
    stored = load_fix(record.work_dir, proposal_id)
    if stored is None or not is_waiting(graph, scan_id, proposal_id):
        raise HTTPException(409, (
            "No approval is pending for this fix. Start it first with POST .../start"))
    decision = Decision(approved=body.approved, reviewer=body.reviewer, note=body.note,
                        decided_at=datetime.now(UTC))
    if not decision.approved:
        return _resume_and_report(graph, record, proposal_id, decision)
    running = stored.model_copy(update={"status": FixStatus.RUNNING, "decision": decision})
    save_fix(record.work_dir, running)
    background.add_task(_resume_and_report, graph, record, proposal_id, decision)
    return running
