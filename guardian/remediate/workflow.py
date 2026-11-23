"""Human-approved fix workflow: plan, pause for approval, sandbox, rescan, diff, summarise.

The approval is a LangGraph ``interrupt``: the graph stops after ``plan`` and nothing touches
the sandbox until it is resumed with an approving ``Decision``.
"""

import shutil
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command, interrupt

from guardian import runner
from guardian.models import RemediationProposal, RunResult
from guardian.remediate.diff import diff_runs
from guardian.remediate.run import (
    Decision,
    FixPlanError,
    FixRun,
    FixStatus,
    load_run,
    resolve_target,
    save_fix,
    verification_summary,
)
from guardian.remediate.sandbox import (
    Runner,
    apply_upgrade,
    build_check,
    create_sandbox,
    run_command,
    run_tests,
)

ScanFn = Callable[[Path, Path], RunResult]
Graph = CompiledStateGraph["FixState", None, "FixState", "FixState"]


class FixState(TypedDict):
    run: FixRun


def find_engine() -> str | None:
    return shutil.which("docker") or shutil.which("podman")


def scan_without_ai(target: Path, out: Path) -> RunResult:
    return runner.scan(target, out, use_llm=False)


@dataclass
class FixDeps:
    runner: Runner = run_command
    scan: ScanFn = scan_without_ai
    engine: str | None = field(default_factory=find_engine)


def open_checkpointer(path: Path) -> SqliteSaver:
    """A file-backed checkpointer: a fix waiting for approval survives a server restart."""
    path.parent.mkdir(parents=True, exist_ok=True)
    return SqliteSaver(sqlite3.connect(path, check_same_thread=False))


def _thread(scan_id: str, proposal_id: str) -> Any:
    return {"configurable": {"thread_id": f"{scan_id}:{proposal_id}"}}


class _Steps:
    def __init__(self, work_dir: Path, deps: FixDeps) -> None:
        self.work_dir = work_dir
        self.deps = deps

    def _folder(self, run: FixRun) -> Path:
        return self.work_dir / "fixes" / run.proposal.proposal_id

    def guarded(self, step: Callable[[FixRun], FixRun]) -> Callable[[FixState], FixState]:
        def node(state: FixState) -> FixState:
            run = state["run"]
            try:
                run = step(run)
            except Exception as error:  # noqa: BLE001 - worker boundary: record, never lose it
                run = run.model_copy(update={
                    "status": FixStatus.FAILED, "error": f"{type(error).__name__}: {error}"})
            save_fix(self.work_dir, run)
            return {"run": run}

        return node

    def plan(self, state: FixState) -> FixState:
        run = state["run"]
        try:
            target = resolve_target(run.proposal, load_run(self.work_dir / "out"))
            run = run.model_copy(update={"target": target, "status": FixStatus.AWAITING_APPROVAL})
        except FixPlanError as error:
            run = run.model_copy(update={"status": FixStatus.FAILED, "error": str(error)})
        save_fix(self.work_dir, run)
        return {"run": run}

    def human_approval(self, state: FixState) -> FixState:
        run = state["run"]
        answer = interrupt({
            "proposal": run.proposal.model_dump(mode="json"),
            "target": run.target.model_dump(mode="json") if run.target else None,
        })
        decision = Decision.model_validate(answer)
        status = FixStatus.RUNNING if decision.approved else FixStatus.REJECTED
        run = run.model_copy(update={"decision": decision, "status": status})
        save_fix(self.work_dir, run)
        return {"run": run}

    def record_rejection(self, run: FixRun) -> FixRun:
        decision = run.decision
        who = decision.reviewer if decision else "a reviewer"
        note = f" Reason: {decision.note}." if decision and decision.note else ""
        return run.model_copy(update={"summary": f"Rejected by {who}.{note} Nothing was changed."})

    def sandbox_apply(self, run: FixRun) -> FixRun:
        assert run.target is not None
        sandbox = create_sandbox(self.work_dir / "repo", self._folder(run) / "sandbox")
        done = apply_upgrade(sandbox, run.target)
        failed = done.status != "passed"
        return run.model_copy(update={
            "apply": done, "status": FixStatus.FAILED if failed else run.status,
            "error": done.detail if failed else None})

    def build_check(self, run: FixRun) -> FixRun:
        assert run.target is not None
        done = build_check(self._folder(run) / "sandbox", run.target, self.deps.runner)
        failed = done.status != "passed"
        return run.model_copy(update={
            "build": done, "status": FixStatus.FAILED if failed else run.status,
            "error": done.detail if failed else None})

    def run_tests(self, run: FixRun) -> FixRun:
        result = run_tests(self._folder(run) / "sandbox", self.deps.runner, self.deps.engine)
        return run.model_copy(update={"tests": result})

    def rescan(self, run: FixRun) -> FixRun:
        folder = self._folder(run)
        self.deps.scan(folder / "sandbox", folder / "out")
        return run

    def diff(self, run: FixRun) -> FixRun:
        after = load_run(self._folder(run) / "out")
        return run.model_copy(update={"diff": diff_runs(load_run(self.work_dir / "out"), after)})

    def verification_summary(self, run: FixRun) -> FixRun:
        verified = run.model_copy(update={"status": FixStatus.VERIFIED})
        return verified.model_copy(update={"summary": verification_summary(verified)})


def _stop_if_failed(next_node: str) -> Callable[[FixState], str]:
    return lambda state: END if state["run"].status is FixStatus.FAILED else next_node


def _after_approval(state: FixState) -> str:
    return "sandbox_apply" if state["run"].status is FixStatus.RUNNING else "record_rejection"


def build_fix_graph(
    work_dir: Path, checkpointer: BaseCheckpointSaver[Any], deps: FixDeps | None = None
) -> Graph:
    steps = _Steps(work_dir, deps or FixDeps())
    graph = StateGraph(FixState)
    graph.add_node("plan", steps.plan)
    graph.add_node("human_approval", steps.human_approval)
    for name in ("record_rejection", "sandbox_apply", "build_check", "run_tests", "rescan",
                 "diff", "verification_summary"):
        node: Any = steps.guarded(getattr(steps, name))
        graph.add_node(name, node)
    graph.add_edge(START, "plan")
    graph.add_conditional_edges("plan", _stop_if_failed("human_approval"))
    graph.add_conditional_edges("human_approval", _after_approval)
    graph.add_edge("record_rejection", END)
    graph.add_conditional_edges("sandbox_apply", _stop_if_failed("build_check"))
    graph.add_conditional_edges("build_check", _stop_if_failed("run_tests"))
    for source, target in (("run_tests", "rescan"), ("rescan", "diff"),
                           ("diff", "verification_summary"), ("verification_summary", END)):
        graph.add_edge(source, target)
    return graph.compile(checkpointer=checkpointer)


def _current(graph: Graph, scan_id: str, proposal_id: str) -> FixRun:
    run: FixRun = graph.get_state(_thread(scan_id, proposal_id)).values["run"]
    return run


def start_fix(graph: Graph, scan_id: str, proposal: RemediationProposal) -> FixRun:
    graph.invoke({"run": FixRun(scan_id=scan_id, proposal=proposal)},
                 _thread(scan_id, proposal.proposal_id))
    return _current(graph, scan_id, proposal.proposal_id)


def is_waiting(graph: Graph, scan_id: str, proposal_id: str) -> bool:
    return bool(graph.get_state(_thread(scan_id, proposal_id)).next)


def resume_fix(graph: Graph, scan_id: str, proposal_id: str, decision: Decision) -> FixRun:
    graph.invoke(Command(resume=decision.model_dump()), _thread(scan_id, proposal_id))
    return _current(graph, scan_id, proposal_id)
