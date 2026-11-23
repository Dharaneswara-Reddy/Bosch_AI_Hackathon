"""Machine-readable final report: findings, validated fixes, residual risk and audit trail."""

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from guardian.decisions import HumanDecision
from guardian.models import (
    AgentTrace,
    Finding,
    FindingsArtifact,
    GraphArtifact,
    RemediationProposal,
    Scan,
)
from guardian.remediate.diff import FindingRef
from guardian.remediate.run import FIX_FILE, FixRun, FixStatus

Verdict = Literal[
    "fixed", "fixed_with_new_findings", "no_effect", "failed", "rejected", "pending"
]
Level = Literal["high", "medium", "low"]
_PENDING = (FixStatus.PROPOSED, FixStatus.AWAITING_APPROVAL, FixStatus.RUNNING)


class Inventory(BaseModel):
    components: int
    by_ecosystem: dict[str, int]


class RankedFinding(BaseModel):
    finding_id: str
    advisory_id: str | None
    kind: str
    package: str
    version: str
    risk_level: str
    risk_score: int | None
    confidence_score: float | None
    dependency_path: list[str]
    evidence_ids: list[str]
    human_decision: str | None


class RecommendedAction(BaseModel):
    proposal_id: str
    finding_id: str
    source: Literal["ai", "rule"]
    action: str
    target_version: str | None
    rationale: str
    rollback: str
    breaking_change_risk: str
    validated: bool
    rejected_reason: str | None
    evidence_ids: list[str]
    status: str


class FixValidation(BaseModel):
    proposal_id: str
    finding_id: str
    advisory_id: str | None
    package: str
    action: str
    status: str
    approved: bool | None
    reviewer: str | None
    note: str
    decided_at: datetime | None
    build_status: str | None
    build_detail: str
    tests_status: str | None
    tests_detail: str
    counts_before: dict[str, int]
    counts_after: dict[str, int]
    fixed: list[FindingRef]
    introduced: list[FindingRef]
    summary: str
    verdict: Verdict
    confidence: Level | None
    evidence_ids: list[str]


class RiskEntry(BaseModel):
    finding_id: str
    advisory_id: str | None
    package: str
    risk_level: str
    origin: str


class AcceptedRisk(BaseModel):
    finding_id: str
    advisory_id: str | None
    package: str
    risk_level: str
    reviewer: str
    note: str
    decided_at: datetime


class AuditEvent(BaseModel):
    at: datetime
    kind: str
    actor: str
    summary: str


class GuardianReport(BaseModel):
    scan_id: str
    target: str
    status: str
    started_at: datetime
    ended_at: datetime | None
    inventory: Inventory
    risk_counts: dict[str, int]
    findings: list[RankedFinding]
    recommended_actions: list[RecommendedAction]
    validations: list[FixValidation]
    remaining_risks: list[RiskEntry]
    accepted_risks: list[AcceptedRisk]
    escalated: list[RankedFinding]
    audit_trail: list[AuditEvent] = Field(default_factory=list)


def load_fixes(work_dir: Path) -> list[FixRun]:
    runs = []
    for path in sorted((work_dir / "fixes").glob(f"*/{FIX_FILE}")):
        try:
            runs.append(FixRun.model_validate_json(path.read_bytes()))
        except ValueError:
            continue
    return runs


class _Labels:
    def __init__(self, graph: GraphArtifact) -> None:
        self._nodes = {node.component_id: node for node in graph.nodes}

    def package(self, finding: Finding) -> tuple[str, str]:
        node = self._nodes.get(finding.component_id)
        return (node.name, node.version) if node else (finding.purl, "UNKNOWN")


def _ranked(finding: Finding, labels: _Labels) -> RankedFinding:
    name, version = labels.package(finding)
    return RankedFinding(
        finding_id=finding.finding_id, advisory_id=finding.advisory_id,
        kind=str(finding.kind), package=name, version=version,
        risk_level=str(finding.risk_level), risk_score=finding.risk_score,
        confidence_score=finding.confidence_score, dependency_path=finding.dependency_path,
        evidence_ids=finding.evidence_ids, human_decision=finding.human_decision)


def _action(proposal: RemediationProposal, runs: dict[str, FixRun]) -> RecommendedAction:
    run = runs.get(proposal.proposal_id)
    return RecommendedAction(
        proposal_id=proposal.proposal_id, finding_id=proposal.finding_id,
        source="rule" if proposal.proposal_id.startswith("rule-") else "ai",
        action=proposal.action.value, target_version=proposal.target_version,
        rationale=proposal.rationale, rollback=proposal.rollback,
        breaking_change_risk=proposal.breaking_change_risk, validated=proposal.validated,
        rejected_reason=proposal.rejected_reason, evidence_ids=proposal.evidence_ids,
        status=run.status.value if run else FixStatus.PROPOSED.value)


def _verdict(run: FixRun) -> Verdict:
    if run.status is FixStatus.REJECTED:
        return "rejected"
    if run.status is FixStatus.FAILED:
        return "failed"
    if run.status in _PENDING or run.diff is None:
        return "pending"
    if run.diff.introduced:
        return "fixed_with_new_findings"
    return "fixed" if run.diff.fixed else "no_effect"


def _confidence(run: FixRun, verdict: Verdict) -> Level | None:
    if verdict not in ("fixed", "fixed_with_new_findings", "no_effect"):
        return None
    points = int(bool(run.tests and run.tests.status == "passed"))
    points += int(verdict == "fixed")
    return ("low", "medium", "high")[points]


def _validation(run: FixRun, finding: Finding | None, labels: _Labels) -> FixValidation:
    verdict = _verdict(run)
    decision, diff = run.decision, run.diff
    return FixValidation(
        proposal_id=run.proposal.proposal_id, finding_id=run.proposal.finding_id,
        advisory_id=finding.advisory_id if finding else None,
        package=labels.package(finding)[0] if finding else "UNKNOWN",
        action=run.proposal.action.value, status=run.status.value,
        approved=decision.approved if decision else None,
        reviewer=decision.reviewer if decision else None,
        note=decision.note if decision else "",
        decided_at=decision.decided_at if decision else None,
        build_status=run.build.status if run.build else None,
        build_detail=run.build.detail if run.build else "",
        tests_status=run.tests.status if run.tests else None,
        tests_detail=run.tests.reason if run.tests else "",
        counts_before=diff.counts_before if diff else {},
        counts_after=diff.counts_after if diff else {},
        fixed=diff.fixed if diff else [], introduced=diff.introduced if diff else [],
        summary=run.summary or run.error or "", verdict=verdict,
        confidence=_confidence(run, verdict), evidence_ids=run.proposal.evidence_ids)


def _remaining(
    findings: list[Finding], runs: list[FixRun], labels: _Labels
) -> list[RiskEntry]:
    verified = [run for run in runs if run.status is FixStatus.VERIFIED and run.diff]
    fixed = {ref.finding_id for run in verified if run.diff for ref in run.diff.fixed}
    entries = [
        RiskEntry(finding_id=f.finding_id, advisory_id=f.advisory_id,
                  package=labels.package(f)[0], risk_level=str(f.risk_level), origin="open")
        for f in findings if f.finding_id not in fixed and f.human_decision != "dismissed"
    ]
    for run in verified:
        for ref in run.diff.introduced if run.diff else []:
            entries.append(RiskEntry(
                finding_id=ref.finding_id, advisory_id=ref.advisory_id, package=ref.package,
                risk_level=ref.risk_level.value,
                origin=f"introduced by fix {run.proposal.proposal_id}"))
    return entries


def _accepted(
    findings: list[Finding], decisions: list[HumanDecision], labels: _Labels
) -> list[AcceptedRisk]:
    by_id = {f.finding_id: f for f in findings}
    latest = {d.finding_id: d for d in decisions}
    return [
        AcceptedRisk(
            finding_id=d.finding_id, advisory_id=by_id[d.finding_id].advisory_id,
            package=labels.package(by_id[d.finding_id])[0],
            risk_level=str(by_id[d.finding_id].risk_level), reviewer=d.reviewer,
            note=d.note, decided_at=d.decided_at)
        for d in latest.values() if d.decision == "dismissed" and d.finding_id in by_id
    ]


def _ai_summary(step: AgentTrace) -> str:
    detail = f"accepted {step.accepted}, rejected {step.rejected}, {step.llm_calls} LLM calls"
    return f"{step.agent.replace('_', ' ')}: {detail}" + (f" ({step.error})" if step.error else "")


def _audit(
    scan: Scan, trace: list[AgentTrace], decisions: list[HumanDecision], runs: list[FixRun]
) -> list[AuditEvent]:
    ended = scan.ended_at or scan.started_at
    events = [AuditEvent(at=scan.started_at, kind="scan_started", actor="guardian",
                         summary=f"Scan of {scan.target} started")]
    events += [AuditEvent(at=ended, kind="ai_review", actor="ai", summary=_ai_summary(s))
               for s in trace]
    events.append(AuditEvent(at=ended, kind="scan_completed", actor="guardian",
                             summary=f"Scan finished with status {scan.status}"))
    for d in decisions:
        events.append(AuditEvent(
            at=d.decided_at, kind="human_decision", actor=d.reviewer,
            summary=f"{d.reviewer} marked {d.finding_id} {d.decision}"
                    + (f": {d.note}" if d.note else "")))
    for run in runs:
        events += _fix_events(run, ended)
    return sorted(events, key=lambda event: event.at)


def _fix_events(run: FixRun, fallback: datetime) -> list[AuditEvent]:
    pid, decision = run.proposal.proposal_id, run.decision
    events = []
    if decision:
        verb = "approved" if decision.approved else "rejected"
        events.append(AuditEvent(
            at=decision.decided_at or fallback, kind=f"fix_{verb}", actor=decision.reviewer,
            summary=f"{decision.reviewer} {verb} fix {pid}"
                    + (f": {decision.note}" if decision.note else "")))
    if run.status in (FixStatus.VERIFIED, FixStatus.FAILED) and run.completed_at:
        events.append(AuditEvent(at=run.completed_at, kind="fix_result", actor="guardian",
                                 summary=f"Fix {pid} {run.status.value}: "
                                         f"{run.summary or run.error or ''}".strip()))
    return events


def build_report(
    scan: Scan,
    graph: GraphArtifact,
    artifacts: FindingsArtifact,
    ranked: list[Finding],
    decisions: list[HumanDecision],
    runs: list[FixRun],
) -> GuardianReport:
    """Assemble the report from the scan artifacts, already-ranked findings and fix runs."""
    labels = _Labels(graph)
    by_id = {f.finding_id: f for f in ranked}
    by_proposal = {run.proposal.proposal_id: run for run in runs}
    return GuardianReport(
        scan_id=scan.scan_id, target=scan.target, status=str(scan.status),
        started_at=scan.started_at, ended_at=scan.ended_at,
        inventory=Inventory(
            components=len(graph.nodes),
            by_ecosystem=dict(Counter(node.ecosystem for node in graph.nodes))),
        risk_counts=dict(Counter(str(f.risk_level) for f in ranked)),
        findings=[_ranked(f, labels) for f in ranked],
        recommended_actions=[_action(p, by_proposal) for p in artifacts.proposals],
        validations=[_validation(run, by_id.get(run.proposal.finding_id), labels)
                     for run in runs],
        remaining_risks=_remaining(ranked, runs, labels),
        accepted_risks=_accepted(artifacts.findings, decisions, labels),
        escalated=[_ranked(f, labels) for f in ranked if f.human_decision == "escalated"],
        audit_trail=_audit(scan, artifacts.agent_trace, decisions, runs),
    )
