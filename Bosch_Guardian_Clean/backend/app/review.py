"""Human review queue: findings flagged for review, and the decisions made on them."""

from collections.abc import Callable
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from guardian.decisions import (
    DecisionInput,
    DecisionLog,
    HumanDecision,
    ReviewSummary,
    summarize,
)
from guardian.models import Finding, FindingsArtifact, GraphArtifact
from guardian.report.render import render

from .schemas import ScanRecord


class ReviewItem(BaseModel):
    finding_id: str
    package: str
    advisory_id: str | None
    anomaly_type: str | None
    risk_level: str
    confidence_score: float | None
    review_reasons: list[str]
    decision: HumanDecision | None


class ReviewQueue(BaseModel):
    items: list[ReviewItem]
    counts: ReviewSummary


def _package_labels(out: Path) -> dict[str, str]:
    path = out / "graph.json"
    if not path.is_file():
        return {}
    graph = GraphArtifact.model_validate_json(path.read_bytes())
    return {node.component_id: f"{node.name}@{node.version}" for node in graph.nodes}


def _queued(out: Path) -> list[Finding]:
    artifact = FindingsArtifact.model_validate_json((out / "findings.json").read_bytes())
    return [finding for finding in artifact.findings if finding.review_required]


def _item(finding: Finding, labels: dict[str, str], decision: HumanDecision | None) -> ReviewItem:
    return ReviewItem(
        finding_id=finding.finding_id,
        package=labels.get(finding.component_id, finding.purl),
        advisory_id=finding.advisory_id,
        anomaly_type=finding.anomaly_type,
        risk_level=str(finding.risk_level),
        confidence_score=finding.confidence_score,
        review_reasons=finding.review_reasons,
        decision=decision,
    )


def _queue(out: Path) -> ReviewQueue:
    queued = _queued(out)
    latest = DecisionLog(out).latest()
    labels = _package_labels(out)
    return ReviewQueue(
        items=[_item(f, labels, latest.get(f.finding_id)) for f in queued],
        counts=summarize(queued, latest),
    )


def build_router(finished: Callable[[str], ScanRecord]) -> APIRouter:
    router = APIRouter()

    @router.get("/scan/{scan_id}/review")
    def review_queue(scan_id: str) -> ReviewQueue:
        return _queue(finished(scan_id).work_dir / "out")

    @router.post("/scan/{scan_id}/review/{finding_id}")
    def decide(scan_id: str, finding_id: str, body: DecisionInput) -> ReviewItem:
        out = finished(scan_id).work_dir / "out"
        if finding_id not in {f.finding_id for f in _queued(out)}:
            raise HTTPException(404, f"Finding {finding_id} is not in this scan's review queue")
        DecisionLog(out).record(HumanDecision(finding_id=finding_id, **body.model_dump()))
        render(out)
        [item] = [i for i in _queue(out).items if i.finding_id == finding_id]
        return item

    return router
