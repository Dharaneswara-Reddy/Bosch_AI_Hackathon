"""Human review decisions: validated, persisted with full history, applied to findings."""

import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, Field, model_validator

from guardian.models import Finding, RiskLevel

DECISIONS_FILE: Final = "decisions.json"
_LEVELS: Final = (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
_LOCK: Final = threading.Lock()


class DecisionInput(BaseModel):
    decision: Literal["confirmed", "dismissed", "escalated"]
    note: str = Field(default="", max_length=500)
    reviewer: str = Field(default="reviewer", min_length=1, max_length=80)

    @model_validator(mode="after")
    def require_note_for_dismissal(self) -> "DecisionInput":
        if self.decision == "dismissed" and not self.note.strip():
            raise ValueError("A note explaining why the finding is dismissed is required.")
        return self


class HumanDecision(DecisionInput):
    finding_id: str
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReviewSummary(BaseModel):
    pending: int = 0
    confirmed: int = 0
    dismissed: int = 0
    escalated: int = 0


class DecisionHistory(BaseModel):
    decisions: list[HumanDecision] = Field(default_factory=list)


class DecisionLog:
    """``<out>/decisions.json``: every decision ever made; the latest per finding applies."""

    def __init__(self, out_dir: Path) -> None:
        self._path = out_dir / DECISIONS_FILE

    def history(self) -> list[HumanDecision]:
        if not self._path.is_file():
            return []
        return DecisionHistory.model_validate_json(self._path.read_bytes()).decisions

    def latest(self) -> dict[str, HumanDecision]:
        return {item.finding_id: item for item in self.history()}

    def record(self, decision: HumanDecision) -> None:
        with _LOCK:
            history = DecisionHistory(decisions=[*self.history(), decision])
            temp = self._path.with_suffix(".json.tmp")
            temp.write_text(history.model_dump_json(indent=2), encoding="utf-8")
            os.replace(temp, self._path)


def _escalate(level: RiskLevel) -> RiskLevel:
    if level not in _LEVELS:
        return level
    return _LEVELS[min(_LEVELS.index(level) + 1, len(_LEVELS) - 1)]


def _apply(finding: Finding, decision: HumanDecision) -> Finding:
    update: dict[str, object] = {
        "human_decision": decision.decision,
        "human_note": decision.note or None,
        "review_required": decision.decision == "escalated",
    }
    if decision.decision == "escalated":
        update["risk_level"] = _escalate(finding.risk_level)
    return finding.model_copy(update=update)


def apply_decisions(findings: list[Finding], decisions: list[HumanDecision]) -> list[Finding]:
    """Apply the latest decision per finding; a decision for an unknown finding is an error."""
    known = {finding.finding_id for finding in findings}
    for decision in decisions:
        if decision.finding_id not in known:
            raise ValueError(f"Unknown finding_id: {decision.finding_id}")
    latest = {item.finding_id: item for item in decisions}
    return [
        _apply(finding, latest[finding.finding_id]) if finding.finding_id in latest else finding
        for finding in findings
    ]


def summarize(findings: list[Finding], latest: dict[str, HumanDecision]) -> ReviewSummary:
    """Counts over the review queue (findings flagged before any decision was applied)."""
    summary = ReviewSummary()
    for finding in findings:
        if not finding.review_required:
            continue
        decision = latest.get(finding.finding_id)
        key = decision.decision if decision else "pending"
        setattr(summary, key, getattr(summary, key) + 1)
    return summary
