import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from guardian.decisions import DecisionLog, HumanDecision, apply_decisions
from guardian.models import Finding, FindingKind, RiskLevel


def finding(finding_id: str = "f1", level: RiskLevel = RiskLevel.MEDIUM) -> Finding:
    return Finding(
        finding_id=finding_id, component_id="lib", purl="pkg:npm/lib@1",
        kind=FindingKind.VULNERABILITY, risk_level=level, review_required=True,
        review_reasons=["low confidence"],
    )


def decision(kind: str = "confirmed", note: str = "", finding_id: str = "f1") -> HumanDecision:
    return HumanDecision.model_validate({
        "finding_id": finding_id, "decision": kind, "note": note,
        "decided_at": datetime(2026, 11, 24, tzinfo=UTC),
    })


def test_dismissal_requires_a_note() -> None:
    with pytest.raises(ValidationError):
        decision("dismissed", note="  ")


def test_note_and_reviewer_are_bounded() -> None:
    with pytest.raises(ValidationError):
        decision("confirmed", note="x" * 501)
    with pytest.raises(ValidationError):
        HumanDecision(finding_id="f1", decision="confirmed", reviewer="r" * 81)


def test_confirmed_clears_review_and_records_the_decision() -> None:
    [result] = apply_decisions([finding()], [decision("confirmed", "checked")])
    assert result.review_required is False
    assert (result.human_decision, result.human_note) == ("confirmed", "checked")
    assert result.risk_level == RiskLevel.MEDIUM


def test_dismissed_clears_review_and_keeps_the_note() -> None:
    [result] = apply_decisions([finding()], [decision("dismissed", "test-only code")])
    assert result.review_required is False
    assert result.human_decision == "dismissed"
    assert result.human_note == "test-only code"


@pytest.mark.parametrize(
    ("start", "expected"),
    [(RiskLevel.LOW, RiskLevel.MEDIUM), (RiskLevel.HIGH, RiskLevel.CRITICAL),
     (RiskLevel.CRITICAL, RiskLevel.CRITICAL)],
)
def test_escalated_keeps_review_and_raises_one_level(start: RiskLevel, expected: RiskLevel) -> None:
    [result] = apply_decisions([finding(level=start)], [decision("escalated")])
    assert result.review_required is True
    assert result.risk_level == expected
    assert result.human_decision == "escalated"


def test_latest_decision_wins_and_undecided_findings_pass_through() -> None:
    other = finding("f2")
    decisions = [decision("dismissed", "x"), decision("confirmed")]
    results = apply_decisions([finding(), other], decisions)
    assert results[0].human_decision == "confirmed"
    assert results[1] == other


def test_unknown_finding_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="nope"):
        apply_decisions([finding()], [decision(finding_id="nope")])


def test_log_persists_history_and_returns_latest_per_finding(tmp_path: Path) -> None:
    log = DecisionLog(tmp_path)
    assert log.latest() == {}
    log.record(decision("dismissed", "first"))
    log.record(decision("confirmed", "second"))
    assert log.latest()["f1"].note == "second"
    saved = json.loads((tmp_path / "decisions.json").read_text("utf-8"))
    assert [item["note"] for item in saved["decisions"]] == ["first", "second"]
    assert [p.name for p in tmp_path.iterdir()] == ["decisions.json"]
    assert DecisionLog(tmp_path).latest()["f1"].decision == "confirmed"
