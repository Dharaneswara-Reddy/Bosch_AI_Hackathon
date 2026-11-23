from __future__ import annotations

import pytest

from guardian.ai.context import ReviewContext
from guardian.ai.risk_rules import check_adjustment
from guardian.ai.state import RiskAdjustment
from guardian.models import (
    Finding,
    FindingKind,
    Relevance,
    RelevanceSignal,
    RiskLevel,
)
from tests.ai.factories import make_context

REASON = "The advisory text says the flaw is only reachable when the legacy parser is enabled."


def _signals(**values: str) -> Relevance:
    return Relevance(signals=[RelevanceSignal(name=k, value=v) for k, v in values.items()])


def _ctx(finding: Finding) -> ReviewContext:
    base = make_context()
    other = base.findings["f-leftpad"].model_copy(update={"evidence_ids": ["ev-diff-0001"]})
    return ReviewContext.build(
        [finding, other], base.evidence.values(), base.components.values()
    )


def _finding(level: RiskLevel, **updates: object) -> Finding:
    jwt = make_context().findings["f-jwt"]
    return jwt.model_copy(update={"risk_level": level, **updates})


def _adjustment(**updates: object) -> RiskAdjustment:
    base = {
        "finding_id": "f-jwt",
        "from_level": "high",
        "to_level": "medium",
        "direction": "lower",
        "reason": REASON,
        "evidence_ids": ["ev-grype-0001"],
    }
    return RiskAdjustment.model_validate({**base, **updates})


def _check(level: RiskLevel, raw: RiskAdjustment, **updates: object) -> RiskAdjustment:
    return check_adjustment(raw, _ctx(_finding(level, **updates)), {"f-jwt"})


def test_one_step_change_with_valid_citation_is_accepted() -> None:
    result = _check(RiskLevel.HIGH, _adjustment())
    assert result.status == "accepted" and result.rejected_reason is None


def test_raising_one_level_is_accepted() -> None:
    raw = _adjustment(from_level="medium", to_level="high", direction="raise")
    assert _check(RiskLevel.MEDIUM, raw).status == "accepted"


@pytest.mark.parametrize(
    ("updates", "level", "reason"),
    [
        ({"to_level": "low"}, RiskLevel.HIGH, "exactly one level"),
        ({"to_level": "high", "direction": "raise"}, RiskLevel.MEDIUM, "does not match"),
        ({"direction": "raise"}, RiskLevel.HIGH, "direction"),
        ({"from_level": "critical", "to_level": "high"}, RiskLevel.HIGH, "does not match"),
        ({"to_level": "high", "direction": "lower"}, RiskLevel.HIGH, "exactly one level"),
        ({}, RiskLevel.UNKNOWN, "no current risk level"),
    ],
)
def test_step_rules_reject(updates: dict[str, str], level: RiskLevel, reason: str) -> None:
    result = _check(level, _adjustment(**updates))
    assert result.status == "rejected" and reason in (result.rejected_reason or "")


def test_malicious_packages_are_never_lowered() -> None:
    raw = _adjustment(from_level="critical", to_level="high")
    result = _check(RiskLevel.CRITICAL, raw, kind=FindingKind.MALICIOUS)
    assert result.status == "rejected" and "malicious" in (result.rejected_reason or "")


def test_known_exploited_production_never_drops_below_high() -> None:
    relevance = _signals(known_exploited="yes", dependency_scope="production")
    low = _check(RiskLevel.HIGH, _adjustment(), relevance=relevance)
    assert low.status == "rejected" and "known exploited" in (low.rejected_reason or "")
    still_high = _adjustment(from_level="critical", to_level="high")
    assert _check(RiskLevel.CRITICAL, still_high, relevance=relevance).status == "accepted"


def test_known_exploited_in_development_has_no_floor() -> None:
    relevance = _signals(known_exploited="yes", dependency_scope="development")
    assert _check(RiskLevel.HIGH, _adjustment(), relevance=relevance).status == "accepted"


@pytest.mark.parametrize(
    "evidence_ids",
    [[], ["ev-nope"], ["ev-diff-0001"], ["ev-grype-0001", "ev-diff-0001"]],
)
def test_citations_must_exist_and_belong_to_the_finding(evidence_ids: list[str]) -> None:
    result = _check(RiskLevel.HIGH, _adjustment(evidence_ids=evidence_ids))
    assert result.status == "rejected" and "evidence" in (result.rejected_reason or "")


def test_reason_must_pass_the_evidence_validator() -> None:
    result = _check(RiskLevel.HIGH, _adjustment(reason="This package is safe to ignore."))
    assert result.status == "rejected" and "safe" in (result.rejected_reason or "")


def test_unknown_finding_is_rejected() -> None:
    result = _check(RiskLevel.HIGH, _adjustment(finding_id="f-ghost"))
    assert result.status == "rejected" and "unknown finding" in (result.rejected_reason or "")
