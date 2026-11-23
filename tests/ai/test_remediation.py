from __future__ import annotations

from typing import Any

from guardian.ai.remediation import build_candidate, validate_proposal
from guardian.ai.schemas import LLMProposal
from guardian.ai.state import FixAction
from guardian.ai.triage import triage
from tests.ai.factories import make_context


def _setup() -> tuple[Any, Any, Any]:
    ctx = make_context()
    packs = {p.finding_id: p for p in triage(ctx, 20)}
    candidates = {f: build_candidate(p) for f, p in packs.items()}
    return ctx, packs, candidates


def _check(**fields: Any) -> tuple[bool, str]:
    ctx, packs, candidates = _setup()
    base = {
        "finding_id": "f-jwt",
        "action": "upgrade",
        "target_version": "4.2.2",
        "rationale": "4.2.2 fixes CVE-2015-9235.",
        "rollback": "Revert the lockfile.",
        "breaking_change_risk": "high",
        "evidence_ids": ["ev-grype-0001"],
    }
    proposal, _ = validate_proposal(
        LLMProposal.model_validate({**base, **fields}), candidates, packs, ctx
    )
    return proposal.validated, proposal.rejected_reason or ""


def test_candidates_for_transitive_vulnerability() -> None:
    _, _, candidates = _setup()
    jwt = candidates["f-jwt"]
    assert jwt.allowed_actions == [
        FixAction.UPGRADE_PARENT,
        FixAction.UPGRADE,
        FixAction.ESCALATE_REVIEW,
    ]
    assert jwt.upgrade_parent == "express-jwt"
    assert jwt.allowed_target_versions == ["4.2.2"]
    assert jwt.major_version_change is True


def test_candidates_for_anomaly() -> None:
    _, _, candidates = _setup()
    assert candidates["f-leftpad"].allowed_actions == [
        FixAction.REMOVE_DEPENDENCY,
        FixAction.ESCALATE_REVIEW,
    ]


def test_valid_upgrade_is_accepted() -> None:
    ok, reason = _check()
    assert ok, reason


def test_parent_upgrade_is_accepted_without_version() -> None:
    ok, reason = _check(
        action="upgrade_parent",
        target_version=None,
        rationale="express-jwt pulls the vulnerable jsonwebtoken.",
    )
    assert ok, reason


def test_invented_version_is_rejected() -> None:
    ok, reason = _check(target_version="5.0.0")
    assert not ok and "not a scanner-reported fix" in reason


def test_disallowed_action_is_rejected() -> None:
    ok, reason = _check(action="pin_action_sha", target_version=None)
    assert not ok and "not allowed here" in reason


def test_downplayed_major_upgrade_is_rejected() -> None:
    ok, reason = _check(breaking_change_risk="low")
    assert not ok and "major version change" in reason


def test_foreign_evidence_is_rejected() -> None:
    ok, reason = _check(evidence_ids=["ev-diff-0001"])
    assert not ok and "another finding" in reason


def test_auto_apply_language_is_rejected() -> None:
    ok, reason = _check(rollback="Not needed, the fix is automatically applied.")
    assert not ok and "without human approval" in reason


def test_unknown_finding_is_rejected() -> None:
    ok, reason = _check(finding_id="f-unknown")
    assert not ok and "no remediation candidate" in reason


def test_rationale_still_goes_through_claim_validator() -> None:
    ok, reason = _check(rationale="Also fixes CVE-2026-31337.")
    assert not ok and "CVE-2026-31337" in reason


def test_describing_an_unreviewed_change_is_not_auto_apply() -> None:
    ctx, packs, candidates = _setup()
    proposal = LLMProposal.model_validate(
        {
            "finding_id": "f-leftpad",
            "action": "remove_dependency",
            "target_version": None,
            "rationale": "left-pad was added without review.",
            "rollback": "Re-add it after review.",
            "breaking_change_risk": "low",
            "evidence_ids": ["ev-diff-0001"],
        }
    )
    checked, _ = validate_proposal(proposal, candidates, packs, ctx)
    assert checked.validated, checked.rejected_reason
    ok, reason = _check(rollback="It will be merged without approval.")
    assert not ok and "without human approval" in reason


def test_fix_may_name_the_lockfile_but_an_analyst_claim_may_not() -> None:
    ok, reason = _check(rollback="Revert package-lock.json to the previous commit.")
    assert ok, reason
    ctx, _, _ = _setup()
    from guardian.ai.validator import validate
    from tests.ai.factories import claim

    checked = validate(claim("The flaw is in package-lock.json.", ["ev-grype-0001"]), ctx)
    assert not checked.validated
