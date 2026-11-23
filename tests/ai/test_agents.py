from __future__ import annotations

from typing import Any

from guardian.ai.context import ReviewContext
from guardian.ai.graph import mermaid_diagram, run_ai_review
from guardian.ai.state import FixAction
from guardian.models import ClaimKind, LlmStatus
from tests.ai.factories import make_context
from tests.ai.fake_llms import RoutingLLM

JWT_CLAIM = {
    "text": "jsonwebtoken 0.4.0 reaches the app via express-jwt 0.1.3 and is affected by "
    "CVE-2015-9235; 4.2.2 fixes it.",
    "evidence_ids": ["ev-grype-0001"],
    "kind": "evidence",
    "uncertainty": None,
}
IMPACT_CLAIM = {
    "text": "An attacker can certainly forge tokens in production.",
    "evidence_ids": ["ev-grype-0001"],
    "kind": "evidence",
    "uncertainty": None,
}
LEFTPAD_CLAIM = {
    "text": "left-pad 1.3.0 was added in package.json without review.",
    "evidence_ids": ["ev-diff-0001"],
    "kind": "evidence",
    "uncertainty": None,
}
FAKE_CLAIM = {
    "text": "jsonwebtoken 0.4.0 is also affected by CVE-2026-31337.",
    "evidence_ids": ["ev-grype-0001"],
    "kind": "evidence",
    "uncertainty": None,
}


def _proposal(**overrides: Any) -> dict[str, Any]:
    base = {
        "finding_id": "f-jwt",
        "action": "upgrade",
        "target_version": "4.2.2",
        "rationale": "4.2.2 is the scanner-reported fix for CVE-2015-9235.",
        "rollback": "Revert the lockfile change.",
        "breaking_change_risk": "high",
        "evidence_ids": ["ev-grype-0001"],
    }
    return {**base, **overrides}


def _claims(*items: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"claims": list(items)}]


def _full_llm() -> RoutingLLM:
    return RoutingLLM(
        vuln_analyst=_claims(JWT_CLAIM, IMPACT_CLAIM),
        change_analyst=_claims(LEFTPAD_CLAIM),
        risk_critic=[{"reviews": []}],  # replaced per test where needed
        remediation_planner=[
            {
                "proposals": [
                    _proposal(),
                    _proposal(target_version="9.9.9"),
                    _proposal(
                        finding_id="f-leftpad",
                        action="remove_dependency",
                        target_version=None,
                        rationale="left-pad was added without review; removing it undoes it.",
                        breaking_change_risk="low",
                        evidence_ids=["ev-diff-0001"],
                    ),
                ]
            }
        ],
        report_writer=_claims({**JWT_CLAIM, "text": "jsonwebtoken 0.4.0 has critical risk."}),
    )


def test_agents_run_in_order_and_hand_off_evidence() -> None:
    llm = _full_llm()
    result = run_ai_review(make_context(), llm)
    assert result.llm_status == LlmStatus.OK
    assert llm.agents_called() == [
        "vuln_analyst",
        "change_analyst",
        "risk_critic",
        "remediation_planner",
        "report_writer",
    ]
    agents = [t.agent for t in result.trace]
    assert agents == [
        "triage",
        "relevance",
        "vuln_analyst",
        "change_analyst",
        "evidence_validator",
        "risk_critic",
        "remediation_candidates",
        "remediation_planner",
        "report_writer",
    ]
    assert result.trace[0].produced == ["pack-f-jwt", "pack-f-leftpad"]
    assert "pack-f-jwt" in result.trace[2].consumed


def test_analysts_only_see_their_own_evidence_packs() -> None:
    llm = _full_llm()
    run_ai_review(make_context(), llm)
    vuln_prompt = next(u for a, _, u in llm.calls if a == "vuln_analyst")
    change_prompt = next(u for a, _, u in llm.calls if a == "change_analyst")
    assert "f-jwt" in vuln_prompt and "f-leftpad" not in vuln_prompt
    assert "f-leftpad" in change_prompt and "f-jwt" not in change_prompt


def test_rejected_claim_triggers_one_revision_round() -> None:
    llm = RoutingLLM(vuln_analyst=_claims(FAKE_CLAIM), analyst_revision=_claims(JWT_CLAIM))
    result = run_ai_review(make_context(), llm)
    assert llm.agents_called().count("analyst_revision") == 1
    revision_prompt = next(u for a, _, u in llm.calls if a == "analyst_revision")
    assert "CVE-2026-31337 is not in the cited findings" in revision_prompt
    original = next(c for c in result.claims if c.step == "vuln_analyst")
    revised = next(c for c in result.claims if c.step == "analyst_revision")
    assert not original.validated and revised.validated


def test_revision_happens_at_most_once() -> None:
    llm = RoutingLLM(vuln_analyst=_claims(FAKE_CLAIM), analyst_revision=_claims(FAKE_CLAIM))
    result = run_ai_review(make_context(), llm)
    assert llm.agents_called().count("analyst_revision") == 1
    assert not any(c.validated for c in result.claims if c.step == "analyst_revision")


def test_critic_can_downgrade_or_reject_but_never_accept() -> None:
    ctx = make_context()
    first = run_ai_review(
        ctx, RoutingLLM(vuln_analyst=_claims(JWT_CLAIM, IMPACT_CLAIM, FAKE_CLAIM))
    )
    ids = {c.text: c.claim_id for c in first.claims if c.step == "vuln_analyst"}
    reviews = [
        {"claim_id": ids[JWT_CLAIM["text"]], "verdict": "supported", "reason": "In the pack."},
        {
            "claim_id": ids[IMPACT_CLAIM["text"]],
            "verdict": "overstated",
            "reason": "Reachability is unknown.",
        },
        {
            "claim_id": ids[FAKE_CLAIM["text"]],
            "verdict": "supported",
            "reason": "Trying to accept.",
        },
        {"claim_id": "claim-does-not-exist", "verdict": "supported", "reason": "Ghost."},
    ]
    llm = RoutingLLM(
        vuln_analyst=_claims(JWT_CLAIM, IMPACT_CLAIM, FAKE_CLAIM),
        analyst_revision=[{"claims": []}],
        risk_critic=[{"reviews": reviews}],
    )
    result = run_ai_review(ctx, llm)
    by_text = {c.text: c for c in result.claims if c.step == "vuln_analyst"}
    assert by_text[JWT_CLAIM["text"]].validated
    assert by_text[IMPACT_CLAIM["text"]].kind == ClaimKind.INFERENCE
    assert "Reachability is unknown" in (by_text[IMPACT_CLAIM["text"]].uncertainty or "")
    assert not by_text[FAKE_CLAIM["text"]].validated, "the critic must not accept rejected claims"
    critic = next(t for t in result.trace if t.agent == "risk_critic")
    assert "claim-does-not-exist" in (critic.error or "")


def test_critic_unsupported_verdict_rejects_and_blocks_remediation() -> None:
    ctx = make_context()
    first = run_ai_review(ctx, RoutingLLM(vuln_analyst=_claims(JWT_CLAIM)))
    jwt_id = next(c.claim_id for c in first.claims if c.step == "vuln_analyst")
    llm = RoutingLLM(
        vuln_analyst=_claims(JWT_CLAIM),
        risk_critic=[
            {
                "reviews": [
                    {"claim_id": jwt_id, "verdict": "unsupported", "reason": "Path not in pack."}
                ]
            }
        ],
        remediation_planner=[{"proposals": [_proposal()]}],
    )
    result = run_ai_review(ctx, llm)
    jwt = next(c for c in result.claims if c.step == "vuln_analyst")
    assert not jwt.validated and "independent reviewer" in (jwt.rejected_reason or "")
    assert "remediation_planner" not in llm.agents_called()
    assert result.proposals == []


def test_remediation_proposals_are_checked_against_code_computed_options() -> None:
    result = run_ai_review(make_context(), _full_llm())
    by_key = {(p.finding_id, p.target_version): p for p in result.proposals}
    good = by_key[("f-jwt", "4.2.2")]
    invented = by_key[("f-jwt", "9.9.9")]
    removal = by_key[("f-leftpad", None)]
    assert good.validated and good.requires_human_approval and good.action == FixAction.UPGRADE
    assert not invented.validated
    assert "not a scanner-reported fix" in (invented.rejected_reason or "")
    assert removal.validated
    fix_claims = [c for c in result.claims if c.step == "remediation_planner"]
    assert len(fix_claims) == 3
    assert all("Requires human approval" in c.text for c in fix_claims)


def test_report_writer_output_is_validated_too() -> None:
    llm = _full_llm()
    llm.replies["report_writer"] = _claims({**FAKE_CLAIM, "text": "Summary: CVE-2026-31337."})
    result = run_ai_review(make_context(), llm)
    summary = next(c for c in result.claims if c.step == "report_writer")
    assert not summary.validated


def test_graph_diagram_lists_every_agent() -> None:
    diagram = mermaid_diagram()
    for agent in (
        "triage",
        "relevance",
        "vuln_analyst",
        "change_analyst",
        "evidence_validator",
        "analyst_revision",
        "risk_critic",
        "remediation_candidates",
        "remediation_planner",
        "report_writer",
    ):
        assert agent in diagram


def test_relevance_node_puts_signals_into_the_analyst_input() -> None:
    from guardian.models import Reachability, Relevance, RelevanceSignal, RelevanceVerdict

    base = make_context()
    relevance = Relevance(
        verdict=RelevanceVerdict.RELEVANT,
        reachability=Reachability.CONFIRMED,
        introduced_by="express-jwt",
        signals=[
            RelevanceSignal(
                name="reachability",
                value="confirmed",
                detail="imported at src/server.js:5 (via express-jwt)",
            )
        ],
    )
    jwt = base.findings["f-jwt"].model_copy(update={"relevance": relevance})
    ctx = ReviewContext.build(
        [jwt, base.findings["f-leftpad"]], base.evidence.values(), base.components.values()
    )
    llm = RoutingLLM()
    result = run_ai_review(ctx, llm)
    relevance_trace = next(t for t in result.trace if t.agent == "relevance")
    assert relevance_trace.produced == ["pack-f-jwt"]
    vuln_prompt = next(u for a, _, u in llm.calls if a == "vuln_analyst")
    assert "imported at src/server.js:5" in vuln_prompt
    assert '"reachability": "confirmed"' in vuln_prompt


def test_triage_ranks_by_relevance_before_risk() -> None:
    from guardian.models import Relevance, RelevanceVerdict, RiskLevel

    base = make_context()
    low = base.findings["f-jwt"].model_copy(
        update={"relevance": Relevance(verdict=RelevanceVerdict.LOW_RELEVANCE)}
    )
    relevant = base.findings["f-leftpad"].model_copy(
        update={
            "risk_level": RiskLevel.LOW,
            "relevance": Relevance(verdict=RelevanceVerdict.RELEVANT),
        }
    )
    ctx = ReviewContext.build([low, relevant], base.evidence.values(), base.components.values())
    assert [f.finding_id for f in ctx.top_findings(2)] == ["f-leftpad", "f-jwt"]


def _many_vulns(count: int) -> ReviewContext:
    base = make_context()
    findings = list(base.findings.values())
    jwt = base.findings["f-jwt"]
    findings += [jwt.model_copy(update={"finding_id": f"f-jwt-{i}"}) for i in range(count - 1)]
    return ReviewContext.build(
        findings, list(base.evidence.values()), list(base.components.values())
    )


def test_vuln_analyst_sends_evidence_packs_in_bounded_batches() -> None:
    llm = RoutingLLM(vuln_analyst=_claims(JWT_CLAIM))
    result = run_ai_review(_many_vulns(5), llm, pack_batch=2)
    prompts = [u for a, _, u in llm.calls if a == "vuln_analyst"]
    assert len(prompts) == 3
    assert [p.count('"finding_id"') for p in prompts] == [2, 2, 1]
    analyst = [t for t in result.trace if t.agent == "vuln_analyst"]
    assert len(analyst) == 1 and len(analyst[0].consumed) == 5
