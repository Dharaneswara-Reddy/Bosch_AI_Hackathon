from __future__ import annotations

from typing import Any

from guardian.ai.graph import run_ai_review
from guardian.ai.llm import FallbackClient, LLMError
from guardian.ai.prompts import REMEDIATION_PLANNER
from guardian.ai.remediation import build_candidate, planner_candidates
from guardian.ai.runtime import AgentRuntime
from guardian.ai.schemas import STRICT_PLANNER_SCHEMA, PlannerReply
from guardian.ai.triage import triage
from guardian.models import LlmStatus, RiskLevel
from tests.ai.factories import make_context
from tests.ai.fake_llms import RoutingLLM
from tests.ai.test_agents import JWT_CLAIM, LEFTPAD_CLAIM, _claims, _proposal


class PlannerRateLimited(RoutingLLM):
    """Every agent answers except the planner, which hits a 429."""

    def complete(
        self, system: str, user: str, schema: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        if "Agent: remediation_planner" in system:
            self.calls.append(("remediation_planner", system, user))
            raise LLMError("Provider returned HTTP 429. Rate limited.")
        return super().complete(system, user, schema, timeout)


class Recording:
    name = "recording"

    def __init__(self, fail_first: int = 0) -> None:
        self.timeouts: list[float] = []
        self.fail_first = fail_first

    def complete(
        self, system: str, user: str, schema: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        self.timeouts.append(timeout)
        if len(self.timeouts) <= self.fail_first:
            raise LLMError("Provider returned HTTP 429. Rate limited.")
        return {"proposals": []}


def _candidates() -> tuple[Any, list[Any]]:
    ctx = make_context()
    packs = triage(ctx, "low", 200)[1]
    return ctx, [build_candidate(p) for p in packs]


def test_planner_only_gets_high_critical_or_review_required_findings() -> None:
    ctx, candidates = _candidates()
    chosen = planner_candidates(candidates, ctx.findings, limit=10)
    assert [c.finding_id for c in chosen] == ["f-jwt"]
    ctx.findings["f-leftpad"].review_required = True
    chosen = planner_candidates(candidates, ctx.findings, limit=10)
    assert [c.finding_id for c in chosen] == ["f-jwt", "f-leftpad"]


def test_planner_candidates_are_capped_worst_first() -> None:
    ctx, candidates = _candidates()
    ctx.findings["f-leftpad"].risk_level = RiskLevel.HIGH
    chosen = planner_candidates(candidates, ctx.findings, limit=1)
    assert [c.finding_id for c in chosen] == ["f-jwt"]


def test_planner_prompt_excludes_low_priority_candidates() -> None:
    llm = RoutingLLM(
        vuln_analyst=_claims(JWT_CLAIM),
        change_analyst=_claims(LEFTPAD_CLAIM),
        remediation_planner=[{"proposals": [_proposal()]}],
    )
    run_ai_review(make_context(), llm)
    prompt = next(u for a, _, u in llm.calls if a == "remediation_planner")
    assert "f-jwt" in prompt and "f-leftpad" not in prompt
    assert llm.agents_called().count("remediation_planner") == 1


def test_planner_rate_limit_is_reported_clearly_and_scan_stays_ok() -> None:
    llm = PlannerRateLimited(
        vuln_analyst=_claims(JWT_CLAIM),
        change_analyst=_claims(LEFTPAD_CLAIM),
    )
    result = run_ai_review(make_context(), llm)
    planner = next(t for t in result.trace if t.agent == "remediation_planner")
    assert (planner.error or "").startswith(
        "AI planner unavailable (rate limited) — rule-based fixes shown"
    )
    assert result.step_errors["remediation_planner"] == planner.error
    assert result.proposals == []
    assert result.llm_status == LlmStatus.OK


def test_planner_gets_its_own_timeout_and_ignores_an_open_breaker() -> None:
    llm = Recording()
    runtime = AgentRuntime(ctx=make_context(), client=llm, timeout=5)
    runtime.open_reason = "HTTP 429"
    data: dict[str, Any] = {"remediation_candidates": [], "evidence_packs": []}
    reply, error = runtime.ask(
        REMEDIATION_PLANNER, data, STRICT_PLANNER_SCHEMA, PlannerReply, reserved_timeout=60
    )
    assert error is None and reply is not None
    assert llm.timeouts == [60]


def test_reserved_call_gives_providers_that_failed_earlier_another_chance() -> None:
    groq = Recording(fail_first=1)
    chain = FallbackClient([("groq:m", groq)], skipped={})
    runtime = AgentRuntime(ctx=make_context(), client=chain, timeout=5)
    data: dict[str, Any] = {"remediation_candidates": [], "evidence_packs": []}
    runtime.ask(REMEDIATION_PLANNER, data, STRICT_PLANNER_SCHEMA, PlannerReply)
    assert "groq:m" in chain.failed
    reply, error = runtime.ask(
        REMEDIATION_PLANNER, data, STRICT_PLANNER_SCHEMA, PlannerReply, reserved_timeout=60
    )
    assert error is None and reply is not None
    assert groq.timeouts == [5, 60]
