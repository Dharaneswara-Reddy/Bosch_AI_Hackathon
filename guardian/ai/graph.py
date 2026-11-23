"""LangGraph orchestration of the Guardian's agents.

                       ┌─► vuln_analyst ──────┐   one set per package group,
    triage ─► relevance ──┼─► change_analyst ────┼─► evidence_validator ─┬─► risk_critic ─►
                          └─► risk_analyst ──────┘          ▲            │
                          (parallel, LangGraph Send)        └─ analyst_revision (once, if rejected)
    ─► remediation_candidates ─► remediation_planner ─► report_writer ─► END

Every hand-off is a typed object (``state.py``). Facts only come from tool
output; agents cite them by ID, and code checks every citation. The scan never
depends on this graph: LLM problems become ``llm_status``, never an exception.
"""

from __future__ import annotations

import json
from pathlib import Path

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field

from guardian.ai.agents import PACK_BATCH, Agents, to_agent_claim
from guardian.ai.context import ReviewContext
from guardian.ai.guardrails import find_injection_markers
from guardian.ai.llm import LLMClient
from guardian.ai.runtime import AgentRuntime
from guardian.ai.schemas import LLMReply
from guardian.ai.state import GuardianState, RemediationProposal
from guardian.config import (
    AI_CONCURRENCY,
    AI_MAX_GROUPS,
    AI_MIN_RISK,
    AI_PLANNER_MAX,
    AI_PLANNER_TIMEOUT_S,
)
from guardian.models import AgentClaim, AgentTrace, LlmStatus, RiskAdjustment

DEFAULT_TIMEOUT_S = 30.0
TOP_FINDING_PLACEHOLDER = "@top-finding"
CLAIM_FIELDS = ("text", "evidence_ids", "kind", "uncertainty")
PREPARE = ("triage", "relevance")
BRANCH = ("vuln_analyst", "change_analyst", "risk_analyst")
TAIL = ("risk_critic", "remediation_candidates", "remediation_planner", "report_writer")


class AIReviewResult(BaseModel):
    claims: list[AgentClaim]
    proposals: list[RemediationProposal] = Field(default_factory=list)
    risk_adjustments: list[RiskAdjustment] = Field(default_factory=list)
    agreement: dict[str, bool] = Field(default_factory=dict)
    provider_by_branch: dict[str, str] = Field(default_factory=dict)
    llm_status: LlmStatus
    llm_calls: int = 0
    step_errors: dict[str, str] = Field(default_factory=dict)
    injection_markers: list[str] = Field(default_factory=list)
    secrets_redacted: int = 0
    trace: list[AgentTrace] = Field(default_factory=list)


def build_graph(
    agents: Agents,
) -> CompiledStateGraph[GuardianState, None, GuardianState, GuardianState]:
    graph = StateGraph(GuardianState)
    for name in (*PREPARE, *BRANCH, "evidence_validator", "analyst_revision", *TAIL):
        graph.add_node(name, getattr(agents, name))
    graph.add_edge(START, PREPARE[0])
    graph.add_edge(*PREPARE)
    graph.add_conditional_edges(PREPARE[-1], agents.fan_out, [*BRANCH, "evidence_validator"])
    for name in BRANCH:
        graph.add_edge(name, "evidence_validator")
    graph.add_conditional_edges(
        "evidence_validator",
        lambda state: "analyst_revision" if agents.needs_revision(state) else TAIL[0],
        ["analyst_revision", TAIL[0]],
    )
    graph.add_edge("analyst_revision", "evidence_validator")
    for left, right in zip(TAIL, TAIL[1:], strict=False):
        graph.add_edge(left, right)
    graph.add_edge(TAIL[-1], END)
    return graph.compile()


def _status(runtime: AgentRuntime, client: LLMClient) -> LlmStatus:
    if client.name == "none" or runtime.unavailable:
        return LlmStatus.UNAVAILABLE
    if runtime.attempted and not runtime.succeeded:
        return LlmStatus.FAILED
    return LlmStatus.OK


def run_ai_review(
    ctx: ReviewContext,
    client: LLMClient,
    injected: list[AgentClaim] | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    min_risk: str = AI_MIN_RISK,
    max_groups: int = AI_MAX_GROUPS,
    pack_batch: int = PACK_BATCH,
    concurrency: int = AI_CONCURRENCY,
    planner_timeout: float = AI_PLANNER_TIMEOUT_S,
    planner_max: int = AI_PLANNER_MAX,
) -> AIReviewResult:
    """Run the agent graph once. Never raises for LLM problems.

    ``concurrency`` bounds how many branch agents run at once (LangGraph ``max_concurrency``).
    """
    runtime = AgentRuntime(ctx=ctx, client=client, timeout=timeout)
    agents = Agents(runtime, min_risk, max_groups, pack_batch, planner_timeout, planner_max)
    initial: GuardianState = {
        "pending": list(injected or []),
        "claims": [],
        "revision_round": 0,
        "trace": [],
        "errors": {},
    }
    final = build_graph(agents).invoke(initial, config={"max_concurrency": concurrency})
    packs_json = json.dumps([p.model_dump() for p in final.get("packs", [])], default=str)
    return AIReviewResult(
        claims=final.get("claims", []),
        proposals=final.get("proposals", []),
        risk_adjustments=final.get("reviewed_adjustments", []),
        agreement=final.get("agreement", {}),
        provider_by_branch=dict(runtime.answered_by),
        llm_status=_status(runtime, client),
        llm_calls=runtime.calls,
        step_errors=final.get("errors", {}),
        injection_markers=find_injection_markers(f"{packs_json} {ctx.project_text}"),
        secrets_redacted=runtime.redactions,
        trace=[*final.get("trace", []), *_provider_trace(client)],
    )


def _provider_trace(client: LLMClient) -> list[AgentTrace]:
    """One row naming the provider chain, which providers failed, and which were skipped."""
    labels: list[str] = getattr(client, "labels", [])
    if not labels:
        return []
    failed: dict[str, str] = getattr(client, "failed", {})
    skipped: dict[str, str] = getattr(client, "skipped", {})
    notes = [f"{label} failed: {reason}" for label, reason in failed.items()]
    notes += [f"{name}: {reason}" for name, reason in skipped.items()]
    return [AgentTrace(agent="llm_providers", produced=labels, error="; ".join(notes) or None)]


def load_injected_claims(path: Path, ctx: ReviewContext) -> list[AgentClaim]:
    """Load the ``--inject-claim`` file. ``@top-finding`` cites the top finding's first evidence."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "claims" not in data:
        data = {"claims": [{k: data[k] for k in CLAIM_FIELDS if k in data}]}
    reply = LLMReply.model_validate(data if isinstance(data, dict) else {"claims": data})
    top = ctx.top_findings(1)
    top_evidence = top[0].evidence_ids[0] if top and top[0].evidence_ids else "UNKNOWN"
    claims = []
    for raw in reply.claims:
        ids = [top_evidence if i == TOP_FINDING_PLACEHOLDER else i for i in raw.evidence_ids]
        claims.append(to_agent_claim("injected", raw.model_copy(update={"evidence_ids": ids})))
    return claims


def mermaid_diagram() -> str:
    """The agent graph as Mermaid (for the architecture document)."""
    from guardian.ai.llm import NoneClient

    runtime = AgentRuntime(ctx=ReviewContext.build([], [], []), client=NoneClient(), timeout=1)
    return build_graph(Agents(runtime, AI_MIN_RISK, AI_MAX_GROUPS)).get_graph().draw_mermaid()
