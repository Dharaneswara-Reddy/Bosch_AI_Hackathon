"""The agents. Each is a LangGraph node with one job and a typed hand-off.

Order (see ``graph.py``)::

  triage -> vuln_analyst -> change_analyst -> evidence_validator
         -> [analyst_revision -> evidence_validator]   (once, only if claims were rejected)
         -> risk_critic -> remediation_candidates -> remediation_planner -> report_writer

LLM agents: vuln_analyst, change_analyst, analyst_revision, risk_critic,
remediation_planner, report_writer. Code-only agents: triage,
evidence_validator, remediation_candidates (and the checks applied to the
critic's verdicts and the planner's proposals).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from guardian.ai.prompts import (
    ANALYST_REVISION,
    CHANGE_ANALYST,
    REMEDIATION_PLANNER,
    REPORT_WRITER,
    RISK_CRITIC,
    VULN_ANALYST,
    AgentRole,
)
from guardian.ai.remediation import build_candidates, validate_proposal
from guardian.ai.runtime import AgentRuntime
from guardian.ai.schemas import (
    STRICT_CRITIC_SCHEMA,
    STRICT_PLANNER_SCHEMA,
    STRICT_REPLY_SCHEMA,
    ClaimReview,
    CriticReply,
    LLMClaim,
    LLMReply,
    PlannerReply,
)
from guardian.ai.state import EvidencePack, GuardianState
from guardian.ai.triage import triage
from guardian.ai.validator import validate
from guardian.models import AgentClaim, AgentTrace, ClaimKind

ANALYSTS = (VULN_ANALYST.name, CHANGE_ANALYST.name, ANALYST_REVISION.name)
Update = dict[str, Any]
# Small batches keep each request under low tokens-per-minute provider limits.
PACK_BATCH = 5


def claim_id(step: str, text: str, evidence_ids: list[str]) -> str:
    digest = hashlib.sha256(json.dumps([step, text, sorted(evidence_ids)]).encode()).hexdigest()
    return f"claim-{digest[:16]}"


def to_agent_claim(step: str, raw: LLMClaim) -> AgentClaim:
    return AgentClaim(
        claim_id=claim_id(step, raw.text, raw.evidence_ids),
        step=step,
        text=raw.text,
        evidence_ids=list(raw.evidence_ids),
        kind=ClaimKind(raw.kind),
        uncertainty=raw.uncertainty,
    )


def _trace(agent: str, runtime: AgentRuntime, before: int, **fields: Any) -> AgentTrace:
    return AgentTrace(
        agent=agent,
        llm_calls=runtime.calls - before,
        provider=runtime.answered_by.get(agent),
        **fields,
    )


def _pack_view(pack: EvidencePack) -> dict[str, Any]:
    return pack.model_dump(exclude={"pack_id"})


class Agents:
    """Node functions bound to one run's runtime."""

    def __init__(self, runtime: AgentRuntime, top_n: int, pack_batch: int = PACK_BATCH) -> None:
        self.rt = runtime
        self.top_n = top_n
        self.pack_batch = pack_batch

    def _packs_by_finding(self, state: GuardianState) -> dict[str, EvidencePack]:
        return {p.finding_id: p for p in state.get("packs", [])}

    def _cited_packs(self, state: GuardianState, claims: list[AgentClaim]) -> list[dict[str, Any]]:
        """Only the evidence packs the given claims cite (critic and reviser see no more)."""
        packs = self._packs_by_finding(state)
        cited = {f.finding_id for c in claims for f in self.rt.ctx.findings_citing(c.evidence_ids)}
        return [_pack_view(packs[f]) for f in sorted(cited) if f in packs]

    def triage(self, state: GuardianState) -> Update:
        packs = triage(self.rt.ctx, self.top_n)
        project = self.rt.ctx.project_text[:2000]
        trace = AgentTrace(
            agent="triage",
            consumed=[f"{len(self.rt.ctx.findings)} findings"],
            produced=[p.pack_id for p in packs],
        )
        return {"packs": packs, "project_text": project, "trace": [trace]}

    def relevance(self, state: GuardianState) -> Update:
        """Code-only: attach each finding's relevance signals to its evidence pack."""
        packs = []
        for pack in state.get("packs", []):
            finding = self.rt.ctx.findings.get(pack.finding_id)
            relevance = finding.relevance if finding is not None else None
            reach = relevance.reachability.value if relevance is not None else "unknown"
            packs.append(pack.model_copy(update={"relevance": relevance, "reachability": reach}))
        assessed = [p.pack_id for p in packs if p.relevance is not None]
        trace = AgentTrace(
            agent="relevance", consumed=[p.pack_id for p in packs], produced=assessed
        )
        return {"packs": packs, "trace": [trace]}

    def _analyst(self, agent: AgentRole, state: GuardianState, kinds: set[str]) -> Update:
        packs = [p for p in state.get("packs", []) if p.kind in kinds]
        pending = list(state.get("pending", []))
        if not packs:
            return {"pending": pending, "trace": [AgentTrace(agent=agent.name, error="no input")]}
        before = self.rt.calls
        produced: list[AgentClaim] = []
        error = None
        for start in range(0, len(packs), self.pack_batch):
            data = {
                "evidence_packs": [_pack_view(p) for p in packs[start : start + self.pack_batch]],
                "project_description": state.get("project_text", ""),
            }
            reply, error = self.rt.ask(agent, data, STRICT_REPLY_SCHEMA, LLMReply)
            produced += [to_agent_claim(agent.name, c) for c in reply.claims] if reply else []
            if error:
                break
        trace = _trace(
            agent.name,
            self.rt,
            before,
            consumed=[p.pack_id for p in packs],
            produced=[c.claim_id for c in produced],
            error=error,
        )
        update: Update = {"pending": pending + produced, "trace": [trace]}
        if error:
            update["errors"] = {agent.name: error}
        return update

    def vuln_analyst(self, state: GuardianState) -> Update:
        return self._analyst(VULN_ANALYST, state, {"vulnerability", "malicious"})

    def change_analyst(self, state: GuardianState) -> Update:
        return self._analyst(CHANGE_ANALYST, state, {"anomaly"})

    def evidence_validator(self, state: GuardianState) -> Update:
        checked = [validate(c, self.rt.ctx) for c in state.get("pending", [])]
        trace = AgentTrace(
            agent="evidence_validator",
            consumed=[c.claim_id for c in checked],
            accepted=sum(c.validated for c in checked),
            rejected=sum(not c.validated for c in checked),
        )
        return {"claims": list(state.get("claims", [])) + checked, "pending": [], "trace": [trace]}

    def needs_revision(self, state: GuardianState) -> bool:
        if state.get("revision_round", 0) >= 1 or self.rt.blocked is not None:
            return False
        return any(not c.validated and c.step in ANALYSTS for c in state.get("claims", []))

    def analyst_revision(self, state: GuardianState) -> Update:
        rejected = [c for c in state.get("claims", []) if not c.validated and c.step in ANALYSTS]
        data = {
            "rejected_claims": [
                {
                    "text": c.text,
                    "evidence_ids": c.evidence_ids,
                    "rejected_reason": c.rejected_reason,
                }
                for c in rejected
            ],
            "evidence_packs": self._cited_packs(state, rejected),
        }
        before = self.rt.calls
        reply, error = self.rt.ask(ANALYST_REVISION, data, STRICT_REPLY_SCHEMA, LLMReply)
        produced = [to_agent_claim(ANALYST_REVISION.name, c) for c in reply.claims] if reply else []
        trace = _trace(
            ANALYST_REVISION.name,
            self.rt,
            before,
            consumed=[c.claim_id for c in rejected],
            produced=[c.claim_id for c in produced],
            error=error,
        )
        update: Update = {"pending": produced, "revision_round": 1, "trace": [trace]}
        if error:
            update["errors"] = {ANALYST_REVISION.name: error}
        return update

    def risk_critic(self, state: GuardianState) -> Update:
        claims = list(state.get("claims", []))
        under_review = [c for c in claims if c.validated and c.step in ANALYSTS]
        if not under_review:
            return {"trace": [AgentTrace(agent=RISK_CRITIC.name, error="no input")]}
        data = {
            "claims": [
                {
                    "claim_id": c.claim_id,
                    "text": c.text,
                    "kind": c.kind.value,
                    "evidence_ids": c.evidence_ids,
                }
                for c in under_review
            ],
            "evidence_packs": self._cited_packs(state, under_review),
        }
        before = self.rt.calls
        reply, error = self.rt.ask(RISK_CRITIC, data, STRICT_CRITIC_SCHEMA, CriticReply)
        reviews = {r.claim_id: r for r in reply.reviews} if reply else {}
        ids = {c.claim_id for c in under_review}
        revised = [
            _apply_review(c, reviews.get(c.claim_id)) if c.claim_id in ids else c for c in claims
        ]
        reviewed = [c for c in revised if c.claim_id in ids]
        unknown = sorted(set(reviews) - ids)
        trace = _trace(
            RISK_CRITIC.name,
            self.rt,
            before,
            consumed=sorted(ids),
            accepted=sum(c.validated for c in reviewed),
            rejected=sum(not c.validated for c in reviewed),
            error=error or (f"ignored unknown claim IDs: {unknown}" if unknown else None),
        )
        update: Update = {"claims": revised, "trace": [trace]}
        if error:
            update["errors"] = {RISK_CRITIC.name: error}
        return update

    def remediation_candidates(self, state: GuardianState) -> Update:
        accepted_claims = [c for c in state.get("claims", []) if c.validated and c.step in ANALYSTS]
        accepted = {
            f.finding_id
            for c in accepted_claims
            for f in self.rt.ctx.findings_citing(c.evidence_ids)
        }
        candidates = build_candidates(state.get("packs", []), accepted)
        trace = AgentTrace(
            agent="remediation_candidates",
            consumed=sorted(accepted),
            produced=[c.finding_id for c in candidates],
        )
        return {"candidates": candidates, "trace": [trace]}

    def remediation_planner(self, state: GuardianState) -> Update:
        candidates = state.get("candidates", [])
        if not candidates:
            return {"trace": [AgentTrace(agent=REMEDIATION_PLANNER.name, error="no input")]}
        packs = self._packs_by_finding(state)
        data = {
            "remediation_candidates": [c.model_dump(mode="json") for c in candidates],
            "evidence_packs": [_pack_view(packs[c.finding_id]) for c in candidates],
        }
        before = self.rt.calls
        reply, error = self.rt.ask(REMEDIATION_PLANNER, data, STRICT_PLANNER_SCHEMA, PlannerReply)
        by_id = {c.finding_id: c for c in candidates}
        checked = [
            validate_proposal(p, by_id, packs, self.rt.ctx)
            for p in (reply.proposals if reply else [])
        ]
        proposals, claims = [p for p, _ in checked], [c for _, c in checked]
        trace = _trace(
            REMEDIATION_PLANNER.name,
            self.rt,
            before,
            consumed=[c.finding_id for c in candidates],
            produced=[p.proposal_id for p in proposals],
            accepted=sum(p.validated for p in proposals),
            rejected=sum(not p.validated for p in proposals),
            error=error,
        )
        update: Update = {
            "proposals": proposals,
            "claims": list(state.get("claims", [])) + claims,
            "trace": [trace],
        }
        if error:
            update["errors"] = {REMEDIATION_PLANNER.name: error}
        return update

    def report_writer(self, state: GuardianState) -> Update:
        claims = list(state.get("claims", []))
        validated = [c for c in claims if c.validated and c.step != "injected"]
        if not validated:
            return {"trace": [AgentTrace(agent=REPORT_WRITER.name, error="no input")]}
        data = {
            "validated_claims": [
                {"text": c.text, "kind": c.kind.value, "evidence_ids": c.evidence_ids}
                for c in validated
            ]
        }
        before = self.rt.calls
        reply, error = self.rt.ask(REPORT_WRITER, data, STRICT_REPLY_SCHEMA, LLMReply)
        produced = [
            validate(to_agent_claim(REPORT_WRITER.name, c), self.rt.ctx)
            for c in (reply.claims if reply else [])
        ]
        trace = _trace(
            REPORT_WRITER.name,
            self.rt,
            before,
            consumed=[c.claim_id for c in validated],
            produced=[c.claim_id for c in produced],
            accepted=sum(c.validated for c in produced),
            rejected=sum(not c.validated for c in produced),
            error=error,
        )
        update: Update = {"claims": claims + produced, "trace": [trace]}
        if error:
            update["errors"] = {REPORT_WRITER.name: error}
        return update


def _apply_review(claim: AgentClaim, review: ClaimReview | None) -> AgentClaim:
    """The critic can only make the output more conservative, never accept anything new."""
    if review is None or review.verdict == "supported":
        return claim
    if review.verdict == "overstated":
        return claim.model_copy(
            update={"kind": ClaimKind.INFERENCE, "uncertainty": f"reviewer: {review.reason}"}
        )
    return claim.model_copy(
        update={"validated": False, "rejected_reason": f"independent reviewer: {review.reason}"}
    )
