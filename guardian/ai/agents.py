"""The agents. Each is a LangGraph node with one job and a typed hand-off.

Order (see ``graph.py``)::

  triage -> relevance -> per package group, in parallel:
                           vuln_analyst | change_analyst (anomalies only) | risk_analyst
         -> evidence_validator
         -> [analyst_revision -> evidence_validator]   (once, only if claims were rejected)
         -> risk_critic -> remediation_candidates -> remediation_planner -> report_writer

LLM agents: vuln_analyst, change_analyst, risk_analyst, analyst_revision, risk_critic,
remediation_planner, report_writer. Code-only agents: triage,
evidence_validator, remediation_candidates (and the checks applied to the
critic's verdicts, the risk analyst's adjustments and the planner's proposals).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from langgraph.types import Send

from guardian.ai.prompts import (
    ANALYST_REVISION,
    CHANGE_ANALYST,
    REMEDIATION_PLANNER,
    REPORT_WRITER,
    RISK_ANALYST,
    RISK_CRITIC,
    VULN_ANALYST,
    AgentRole,
)
from guardian.ai.remediation import build_candidates, planner_candidates, validate_proposal
from guardian.ai.risk_rules import check_adjustment
from guardian.ai.runtime import AgentRuntime, branch_key
from guardian.ai.schemas import (
    STRICT_CRITIC_SCHEMA,
    STRICT_PLANNER_SCHEMA,
    STRICT_REPLY_SCHEMA,
    STRICT_RISK_SCHEMA,
    AdjustmentReview,
    ClaimReview,
    CriticReply,
    LLMClaim,
    LLMReply,
    PlannerReply,
    RiskReply,
)
from guardian.ai.state import BranchInput, EvidencePack, GuardianState, RemediationCandidate
from guardian.ai.triage import triage
from guardian.ai.validator import validate
from guardian.config import AI_PLANNER_MAX, AI_PLANNER_TIMEOUT_S
from guardian.models import AgentClaim, AgentTrace, ClaimKind, RiskAdjustment

ANALYSTS = (VULN_ANALYST.name, CHANGE_ANALYST.name, ANALYST_REVISION.name)
VULN_KINDS = {"vulnerability", "malicious"}
ANOMALY_KINDS = {"anomaly"}
ADJUSTMENT_VIEW = {"finding_id", "from_level", "to_level", "reason", "evidence_ids"}
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


def _trace(agent: str, runtime: AgentRuntime, branch: str = "", **fields: Any) -> AgentTrace:
    key = branch_key(agent, branch)
    return AgentTrace(
        agent=agent,
        llm_calls=runtime.calls_by.get(key, 0),
        provider=runtime.answered_by.get(key),
        **fields,
    )


def _planner_error(error: str | None) -> str | None:
    """Plain wording for the UI when the planner could not answer."""
    if error is None or error.startswith("reply did not match"):
        return error
    limited = "429" in error or "rate limit" in error.lower()
    reason = " (rate limited)" if limited else ""
    return f"AI planner unavailable{reason} — rule-based fixes shown. {error}"


def _pack_view(pack: EvidencePack) -> dict[str, Any]:
    return pack.model_dump(exclude={"pack_id"})


class Agents:
    """Node functions bound to one run's runtime."""

    def __init__(
        self,
        runtime: AgentRuntime,
        min_risk: str,
        max_groups: int,
        pack_batch: int = PACK_BATCH,
        planner_timeout: float = AI_PLANNER_TIMEOUT_S,
        planner_max: int = AI_PLANNER_MAX,
    ) -> None:
        self.rt = runtime
        self.planner_timeout = planner_timeout
        self.planner_max = planner_max
        self.min_risk = min_risk
        self.max_groups = max_groups
        self.pack_batch = pack_batch

    def _packs_by_finding(self, state: GuardianState) -> dict[str, EvidencePack]:
        return {p.finding_id: p for p in state.get("packs", [])}

    def _cited_packs(
        self,
        state: GuardianState,
        claims: list[AgentClaim],
        adjustments: list[RiskAdjustment] | None = None,
    ) -> list[dict[str, Any]]:
        """Only the evidence packs the given claims and adjustments cite (critic and reviser)."""
        packs = self._packs_by_finding(state)
        cited = {f.finding_id for c in claims for f in self.rt.ctx.findings_citing(c.evidence_ids)}
        cited |= {a.finding_id for a in adjustments or []}
        return [_pack_view(packs[f]) for f in sorted(cited) if f in packs]

    def triage(self, state: GuardianState) -> Update:
        groups, packs = triage(self.rt.ctx, self.min_risk, self.max_groups)
        project = self.rt.ctx.project_text[:2000]
        trace = AgentTrace(
            agent="triage",
            consumed=[f"{len(self.rt.ctx.findings)} findings"],
            produced=[p.pack_id for p in packs],
        )
        return {"groups": groups, "packs": packs, "project_text": project, "trace": [trace]}

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

    def fan_out(self, state: GuardianState) -> list[Send] | str:
        """One branch per package group: its analysts run in parallel (change analyst only
        for groups with anomalies). With no group, go straight to the validator."""
        by_finding = self._packs_by_finding(state)
        sends: list[Send] = []
        for group in state.get("groups", []):
            packs = [by_finding[f] for f in group.finding_ids if f in by_finding]
            branch: BranchInput = {
                "group": group,
                "group_packs": packs,
                "project": state.get("project_text", ""),
            }
            kinds = {p.kind for p in packs}
            if kinds & VULN_KINDS:
                sends.append(Send(VULN_ANALYST.name, branch))
            if kinds & ANOMALY_KINDS:
                sends.append(Send(CHANGE_ANALYST.name, branch))
            sends.append(Send(RISK_ANALYST.name, branch))
        return sends or "evidence_validator"

    def _batches(self, packs: list[EvidencePack]) -> list[list[EvidencePack]]:
        return [packs[i : i + self.pack_batch] for i in range(0, len(packs), self.pack_batch)]

    def _analyst(self, agent: AgentRole, branch: BranchInput, kinds: set[str]) -> Update:
        group = branch["group"].group_id
        batches = self._batches([p for p in branch["group_packs"] if p.kind in kinds])
        produced: list[AgentClaim] = []
        error = None
        for batch in batches:
            data = {
                "evidence_packs": [_pack_view(p) for p in batch],
                "project_description": branch["project"],
            }
            reply, error = self.rt.ask(agent, data, STRICT_REPLY_SCHEMA, LLMReply, branch=group)
            produced += [to_agent_claim(agent.name, c) for c in reply.claims] if reply else []
            if error:
                break
        trace = _trace(
            agent.name,
            self.rt,
            group,
            consumed=[p.pack_id for batch in batches for p in batch],
            produced=[c.claim_id for c in produced],
            error=error,
        )
        update: Update = {"pending": produced, "trace": [trace]}
        if error:
            update["errors"] = {agent.name: error}
        return update

    def vuln_analyst(self, branch: BranchInput) -> Update:
        return self._analyst(VULN_ANALYST, branch, VULN_KINDS)

    def change_analyst(self, branch: BranchInput) -> Update:
        return self._analyst(CHANGE_ANALYST, branch, ANOMALY_KINDS)

    def risk_analyst(self, branch: BranchInput) -> Update:
        """Proposes one-level risk changes; code checks each one and keeps the verdict."""
        group, scope = branch["group"].group_id, branch["group"].finding_ids
        produced: list[RiskAdjustment] = []
        error = None
        for batch in self._batches(branch["group_packs"]):
            data = {
                "evidence_packs": [_pack_view(p) for p in batch],
                "project_description": branch["project"],
            }
            reply, error = self.rt.ask(
                RISK_ANALYST, data, STRICT_RISK_SCHEMA, RiskReply, branch=group
            )
            for raw in reply.adjustments if reply else []:
                produced.append(check_adjustment(raw, self.rt.ctx, scope))
            if error:
                break
        adjustments = _one_per_finding(produced)
        trace = _trace(
            RISK_ANALYST.name,
            self.rt,
            group,
            consumed=[p.pack_id for p in branch["group_packs"]],
            produced=[a.finding_id for a in adjustments],
            accepted=sum(a.status == "accepted" for a in adjustments),
            rejected=sum(a.status == "rejected" for a in adjustments),
            error=error,
        )
        update: Update = {"adjustments": adjustments, "trace": [trace]}
        if error:
            update["errors"] = {RISK_ANALYST.name: error}
        return update

    def evidence_validator(self, state: GuardianState) -> Update:
        known = {c.claim_id for c in state.get("claims", [])}
        fresh = {c.claim_id: c for c in state.get("pending", []) if c.claim_id not in known}
        checked = [validate(c, self.rt.ctx) for c in fresh.values()]
        trace = AgentTrace(
            agent="evidence_validator",
            consumed=[c.claim_id for c in checked],
            accepted=sum(c.validated for c in checked),
            rejected=sum(not c.validated for c in checked),
        )
        return {"claims": list(state.get("claims", [])) + checked, "trace": [trace]}

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
        reply, error = self.rt.ask(ANALYST_REVISION, data, STRICT_REPLY_SCHEMA, LLMReply)
        produced = [to_agent_claim(ANALYST_REVISION.name, c) for c in reply.claims] if reply else []
        trace = _trace(
            ANALYST_REVISION.name,
            self.rt,
            consumed=[c.claim_id for c in rejected],
            produced=[c.claim_id for c in produced],
            error=error,
        )
        update: Update = {"pending": produced, "revision_round": 1, "trace": [trace]}
        if error:
            update["errors"] = {ANALYST_REVISION.name: error}
        return update

    def _critic_data(
        self,
        state: GuardianState,
        under_review: list[AgentClaim],
        proposed: list[RiskAdjustment],
    ) -> dict[str, Any]:
        claims = [
            {
                "claim_id": c.claim_id,
                "text": c.text,
                "kind": c.kind.value,
                "evidence_ids": c.evidence_ids,
            }
            for c in under_review
        ]
        return {
            "claims": claims,
            "risk_adjustments": [a.model_dump(include=ADJUSTMENT_VIEW) for a in proposed],
            "evidence_packs": self._cited_packs(state, under_review, proposed),
        }

    def risk_critic(self, state: GuardianState) -> Update:
        claims = list(state.get("claims", []))
        adjustments = list(state.get("adjustments", []))
        under_review = [c for c in claims if c.validated and c.step in ANALYSTS]
        proposed = [a for a in adjustments if a.status == "accepted"]
        if not under_review and not proposed:
            trace = AgentTrace(agent=RISK_CRITIC.name, error="no input")
            return {"reviewed_adjustments": adjustments, "agreement": {}, "trace": [trace]}
        data = self._critic_data(state, under_review, proposed)
        reply, error = self.rt.ask(RISK_CRITIC, data, STRICT_CRITIC_SCHEMA, CriticReply)
        reviews = {r.claim_id: r for r in reply.reviews} if reply else {}
        by_finding = {r.finding_id: r for r in reply.adjustment_reviews} if reply else {}
        ids = {c.claim_id for c in under_review}
        revised = [
            _apply_review(c, reviews.get(c.claim_id)) if c.claim_id in ids else c for c in claims
        ]
        reviewed = [c for c in revised if c.claim_id in ids]
        final, agreement = _review_adjustments(adjustments, by_finding)
        unknown = sorted(set(reviews) - ids)
        unknown += sorted(set(by_finding) - {a.finding_id for a in proposed})
        trace = _trace(
            RISK_CRITIC.name,
            self.rt,
            consumed=sorted(ids) + [a.finding_id for a in proposed],
            accepted=sum(c.validated for c in reviewed),
            rejected=sum(not c.validated for c in reviewed),
            error=error or (f"ignored unknown IDs: {unknown}" if unknown else None),
        )
        update: Update = {
            "claims": revised,
            "reviewed_adjustments": final,
            "agreement": agreement,
            "trace": [trace],
        }
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
        candidates = planner_candidates(
            state.get("candidates", []), self.rt.ctx.findings, self.planner_max
        )
        if not candidates:
            return {"trace": [AgentTrace(agent=REMEDIATION_PLANNER.name, error="no input")]}
        packs = self._packs_by_finding(state)
        data = {
            "remediation_candidates": [c.model_dump(mode="json") for c in candidates],
            "evidence_packs": [_pack_view(packs[c.finding_id]) for c in candidates],
        }
        reply, error = self.rt.ask(
            REMEDIATION_PLANNER,
            data,
            STRICT_PLANNER_SCHEMA,
            PlannerReply,
            reserved_timeout=self.planner_timeout,
        )
        return self._planner_update(state, candidates, packs, reply, _planner_error(error))

    def _planner_update(
        self,
        state: GuardianState,
        candidates: list[RemediationCandidate],
        packs: dict[str, EvidencePack],
        reply: PlannerReply | None,
        error: str | None,
    ) -> Update:
        by_id = {c.finding_id: c for c in candidates}
        checked = [
            validate_proposal(p, by_id, packs, self.rt.ctx)
            for p in (reply.proposals if reply else [])
        ]
        proposals, claims = [p for p, _ in checked], [c for _, c in checked]
        trace = _trace(
            REMEDIATION_PLANNER.name,
            self.rt,
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
        reply, error = self.rt.ask(REPORT_WRITER, data, STRICT_REPLY_SCHEMA, LLMReply)
        produced = [
            validate(to_agent_claim(REPORT_WRITER.name, c), self.rt.ctx)
            for c in (reply.claims if reply else [])
        ]
        trace = _trace(
            REPORT_WRITER.name,
            self.rt,
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


def _one_per_finding(adjustments: list[RiskAdjustment]) -> list[RiskAdjustment]:
    """The first adjustment for a finding stands; later ones are kept as rejected."""
    seen: set[str] = set()
    result = []
    for adjustment in adjustments:
        if adjustment.finding_id in seen:
            adjustment = adjustment.model_copy(
                update={"status": "rejected", "rejected_reason": "duplicate adjustment for finding"}
            )
        seen.add(adjustment.finding_id)
        result.append(adjustment)
    return result


def _review_adjustments(
    adjustments: list[RiskAdjustment], reviews: dict[str, AdjustmentReview]
) -> tuple[list[RiskAdjustment], dict[str, bool]]:
    """The critic may only reject an accepted adjustment. Agreement means it said 'supported'.

    An accepted adjustment the critic did not review counts as no agreement.
    """
    final: list[RiskAdjustment] = []
    agreement: dict[str, bool] = {}
    for adjustment in adjustments:
        if adjustment.status != "accepted":
            final.append(adjustment)
            continue
        review = reviews.get(adjustment.finding_id)
        agreement[adjustment.finding_id] = review is not None and review.verdict == "supported"
        if review is not None and review.verdict != "supported":
            adjustment = adjustment.model_copy(
                update={
                    "status": "rejected",
                    "rejected_reason": f"independent reviewer: {review.reason}",
                }
            )
        final.append(adjustment)
    return final, agreement
