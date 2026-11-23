"""AI review chain: explain_vulns -> explain_changes -> inventory_note -> validator -> summarize.

* Steps are plain functions in a fixed order; only the top-N findings are sent.
* Each LLM call has a hard deadline. A timeout or provider error opens a
  circuit breaker: no further calls, ``llm_status="failed"``. The scan status
  is never touched here.
* A reply that does not match ``LLMReply`` is retried once, then the step fails.
* ``injected`` claims (the ``--inject-claim`` demo hook) are validated even when
  the LLM is off, so the fabricated-CVE rejection can always be shown.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from guardian.ai.context import ReviewContext, as_text
from guardian.ai.guardrails import find_injection_markers, redact_secrets
from guardian.ai.llm import LLMBadResponse, LLMClient, LLMError, LLMTimeout, LLMUnavailable
from guardian.ai.prompts import system_prompt, user_prompt
from guardian.ai.schemas import LLMClaim, LLMReply
from guardian.ai.validator import purl_name_version, validate
from guardian.models import AgentClaim, ClaimKind, Finding, LlmStatus

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_TOP_N = 20
TOP_FINDING_PLACEHOLDER = "@top-finding"
CLAIM_FIELDS = ("text", "evidence_ids", "kind", "uncertainty")
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="guardian-llm")


class AIReviewResult(BaseModel):
    claims: list[AgentClaim]
    llm_status: LlmStatus
    llm_calls: int = 0
    step_errors: dict[str, str] = Field(default_factory=dict)
    injection_markers: list[str] = Field(default_factory=list)
    secrets_redacted: int = 0


class _Breaker:
    """Stops all further LLM calls after the first provider-level failure."""

    def __init__(self) -> None:
        self.open_reason: str | None = None
        self.unavailable = False
        self.calls = 0
        self.redactions = 0


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
        validated=False,
        rejected_reason=None,
        uncertainty=raw.uncertainty,
    )


def _finding_view(finding: Finding, ctx: ReviewContext) -> dict[str, Any]:
    component = ctx.component(finding.component_id)
    path = [ctx.component(c) for c in finding.dependency_path]
    return {
        "finding_id": finding.finding_id,
        "kind": as_text(finding.kind),
        "package": component.name if component else purl_name_version(finding.purl)[0],
        "version": component.version
        if component
        else purl_name_version(finding.purl)[1] or "UNKNOWN",
        "purl": finding.purl,
        "advisory_id": finding.advisory_id,
        "aliases": list(finding.aliases),
        "anomaly_type": finding.anomaly_type,
        "source_severity": as_text(finding.source_severity),
        "fixed_versions": list(finding.fixed_versions),
        "dependency_path": [f"{c.name}@{c.version}" if c else "UNKNOWN" for c in path],
        "path_count": finding.path_count,
        "risk_level": as_text(finding.risk_level),
        "risk_rule_id": as_text(finding.risk_rule_id),
        "state": as_text(finding.state),
        "reachability": "unknown",
        "evidence": [_evidence_view(ctx, e) for e in finding.evidence_ids],
    }


def _evidence_view(ctx: ReviewContext, evidence_id: str) -> dict[str, Any]:
    record = ctx.evidence.get(evidence_id)
    if record is None:
        return {"evidence_id": evidence_id, "status": "UNKNOWN"}
    return {
        "evidence_id": evidence_id,
        "tool": record.tool,
        "file": record.file,
        "pointer": record.pointer,
        "url": record.url,
    }


def _step_inputs(ctx: ReviewContext, top_n: int) -> dict[str, dict[str, Any]]:
    top = ctx.top_findings(top_n)
    vulns = [_finding_view(f, ctx) for f in top if as_text(f.kind) != "anomaly"]
    changes = [_finding_view(f, ctx) for f in top if as_text(f.kind) == "anomaly"]
    ecosystems = Counter(as_text(c.ecosystem) for c in ctx.components.values())
    inventory = {
        "components_total": len(ctx.components),
        "components_by_ecosystem": dict(sorted(ecosystems.items())),
        "findings_total": len(ctx.findings),
        "findings_by_kind": dict(Counter(as_text(f.kind) for f in ctx.findings.values())),
        "project_description": ctx.project_text[:2000],
    }
    inputs: dict[str, dict[str, Any]] = {"inventory_note": inventory}
    if vulns:
        inputs["explain_vulns"] = {"findings": vulns}
    if changes:
        inputs["explain_changes"] = {"findings": changes}
    return inputs


def _call(client: LLMClient, system: str, user: str, timeout: float) -> dict[str, Any]:
    future = _EXECUTOR.submit(client.complete, system, user, LLMReply.model_json_schema(), timeout)
    try:
        return future.result(timeout=timeout)
    except FutureTimeout as exc:
        future.cancel()
        raise LLMTimeout(f"No reply within {timeout:.0f}s.") from exc


def _run_step(
    step: str, data: dict[str, Any], client: LLMClient, breaker: _Breaker, timeout: float
) -> tuple[list[AgentClaim], str | None]:
    redacted, count = redact_secrets(json.dumps(data, sort_keys=True, default=str))
    breaker.redactions += count
    user = user_prompt(step, redacted)
    last_error = ""
    for _attempt in range(2):
        if breaker.open_reason is not None or breaker.unavailable:
            return [], breaker.open_reason or "LLM unavailable"
        breaker.calls += 1
        try:
            reply = LLMReply.model_validate(_call(client, system_prompt(), user, timeout))
            return [to_agent_claim(step, c) for c in reply.claims], None
        except (ValidationError, LLMBadResponse) as exc:
            last_error = f"reply did not match the claim schema: {str(exc)[:200]}"
        except LLMUnavailable as exc:
            breaker.unavailable = True
            return [], str(exc)
        except LLMError as exc:
            breaker.open_reason = f"{type(exc).__name__}: {exc}"
            return [], breaker.open_reason
    return [], last_error


def _status(attempted: int, errors: dict[str, str], breaker: _Breaker) -> LlmStatus:
    """ok = at least one step produced claims (failed steps are listed in step_errors)."""
    if breaker.unavailable:
        return LlmStatus.UNAVAILABLE
    return LlmStatus.FAILED if errors and len(errors) >= attempted else LlmStatus.OK


def run_ai_review(
    ctx: ReviewContext,
    client: LLMClient,
    injected: list[AgentClaim] | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    top_n: int = DEFAULT_TOP_N,
) -> AIReviewResult:
    """Run every step, validate every claim, and never raise for LLM problems."""
    inputs = _step_inputs(ctx, top_n)
    markers = find_injection_markers(json.dumps(inputs, sort_keys=True, default=str))
    breaker, errors = _Breaker(), dict[str, str]()
    claims = [validate(c, ctx) for c in (injected or [])]
    for step in ("explain_vulns", "explain_changes", "inventory_note"):
        if step in inputs:
            produced, error = _run_step(step, inputs[step], client, breaker, timeout)
            claims += [validate(c, ctx) for c in produced]
            if error:
                errors[step] = error
    attempted = sum(
        1 for s in ("explain_vulns", "explain_changes", "inventory_note") if s in inputs
    )
    accepted = [c for c in claims if c.validated and c.step != "injected"]
    if accepted:
        summary_input = {
            "accepted_claims": [{"text": c.text, "evidence_ids": c.evidence_ids} for c in accepted]
        }
        produced, error = _run_step("summarize", summary_input, client, breaker, timeout)
        claims += [validate(c, ctx) for c in produced]
        attempted += 1
        if error:
            errors["summarize"] = error
    return AIReviewResult(
        claims=claims,
        llm_status=_status(attempted, errors, breaker),
        llm_calls=breaker.calls,
        step_errors=errors,
        injection_markers=markers,
        secrets_redacted=breaker.redactions,
    )


def load_injected_claims(path: Path, ctx: ReviewContext) -> list[AgentClaim]:
    """Load the ``--inject-claim`` file.

    ``@top-finding`` cites the top finding's first evidence ID.
    """
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
