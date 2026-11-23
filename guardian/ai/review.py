"""Adapters that let the runner drive the AI review with a plain RunResult."""

from __future__ import annotations

import os
from pathlib import Path

from guardian.ai.context import ReviewContext
from guardian.ai.graph import load_injected_claims, run_ai_review
from guardian.ai.llm import build_client
from guardian.config import Settings
from guardian.models import AgentClaim, AgentTrace, LlmStatus, RunResult


def review_context_from_result(result: RunResult) -> ReviewContext:
    return ReviewContext.build(result.findings, result.evidence, result.graph.nodes)


def load_injected(path: Path, result: RunResult) -> list[AgentClaim]:
    return load_injected_claims(path, review_context_from_result(result))


def run_review(
    result: RunResult,
    settings: Settings,
    injected: list[AgentClaim],
) -> tuple[list[AgentClaim], LlmStatus, list[AgentTrace]]:
    client = build_client(
        settings.provider,
        settings.model,
        settings.api_key.get_secret_value(),
        os.environ.get("GUARDIAN_LLM_BASE_URL", ""),
    )
    review = run_ai_review(
        review_context_from_result(result),
        client,
        injected=injected,
        timeout=float(settings.timeout_s),
    )
    return review.claims, review.llm_status, review.trace
