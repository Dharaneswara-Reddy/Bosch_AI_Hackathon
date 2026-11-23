"""Adapters that let the runner drive the AI review with a plain RunResult."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from guardian.ai.agents import PACK_BATCH
from guardian.ai.context import ReviewContext
from guardian.ai.graph import load_injected_claims, run_ai_review
from guardian.ai.llm import (
    GROQ_DEFAULT_MODEL,
    MAX_TOKENS,
    RATE_LIMIT_RETRIES,
    LLMClient,
    build_client,
    read_env_file,
    with_fallbacks,
)
from guardian.config import Settings
from guardian.models import AgentClaim, AgentTrace, LlmStatus, RunResult


def review_context_from_result(result: RunResult) -> ReviewContext:
    return ReviewContext.build(result.findings, result.evidence, result.graph.nodes)


def load_injected(path: Path, result: RunResult) -> list[AgentClaim]:
    return load_injected_claims(path, review_context_from_result(result))


def review_client(settings: Settings, env: Mapping[str, str]) -> LLMClient:
    """The primary provider from settings, followed by the ``GUARDIAN_LLM_FALLBACKS`` chain."""
    primary = build_client(
        settings.provider,
        settings.model,
        settings.api_key.get_secret_value(),
        env.get("GUARDIAN_LLM_BASE_URL", ""),
        int(env.get("GUARDIAN_LLM_RATE_LIMIT_RETRIES", RATE_LIMIT_RETRIES)),
        int(env.get("GUARDIAN_LLM_MAX_TOKENS", MAX_TOKENS)),
    )
    default = GROQ_DEFAULT_MODEL if settings.provider == "groq" else ""
    label = f"{settings.provider}:{settings.model or default}"
    return with_fallbacks(primary, label, env)


def run_review(
    result: RunResult,
    settings: Settings,
    injected: list[AgentClaim],
) -> tuple[list[AgentClaim], LlmStatus, list[AgentTrace]]:
    env = {**read_env_file(Path(".env")), **os.environ}
    review = run_ai_review(
        review_context_from_result(result),
        review_client(settings, env),
        injected=injected,
        timeout=float(settings.timeout_s),
        pack_batch=int(env.get("GUARDIAN_LLM_PACK_BATCH", PACK_BATCH)),
    )
    return review.claims, review.llm_status, review.trace
