"""Adapters that let the runner drive the AI review with a plain RunResult."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from guardian.ai.agents import PACK_BATCH
from guardian.ai.context import RISK_ORDER, ReviewContext
from guardian.ai.graph import AIReviewResult, load_injected_claims, run_ai_review
from guardian.ai.llm import (
    GROQ_DEFAULT_MODEL,
    MAX_TOKENS,
    RATE_LIMIT_RETRIES,
    LLMClient,
    build_client,
    read_env_file,
    with_fallbacks,
)
from guardian.config import AI_CONCURRENCY, AI_MAX_GROUPS, AI_MIN_RISK, Settings
from guardian.models import AgentClaim, RunResult


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


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        value = 0
    if value < 1:
        raise ValueError(f"{name} must be a whole number of at least 1, not '{raw}'.")
    return value


def review_options(env: Mapping[str, str]) -> dict[str, Any]:
    """Policy and concurrency settings for one review; a bad value fails at startup."""
    min_risk = env.get("GUARDIAN_AI_MIN_RISK", "").strip().lower() or AI_MIN_RISK
    if min_risk not in RISK_ORDER:
        raise ValueError(
            f"GUARDIAN_AI_MIN_RISK must be one of {', '.join(RISK_ORDER)}, not '{min_risk}'."
        )
    return {
        "min_risk": min_risk,
        "max_groups": _positive_int(env, "GUARDIAN_AI_MAX_GROUPS", AI_MAX_GROUPS),
        "pack_batch": _positive_int(env, "GUARDIAN_LLM_PACK_BATCH", PACK_BATCH),
        "concurrency": _positive_int(env, "GUARDIAN_LLM_CONCURRENCY", AI_CONCURRENCY),
    }


def run_review(
    result: RunResult,
    settings: Settings,
    injected: list[AgentClaim],
) -> AIReviewResult:
    env = {**read_env_file(Path(".env")), **os.environ}
    return run_ai_review(
        review_context_from_result(result),
        review_client(settings, env),
        injected=injected,
        timeout=float(settings.timeout_s),
        **review_options(env),
    )
