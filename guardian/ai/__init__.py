"""AI review: explains tool findings; a code validator decides what is accepted.

Entry points for the runner (P5):

    ctx = ReviewContext.build(findings, evidence, components, project_text=readme_excerpt)
    client = build_client(
        settings.llm_provider, settings.llm_model, settings.llm_api_key, settings.llm_base_url
    )
    injected = load_injected_claims(path, ctx) if inject_claim else []
    result = run_ai_review(ctx, client, injected=injected, timeout=settings.llm_timeout_s)
    # result.claims -> findings.json; result.llm_status (LlmStatus) -> Scan.llm_status;
    # result.llm_calls -> run.json
"""

from guardian.ai.context import ReviewContext
from guardian.ai.llm import LLMClient, NoneClient, build_client
from guardian.ai.steps import AIReviewResult, load_injected_claims, run_ai_review
from guardian.ai.validator import validate

__all__ = [
    "AIReviewResult",
    "LLMClient",
    "NoneClient",
    "ReviewContext",
    "build_client",
    "load_injected_claims",
    "run_ai_review",
    "validate",
]
