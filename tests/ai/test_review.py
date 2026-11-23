from __future__ import annotations

import json
from pathlib import Path

from guardian.ai.review import load_injected, review_context_from_result, run_review
from guardian.config import Settings
from guardian.models import LlmStatus, RunResult, Scan
from tests.ai.factories import make_context

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _result() -> RunResult:
    ctx = make_context()
    return RunResult(
        scan=Scan(scan_id="s", target="t", started_at="2026-01-01T00:00:00Z"),
        findings=list(ctx.findings.values()),
        evidence=list(ctx.evidence.values()),
    )


def test_context_from_result_exposes_findings_and_evidence() -> None:
    ctx = review_context_from_result(_result())
    assert set(ctx.findings) == {"f-jwt", "f-leftpad"}
    assert "ev-grype-0001" in ctx.evidence


def test_fixture_claims_are_rejected_with_reasons_and_llm_off_is_unavailable() -> None:
    result = _result()
    injected = load_injected(FIXTURES / "fake_cve_claim.json", result)
    assert [c.step for c in injected] == ["injected", "injected"]
    assert injected[0].evidence_ids == ["ev-grype-0001"]
    claims, status, trace = run_review(result, Settings(), injected)
    assert [t.agent for t in trace][:2] == ["triage", "relevance"]
    assert status == LlmStatus.UNAVAILABLE
    assert [c.validated for c in claims] == [False, False]
    assert "CVE-2026-31337" in (claims[0].rejected_reason or "")
    assert "evidence ID not found" in (claims[1].rejected_reason or "")


def test_review_client_chains_configured_fallbacks_after_the_primary() -> None:
    from pydantic import SecretStr

    from guardian.ai.llm import FallbackClient
    from guardian.ai.review import review_client

    settings = Settings(provider="groq", api_key=SecretStr("gsk_test"), model="openai/gpt-oss-120b")
    env = {"GUARDIAN_LLM_FALLBACKS": "gemini,openai", "GEMINI_API_KEY": "g-key"}
    client = review_client(settings, env)
    assert isinstance(client, FallbackClient)
    assert client.labels == ["groq:openai/gpt-oss-120b", "gemini:gemini-2.5-flash"]
    assert client.skipped == {"openai": "skipped: no key"}


def test_single_claim_object_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "claim.json"
    path.write_text(
        json.dumps(
            {
                "text": "jsonwebtoken 0.4.0 is affected by CVE-2015-9235.",
                "evidence_ids": ["@top-finding"],
                "kind": "evidence",
            }
        )
    )
    claims, _, _ = run_review(_result(), Settings(), load_injected(path, _result()))
    assert [c.validated for c in claims] == [True]
