from __future__ import annotations

import io
import json
from typing import Any

import pytest

from guardian.ai.graph import run_ai_review
from guardian.ai.llm import (
    ANTHROPIC_DEFAULT_MODEL,
    GEMINI_DEFAULT_MODEL,
    FallbackClient,
    LLMBadResponse,
    LLMError,
    LLMTimeout,
    NoneClient,
    with_fallbacks,
)
from guardian.ai.schemas import STRICT_REPLY_SCHEMA
from guardian.models import LlmStatus
from tests.ai.factories import make_context
from tests.ai.fake_llms import RoutingLLM

REPLY = {"claims": []}


class Scripted:
    """Provider double: raises ``error`` when set, otherwise answers ``REPLY``."""

    def __init__(self, name: str, error: LLMError | None = None) -> None:
        self.name = name
        self.error = error
        self.calls = 0

    def complete(self, system: str, user: str, schema: dict[str, Any], timeout: float) -> Any:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return REPLY


def _chain(*providers: Scripted) -> FallbackClient:
    return FallbackClient([(p.name, p) for p in providers], skipped={})


@pytest.mark.parametrize(
    "error",
    [
        LLMError("Provider returned HTTP 429. Rate limited."),
        LLMError("Provider returned HTTP 503."),
        LLMError("Provider returned HTTP 401. Check GUARDIAN_LLM_API_KEY."),
        LLMError("Provider returned HTTP 413. Request too large."),
        LLMError("Provider unreachable: connection refused."),
        LLMTimeout("No reply within 30s."),
    ],
)
def test_provider_failure_falls_over_to_the_next_provider(error: LLMError) -> None:
    groq, gemini = Scripted("groq", error), Scripted("gemini")
    client = _chain(groq, gemini)
    assert client.complete("s", "u", STRICT_REPLY_SCHEMA, 5) == REPLY
    assert client.last_used == "gemini"
    assert "groq" in client.failed


def test_schema_mismatch_is_not_a_provider_failure() -> None:
    groq, gemini = Scripted("groq", LLMBadResponse("not JSON")), Scripted("gemini")
    with pytest.raises(LLMBadResponse):
        _chain(groq, gemini).complete("s", "u", STRICT_REPLY_SCHEMA, 5)
    assert gemini.calls == 0


def test_failed_provider_is_skipped_for_the_rest_of_the_run() -> None:
    groq, gemini = Scripted("groq", LLMError("HTTP 429")), Scripted("gemini")
    client = _chain(groq, gemini)
    for _ in range(3):
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 5)
    assert groq.calls == 1 and gemini.calls == 3


def test_every_provider_failing_raises_with_each_reason() -> None:
    client = _chain(
        Scripted("groq", LLMError("HTTP 429")), Scripted("gemini", LLMError("HTTP 503"))
    )
    with pytest.raises(LLMError, match=r"groq.*429.*gemini.*503"):
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 5)


def test_chain_from_env_skips_providers_without_a_key() -> None:
    env = {"GUARDIAN_LLM_FALLBACKS": "gemini, openai, anthropic", "GEMINI_API_KEY": "g-key"}
    client = with_fallbacks(Scripted("groq"), "groq:openai/gpt-oss-120b", env)
    assert isinstance(client, FallbackClient)
    assert client.labels == ["groq:openai/gpt-oss-120b", f"gemini:{GEMINI_DEFAULT_MODEL}"]
    assert client.skipped == {"openai": "skipped: no key", "anthropic": "skipped: no key"}


def test_unknown_fallback_provider_fails_at_startup() -> None:
    with pytest.raises(ValueError, match="GUARDIAN_LLM_FALLBACKS"):
        with_fallbacks(Scripted("groq"), "groq", {"GUARDIAN_LLM_FALLBACKS": "mistral"})


def test_ai_off_stays_off_even_with_fallback_keys() -> None:
    env = {"GUARDIAN_LLM_FALLBACKS": "gemini", "GEMINI_API_KEY": "g-key"}
    assert isinstance(with_fallbacks(NoneClient(), "none", env), NoneClient)


def _http_400(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    import urllib.error

    def urlopen(request: Any, timeout: float) -> io.BytesIO:
        body = io.BytesIO(json.dumps([{"error": {"code": 400, "message": message}}]).encode())
        raise urllib.error.HTTPError(request.full_url, 400, "Bad Request", None, body)  # type: ignore[arg-type]

    monkeypatch.setattr("urllib.request.urlopen", urlopen)


def test_invalid_key_400_is_a_provider_failure_with_its_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guardian.ai.llm import OpenAICompatibleClient

    _http_400(monkeypatch, "API key not valid. Please pass a valid API key.")
    client = OpenAICompatibleClient("https://example.invalid/v1", "bad", "m")
    with pytest.raises(LLMError, match="API key not valid") as info:
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 5)
    assert not isinstance(info.value, LLMBadResponse)


def test_schema_400_keeps_the_provider_message(monkeypatch: pytest.MonkeyPatch) -> None:
    from guardian.ai.llm import OpenAICompatibleClient

    _http_400(monkeypatch, "Generated JSON does not match the schema")
    client = OpenAICompatibleClient("https://example.invalid/v1", "k", "m")
    with pytest.raises(LLMBadResponse, match="does not match the schema"):
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 5)


def _captured_request(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> Any:
    sent: dict[str, Any] = {}

    def urlopen(request: Any, timeout: float) -> io.BytesIO:
        sent["request"] = request
        reply = {"choices": [{"message": {"content": json.dumps(REPLY)}}]}
        return io.BytesIO(json.dumps(reply).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    client = with_fallbacks(Scripted("groq", LLMError("HTTP 429")), "groq", env)
    assert client.complete("s", "u", STRICT_REPLY_SCHEMA, 5) == REPLY
    return sent["request"]


def test_gemini_is_called_on_its_openai_compatible_endpoint_with_strict_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = {"GUARDIAN_LLM_FALLBACKS": "gemini", "GEMINI_API_KEY": "g-key"}
    request = _captured_request(monkeypatch, env)
    body = json.loads(request.data)
    assert request.full_url == (
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    )
    assert request.get_header("Authorization") == "Bearer g-key"
    assert body["model"] == GEMINI_DEFAULT_MODEL
    assert body["response_format"]["type"] == "json_schema"


def test_anthropic_uses_json_mode_because_its_compat_layer_ignores_schemas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = {
        "GUARDIAN_LLM_FALLBACKS": "anthropic",
        "ANTHROPIC_API_KEY": "a-key",
        "GUARDIAN_ANTHROPIC_MODEL": "",
    }
    request = _captured_request(monkeypatch, env)
    body = json.loads(request.data)
    assert request.full_url == "https://api.anthropic.com/v1/chat/completions"
    assert body["model"] == ANTHROPIC_DEFAULT_MODEL
    assert body["response_format"] == {"type": "json_object"}


def test_review_records_which_provider_answered_each_step() -> None:
    client = FallbackClient(
        [("groq:m", Scripted("groq", LLMError("HTTP 429"))), ("gemini:m", RoutingLLM())],
        skipped={"openai": "skipped: no key"},
    )
    result = run_ai_review(make_context(), client)
    assert result.llm_status == LlmStatus.OK
    answered = {t.agent: t.provider for t in result.trace if t.llm_calls}
    assert answered and set(answered.values()) == {"gemini:m"}
    chain = next(t for t in result.trace if t.agent == "llm_providers")
    assert chain.produced == ["groq:m", "gemini:m"]
    assert "groq:m" in (chain.error or "") and "openai: skipped: no key" in (chain.error or "")
