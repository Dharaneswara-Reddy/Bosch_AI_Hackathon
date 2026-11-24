from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_groq import ChatGroq

from guardian.ai.llm import (
    LangChainChatClient,
    LLMBadResponse,
    LLMError,
    LLMTimeout,
    NoneClient,
    client_from_env,
    groq_client,
    read_env_file,
)
from guardian.ai.schemas import (
    STRICT_CRITIC_SCHEMA,
    STRICT_PLANNER_SCHEMA,
    STRICT_REPLY_SCHEMA,
    CriticReply,
    LLMReply,
    PlannerReply,
)

KEY = "gsk_test_not_a_real_key_0123456789"
REPLY = {"claims": [{"text": "x", "evidence_ids": ["e1"], "kind": "evidence", "uncertainty": None}]}


class _Failing(GenericFakeChatModel):
    error: Any = None

    def _generate(self, *args: Any, **kwargs: Any) -> Any:
        raise self.error


class _StatusError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__("boom")
        self.status_code = status_code


class APITimeoutError(Exception):
    pass


def test_langchain_adapter_parses_reply() -> None:
    fake = GenericFakeChatModel(messages=iter([AIMessage(content=json.dumps(REPLY))]))
    client = LangChainChatClient(fake, name="fake", strict_schema=False)
    assert LLMReply.model_validate(client.complete("s", "u", STRICT_REPLY_SCHEMA, 5)).claims


def test_groq_client_is_langchain_chatgroq_with_strict_schema_and_no_retries() -> None:
    client = groq_client(api_key=KEY)
    assert isinstance(client, LangChainChatClient)
    chat = client._model
    assert isinstance(chat, ChatGroq)
    assert chat.model_name == "openai/gpt-oss-120b"
    assert chat.max_retries == 0 and (chat.temperature or 0) < 1e-6
    assert client._strict_schema


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (_StatusError(400), LLMBadResponse),
        (_StatusError(401), LLMError),
        (_StatusError(429), LLMError),
        (APITimeoutError(), LLMTimeout),
    ],
)
def test_provider_errors_are_mapped(error: Exception, expected: type[LLMError]) -> None:
    client = LangChainChatClient(
        _Failing(messages=iter([]), error=error), name="f", strict_schema=False
    )
    with pytest.raises(expected) as info:
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 5)
    if expected is LLMError:
        assert not isinstance(info.value, LLMBadResponse)
    assert KEY not in str(info.value)


def test_schema_rejection_keeps_the_provider_message() -> None:
    error = _StatusError(400)
    error.body = {"message": "Generated JSON does not match the expected schema"}  # type: ignore[attr-defined]
    client = LangChainChatClient(
        _Failing(messages=iter([]), error=error), name="f", strict_schema=False
    )
    with pytest.raises(LLMBadResponse, match="does not match the expected schema"):
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 5)


@pytest.mark.parametrize(
    ("schema", "model", "sample"),
    [
        (STRICT_REPLY_SCHEMA, LLMReply, REPLY),
        (
            STRICT_CRITIC_SCHEMA,
            CriticReply,
            {"reviews": [{"claim_id": "c", "verdict": "supported", "reason": "ok"}]},
        ),
        (
            STRICT_PLANNER_SCHEMA,
            PlannerReply,
            {
                "proposals": [
                    {
                        "finding_id": "f",
                        "action": "upgrade",
                        "target_version": "1.0.0",
                        "rationale": "r",
                        "rollback": "b",
                        "breaking_change_risk": "low",
                        "evidence_ids": ["e"],
                    }
                ]
            },
        ),
    ],
)
def test_strict_schemas_match_reply_models(
    schema: dict[str, Any], model: Any, sample: dict[str, Any]
) -> None:
    model.model_validate(sample)
    item = next(iter(schema["properties"].values()))["items"]
    assert (
        set(item["required"])
        == set(item["properties"])
        == set(
            model.model_fields[next(iter(model.model_fields))].annotation.__args__[0].model_fields
        )
    )
    assert item["additionalProperties"] is False


def test_client_from_env(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(f'# comment\nGUARDIAN_LLM_PROVIDER=groq\nGROQ_API_KEY="{KEY}"\n')
    assert isinstance(client_from_env(read_env_file(env_file)), LangChainChatClient)
    assert isinstance(client_from_env({}), NoneClient)
    assert read_env_file(tmp_path / "missing.env") == {}


def test_groq_without_key_fails_at_startup_with_actionable_message() -> None:
    with pytest.raises(ValueError, match="GUARDIAN_LLM_API_KEY"):
        client_from_env({"GUARDIAN_LLM_PROVIDER": "groq"})
    with pytest.raises(ValueError, match="Unknown GUARDIAN_LLM_PROVIDER"):
        client_from_env({"GUARDIAN_LLM_PROVIDER": "gpt"})


class _RateLimited(Exception):
    def __init__(self, retry_after: str | None = None) -> None:
        super().__init__("rate limited")
        self.status_code = 429
        headers = {"retry-after": retry_after} if retry_after is not None else {}
        self.response = type("Response", (), {"headers": headers})()


class _Sequence(GenericFakeChatModel):
    errors: list[Any] = []

    def _generate(self, *args: Any, **kwargs: Any) -> Any:
        if self.errors:
            raise self.errors.pop(0)
        return super()._generate(*args, **kwargs)


def _rate_limited_client(
    errors: list[Any], retries: int = 2
) -> tuple[LangChainChatClient, list[float]]:
    waits: list[float] = []
    fake = _Sequence(messages=iter([AIMessage(content=json.dumps(REPLY))]), errors=errors)
    client = LangChainChatClient(
        fake, name="fake", strict_schema=False, rate_limit_retries=retries, sleep=waits.append
    )
    return client, waits


def test_rate_limit_is_retried_after_the_retry_after_header() -> None:
    client, waits = _rate_limited_client([_RateLimited("2")])
    assert LLMReply.model_validate(client.complete("s", "u", STRICT_REPLY_SCHEMA, 30)).claims
    assert waits == [2.0]


def test_rate_limit_without_header_backs_off_then_gives_up() -> None:
    client, waits = _rate_limited_client([_RateLimited(), _RateLimited(), _RateLimited()])
    with pytest.raises(LLMError, match="429"):
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 30)
    assert waits == [1.0, 2.0]


def test_rate_limit_wait_longer_than_the_step_budget_is_not_attempted() -> None:
    client, waits = _rate_limited_client([_RateLimited("60")])
    with pytest.raises(LLMError, match="429"):
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 5)
    assert waits == []


def test_other_provider_errors_are_not_retried() -> None:
    client, waits = _rate_limited_client([_StatusError(401)])
    with pytest.raises(LLMError, match="401"):
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 30)
    assert waits == []


def test_rate_limit_retry_count_comes_from_env() -> None:
    client = client_from_env(
        {
            "GUARDIAN_LLM_PROVIDER": "groq",
            "GUARDIAN_LLM_API_KEY": KEY,
            "GUARDIAN_LLM_RATE_LIMIT_RETRIES": "5",
        }
    )
    assert isinstance(client, LangChainChatClient)
    assert client.rate_limit_retries == 5


def test_request_too_large_is_reported_with_the_provider_message_and_not_retried() -> None:
    error = _RateLimited("1")
    error.body = {"message": "Request too large for model: Limit 8000, Requested 9500"}
    client, waits = _rate_limited_client([error])
    with pytest.raises(LLMError, match="Request too large"):
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 30)
    assert waits == []


def test_rate_limit_error_carries_the_provider_message() -> None:
    error = _RateLimited()
    error.body = {"message": "Rate limit reached for tokens per minute. Try again in 2s."}
    client, _ = _rate_limited_client([error], retries=0)
    with pytest.raises(LLMError, match="tokens per minute"):
        client.complete("s", "u", STRICT_REPLY_SCHEMA, 30)


def test_groq_completion_size_is_capped_from_env() -> None:
    client = client_from_env(
        {
            "GUARDIAN_LLM_PROVIDER": "groq",
            "GUARDIAN_LLM_API_KEY": KEY,
            "GUARDIAN_LLM_MAX_TOKENS": "1500",
        }
    )
    assert isinstance(client, LangChainChatClient)
    assert client._model.max_tokens == 1500
    assert groq_client(api_key=KEY)._model.max_tokens == 2048
