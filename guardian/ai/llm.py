"""LLM provider interface.

The scan never depends on the model: every failure surfaces as an ``LLMError``
subclass so the caller can mark the AI section unavailable or failed while the
scan itself stays ``complete``. API keys are only placed in the HTTP header;
they are never logged, written to artifacts or sent as prompt text.
"""

from __future__ import annotations

import json
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_groq import ChatGroq
from pydantic import SecretStr

JsonObject = dict[str, Any]

GROQ_DEFAULT_MODEL = "openai/gpt-oss-120b"
USER_AGENT = "guardian/0.1 (+supply-chain-guardian)"
PROVIDERS = ("none", "groq", "openai_compatible")
RATE_LIMIT_RETRIES = 2
MAX_TOKENS = 2048
BACKOFF_BASE_S = 1.0
GEMINI_DEFAULT_MODEL = "gemini-2.5-flash"
OPENAI_DEFAULT_MODEL = "gpt-4o-mini"
ANTHROPIC_DEFAULT_MODEL = "claude-haiku-5-5"
# name -> (key env var, model env var, default model, OpenAI-compatible base URL, strict schema).
# Anthropic's compatibility layer ignores response_format, so it gets JSON mode and relies on
# the schema already embedded in the system prompt.
FALLBACK_PROVIDERS: dict[str, tuple[str, str, str, str, bool]] = {
    "gemini": (
        "GEMINI_API_KEY",
        "GUARDIAN_GEMINI_MODEL",
        GEMINI_DEFAULT_MODEL,
        "https://generativelanguage.googleapis.com/v1beta/openai",
        True,
    ),
    "openai": (
        "OPENAI_API_KEY",
        "GUARDIAN_OPENAI_MODEL",
        OPENAI_DEFAULT_MODEL,
        "https://api.openai.com/v1",
        True,
    ),
    "anthropic": (
        "ANTHROPIC_API_KEY",
        "GUARDIAN_ANTHROPIC_MODEL",
        ANTHROPIC_DEFAULT_MODEL,
        "https://api.anthropic.com/v1",
        False,
    ),
}


class LLMError(Exception):
    """Base class for every LLM failure."""


class LLMUnavailable(LLMError):
    """No provider is configured, so no call was attempted."""


class LLMTimeout(LLMError):
    """The provider did not answer within the step deadline."""


class LLMBadResponse(LLMError):
    """The reply was not a single JSON object."""


class LLMClient(Protocol):
    """``complete`` returns one parsed JSON object or raises ``LLMError``."""

    name: str

    def complete(
        self, system: str, user: str, schema: JsonObject, timeout: float
    ) -> JsonObject: ...


class NoneClient:
    """Used when ``GUARDIAN_LLM_PROVIDER=none``. Always unavailable."""

    name = "none"

    def complete(self, system: str, user: str, schema: JsonObject, timeout: float) -> JsonObject:
        raise LLMUnavailable("No LLM provider configured (GUARDIAN_LLM_PROVIDER=none).")


class OpenAICompatibleClient:
    """Any OpenAI-compatible ``/chat/completions`` endpoint (OpenAI, Ollama, vLLM, Groq, ...)."""

    name = "openai_compatible"

    def __init__(
        self, base_url: str, api_key: str, model: str, strict_schema: bool = False
    ) -> None:
        if not base_url or not model:
            raise ValueError(
                "GUARDIAN_LLM_BASE_URL and GUARDIAN_LLM_MODEL must be set for this provider."
            )
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._api_key = api_key
        self._model = model
        self._strict_schema = strict_schema

    def _response_format(self, schema: JsonObject) -> JsonObject:
        if not self._strict_schema:
            return {"type": "json_object"}
        return {
            "type": "json_schema",
            "json_schema": {"name": "guardian_claims", "strict": True, "schema": schema},
        }

    def complete(self, system: str, user: str, schema: JsonObject, timeout: float) -> JsonObject:
        body = {
            "model": self._model,
            "temperature": 0,
            "response_format": self._response_format(schema),
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        payload = self._post(body, timeout)
        try:
            text = str(payload["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMBadResponse("Provider reply has no choices[0].message.content.") from exc
        return parse_json_object(text)

    def _post(self, body: JsonObject, timeout: float) -> JsonObject:
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        request = urllib.request.Request(
            self._url, json.dumps(body).encode(), headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                result: JsonObject = json.load(response)
                return result
        except TimeoutError as exc:
            raise LLMTimeout(f"No reply within {timeout:.0f}s.") from exc
        except urllib.error.HTTPError as exc:
            raise _http_error(exc) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise LLMTimeout(f"No reply within {timeout:.0f}s.") from exc
            raise LLMError(f"Provider unreachable: {exc.reason}.") from exc
        except json.JSONDecodeError as exc:
            raise LLMBadResponse("Provider reply was not JSON.") from exc


class LangChainChatClient:
    """Adapter from any LangChain chat model to ``LLMClient``.

    With ``strict_schema`` the agent's JSON Schema is sent as a strict
    ``response_format`` so the provider constrains decoding to that shape.
    Provider exceptions are mapped onto ``LLMError`` subclasses so the circuit
    breaker can act on them; nothing is swallowed.
    """

    def __init__(
        self,
        model: BaseChatModel,
        name: str,
        strict_schema: bool = True,
        rate_limit_retries: int = RATE_LIMIT_RETRIES,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._model = model
        self.name = name
        self._strict_schema = strict_schema
        self.rate_limit_retries = rate_limit_retries
        self._sleep = sleep

    def complete(self, system: str, user: str, schema: JsonObject, timeout: float) -> JsonObject:
        runnable = (
            self._model.bind(response_format=_strict_format(schema))
            if (self._strict_schema)
            else self._model
        )
        messages = [SystemMessage(content=system), HumanMessage(content=user)]
        deadline = time.monotonic() + timeout
        attempt = 0
        while True:
            try:
                message = runnable.invoke(messages)
            except Exception as exc:  # noqa: BLE001 - re-raised as a typed LLMError
                wait = _retry_after(exc, attempt)
                last = attempt == self.rate_limit_retries
                if wait is None or last or time.monotonic() + wait >= deadline:
                    raise _provider_error(exc) from exc
                self._sleep(wait)
                attempt += 1
                continue
            return parse_json_object(str(message.content))


def _provider_message(exc: Exception) -> str:
    body = getattr(exc, "body", None)
    message = body.get("message") if isinstance(body, dict) else None
    return str(message)[:300] if message else ""


def _retry_after(exc: Exception, attempt: int) -> float | None:
    """Seconds to wait before retrying a 429, or ``None`` when retrying cannot help."""
    if getattr(exc, "status_code", None) != 429:
        return None
    if "request too large" in _provider_message(exc).lower():
        return None
    headers = getattr(getattr(exc, "response", None), "headers", None) or {}
    try:
        return max(0.0, float(headers.get("retry-after", "")))
    except ValueError:
        return BACKOFF_BASE_S * 2**attempt


def _strict_format(schema: JsonObject) -> JsonObject:
    return {
        "type": "json_schema",
        "json_schema": {"name": "guardian_reply", "strict": True, "schema": schema},
    }


def _provider_error(exc: Exception) -> LLMError:
    status = getattr(exc, "status_code", None)
    if "timeout" in type(exc).__name__.lower():
        return LLMTimeout("No reply within the deadline.")
    if status == 400:
        detail = _provider_message(exc)
        return LLMBadResponse(
            "Provider rejected the reply as not matching the agent schema (400)."
            + (f" {detail}" if detail else "")
        )
    hints = {401: " Check GUARDIAN_LLM_API_KEY.", 403: " Key lacks access.", 429: " Rate limited."}
    if isinstance(status, int):
        detail = _provider_message(exc)
        detail = f" {detail}" if detail else ""
        return LLMError(f"Provider returned HTTP {status}.{hints.get(status, '')}{detail}")
    return LLMError(f"Provider call failed: {type(exc).__name__}.")


def groq_client(
    api_key: str,
    model: str = GROQ_DEFAULT_MODEL,
    timeout: float = 30.0,
    rate_limit_retries: int = RATE_LIMIT_RETRIES,
    max_tokens: int = MAX_TOKENS,
) -> LLMClient:
    """Groq through LangChain (``langchain-groq``), strict structured outputs, no SDK retries."""
    if not api_key:
        raise ValueError(
            "GUARDIAN_LLM_PROVIDER=groq needs GUARDIAN_LLM_API_KEY (or GROQ_API_KEY) in .env "
            "(create one at https://console.groq.com/keys), or set GUARDIAN_LLM_PROVIDER=none."
        )
    chat = ChatGroq(
        model=model or GROQ_DEFAULT_MODEL,
        api_key=SecretStr(api_key),
        temperature=0,
        max_retries=0,
        timeout=timeout,
        max_tokens=max_tokens,
    )
    return LangChainChatClient(chat, name="groq", rate_limit_retries=rate_limit_retries)


def _http_message(exc: urllib.error.HTTPError) -> str:
    """The provider's error text; Gemini wraps the OpenAI-style error object in a list."""
    try:
        data = json.loads(exc.read() or b"null")
    except (OSError, json.JSONDecodeError):
        return ""
    error = (data[0] if isinstance(data, list) and data else data) or {}
    error = error.get("error", error) if isinstance(error, dict) else {}
    message = error.get("message") if isinstance(error, dict) else None
    return str(message)[:300] if message else ""


def _http_error(exc: urllib.error.HTTPError) -> LLMError:
    """A 400 is a schema break (retry once) unless it is a bad key, which trips the breaker."""
    detail = _http_message(exc)
    suffix = f" {detail}" if detail else ""
    if exc.code == 400 and "api key" not in detail.lower():
        return LLMBadResponse(
            f"Provider rejected the reply as not matching the claim schema (400).{suffix}"
        )
    hints = {401: " Check the API key.", 403: " Key lacks access.", 429: " Rate limited."}
    return LLMError(f"Provider returned HTTP {exc.code}.{hints.get(exc.code, '')}{suffix}")


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def parse_json_object(text: str) -> JsonObject:
    """Parse a model reply that should be exactly one JSON object (code fences tolerated)."""
    cleaned = _FENCE.sub("", text.strip())
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise LLMBadResponse("Model reply was not valid JSON.") from exc
    if not isinstance(value, dict):
        raise LLMBadResponse("Model reply was JSON but not an object.")
    return value


def build_client(
    provider: str,
    model: str = "",
    api_key: str = "",
    base_url: str = "",
    rate_limit_retries: int = RATE_LIMIT_RETRIES,
    max_tokens: int = MAX_TOKENS,
) -> LLMClient:
    """Factory used by the runner. Raises ``ValueError`` (fail at startup) on bad settings."""
    if provider in ("", "none"):
        return NoneClient()
    if provider == "groq":
        return groq_client(
            api_key=api_key,
            model=model,
            rate_limit_retries=rate_limit_retries,
            max_tokens=max_tokens,
        )
    if provider == "openai_compatible":
        return OpenAICompatibleClient(base_url=base_url, api_key=api_key, model=model)
    raise ValueError(
        f"Unknown GUARDIAN_LLM_PROVIDER '{provider}'. Use one of: {', '.join(PROVIDERS)}."
    )


class FallbackClient:
    """Ordered provider chain with a per-run breaker: a provider that fails is not retried.

    Schema mismatches (``LLMBadResponse``) and "not configured" (``LLMUnavailable``) are
    re-raised unchanged: the runtime retries the former once, and neither says the provider
    is down. Every other ``LLMError`` (429, 5xx, 401/403, timeout, network) moves on.
    """

    def __init__(self, providers: list[tuple[str, LLMClient]], skipped: dict[str, str]) -> None:
        self._providers = providers
        self.skipped = skipped
        self.failed: dict[str, str] = {}
        self._lock = threading.Lock()
        self._local = threading.local()
        self.name = "→".join(label.split(":")[0] for label, _ in providers)

    @property
    def last_used(self) -> str | None:
        """The provider that answered this thread's latest call (calls run in parallel)."""
        value: str | None = getattr(self._local, "last_used", None)
        return value

    @property
    def labels(self) -> list[str]:
        return [label for label, _ in self._providers]

    def complete(self, system: str, user: str, schema: JsonObject, timeout: float) -> JsonObject:
        for label, client in self._providers:
            with self._lock:
                if label in self.failed:
                    continue
            try:
                result = client.complete(system, user, schema, timeout)
            except (LLMBadResponse, LLMUnavailable):
                raise
            except LLMError as exc:
                with self._lock:
                    self.failed.setdefault(label, f"{type(exc).__name__}: {exc}")
                continue
            self._local.last_used = label
            return result
        with self._lock:
            reasons = "; ".join(f"{label}: {reason}" for label, reason in self.failed.items())
        raise LLMError(f"All LLM providers failed. {reasons}")


def with_fallbacks(primary: LLMClient, primary_label: str, env: Mapping[str, str]) -> LLMClient:
    """Wrap the primary client in the ``GUARDIAN_LLM_FALLBACKS`` chain; AI off stays off."""
    if isinstance(primary, NoneClient):
        return primary
    providers: list[tuple[str, LLMClient]] = [(primary_label, primary)]
    skipped: dict[str, str] = {}
    for name in [n.strip().lower() for n in env.get("GUARDIAN_LLM_FALLBACKS", "").split(",")]:
        if not name:
            continue
        if name not in FALLBACK_PROVIDERS:
            raise ValueError(
                f"Unknown provider '{name}' in GUARDIAN_LLM_FALLBACKS. "
                f"Use: {', '.join(FALLBACK_PROVIDERS)}."
            )
        key_var, model_var, default_model, base_url, strict = FALLBACK_PROVIDERS[name]
        key = env.get(key_var, "").strip()
        if not key:
            skipped[name] = "skipped: no key"
            continue
        model = env.get(model_var, "").strip() or default_model
        client = OpenAICompatibleClient(base_url, key, model, strict_schema=strict)
        providers.append((f"{name}:{model}", client))
    return FallbackClient(providers, skipped)


def read_env_file(path: Path) -> dict[str, str]:
    """Minimal ``.env`` reader (KEY=VALUE lines, # comments, optional quotes)."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        values[key.strip()] = value.strip().strip("\"'")
    return values


def client_from_env(env: Mapping[str, str]) -> LLMClient:
    """Build the client from ``GUARDIAN_LLM_*`` / ``GROQ_API_KEY`` settings."""
    provider = env.get("GUARDIAN_LLM_PROVIDER", "none").strip().lower()
    api_key = env.get("GUARDIAN_LLM_API_KEY") or env.get("GROQ_API_KEY", "")
    return build_client(
        provider,
        model=env.get("GUARDIAN_LLM_MODEL", ""),
        api_key=api_key.strip(),
        base_url=env.get("GUARDIAN_LLM_BASE_URL", ""),
        rate_limit_retries=int(env.get("GUARDIAN_LLM_RATE_LIMIT_RETRIES", RATE_LIMIT_RETRIES)),
        max_tokens=int(env.get("GUARDIAN_LLM_MAX_TOKENS", MAX_TOKENS)),
    )
