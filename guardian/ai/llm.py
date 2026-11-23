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
import urllib.error
import urllib.request
from typing import Any, Protocol

JsonObject = dict[str, Any]


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

    def __init__(self, base_url: str, api_key: str, model: str) -> None:
        if not base_url or not model:
            raise ValueError(
                "GUARDIAN_LLM_BASE_URL and GUARDIAN_LLM_MODEL must be set for this provider."
            )
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._api_key = api_key
        self._model = model

    def complete(self, system: str, user: str, schema: JsonObject, timeout: float) -> JsonObject:
        body = {
            "model": self._model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        payload = self._post(body, timeout)
        try:
            text = str(payload["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMBadResponse("Provider reply has no choices[0].message.content.") from exc
        return parse_json_object(text)

    def _post(self, body: JsonObject, timeout: float) -> JsonObject:
        headers = {"Content-Type": "application/json"}
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
            raise LLMError(f"Provider returned HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise LLMTimeout(f"No reply within {timeout:.0f}s.") from exc
            raise LLMError(f"Provider unreachable: {exc.reason}.") from exc
        except json.JSONDecodeError as exc:
            raise LLMBadResponse("Provider reply was not JSON.") from exc


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
    provider: str, model: str = "", api_key: str = "", base_url: str = ""
) -> LLMClient:
    """Factory used by the runner with values from P5's settings."""
    if provider in ("", "none"):
        return NoneClient()
    if provider == "openai_compatible":
        return OpenAICompatibleClient(base_url=base_url, api_key=api_key, model=model)
    raise ValueError(
        f"Unknown GUARDIAN_LLM_PROVIDER '{provider}'. Use 'none' or 'openai_compatible'."
    )
