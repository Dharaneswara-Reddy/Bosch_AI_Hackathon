"""Shared runtime for every LLM agent: deadline, one retry, circuit breaker, redaction.

* Each call has a hard deadline (``timeout``).
* A reply that does not match the agent's schema is retried once.
* ``BREAKER_THRESHOLD`` consecutive provider-level failures (timeout, auth, rate limit,
  network) open the breaker: no agent calls the model again in this run. One failed
  branch therefore never stops the other branches; a real outage stops quickly.
* Input is redacted for secrets and wrapped as untrusted data before sending.
* Branches run in parallel, so every counter is updated under one lock and the provider
  that answered is read in the thread that made the call.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from guardian.ai.context import ReviewContext
from guardian.ai.guardrails import redact_secrets
from guardian.ai.llm import LLMBadResponse, LLMClient, LLMError, LLMTimeout, LLMUnavailable
from guardian.ai.prompts import AgentRole, system_prompt, user_prompt
from guardian.ai.schemas import JsonSchema

ReplyT = TypeVar("ReplyT", bound=BaseModel)
BREAKER_THRESHOLD = 3
# Sized well above any sane GUARDIAN_LLM_CONCURRENCY so queueing never eats a call's deadline.
_EXECUTOR = ThreadPoolExecutor(max_workers=32, thread_name_prefix="guardian-llm")


def branch_key(agent: str, branch: str = "") -> str:
    """Key of one agent run: ``agent`` alone, or ``agent:branch`` for a package-group branch."""
    return f"{agent}:{branch}" if branch else agent


@dataclass
class AgentRuntime:
    ctx: ReviewContext
    client: LLMClient
    timeout: float
    calls: int = 0
    redactions: int = 0
    unavailable: bool = False
    open_reason: str | None = None
    failure_streak: int = 0
    attempted: set[str] = field(default_factory=set)
    succeeded: set[str] = field(default_factory=set)
    answered_by: dict[str, str] = field(default_factory=dict)
    calls_by: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    @property
    def blocked(self) -> str | None:
        if self.unavailable:
            return "LLM unavailable"
        return self.open_reason

    def _blocked_for(self, reserved: bool) -> str | None:
        if self.unavailable:
            return "LLM unavailable"
        return None if reserved else self.open_reason

    def ask(
        self,
        agent: AgentRole,
        data: dict[str, Any],
        schema: JsonSchema,
        reply: type[ReplyT],
        branch: str = "",
        reserved_timeout: float | None = None,
    ) -> tuple[ReplyT | None, str | None]:
        """Call the model for one agent. Returns (reply, None) or (None, error).

        ``reserved_timeout`` gives the call its own deadline and ignores the run's open breaker
        and failed-provider marks, so an agent late in the run is not starved by earlier
        rate limits.
        """
        reserved = reserved_timeout is not None
        deadline = reserved_timeout if reserved_timeout is not None else self.timeout
        blocked = self._blocked_for(reserved)
        if blocked is not None:
            return None, blocked
        if reserved:
            getattr(self.client, "revive", lambda: None)()
        key = branch_key(agent.name, branch)
        redacted, count = redact_secrets(json.dumps(data, sort_keys=True, default=str))
        with self._lock:
            self.attempted.add(agent.name)
            self.redactions += count
        system, user = system_prompt(agent, schema), user_prompt(agent, redacted)
        error = ""
        for _attempt in range(2):
            parsed, error, retry, provider = self._attempt(
                key, system, user, schema, reply, deadline, reserved
            )
            if parsed is not None:
                with self._lock:
                    self.succeeded.add(agent.name)
                    self.answered_by[key] = provider or self.client.name
                    self.failure_streak = 0
                return parsed, None
            if not retry:
                break
        return None, error

    def _attempt(
        self,
        key: str,
        system: str,
        user: str,
        schema: JsonSchema,
        reply: type[ReplyT],
        deadline: float,
        reserved: bool,
    ) -> tuple[ReplyT | None, str, bool, str | None]:
        blocked = self._blocked_for(reserved)
        if blocked is not None:
            return None, blocked, False, None
        with self._lock:
            self.calls += 1
            self.calls_by[key] = self.calls_by.get(key, 0) + 1
        try:
            raw, provider = self._call(system, user, schema, deadline)
            return reply.model_validate(raw), "", False, provider
        except (ValidationError, LLMBadResponse) as exc:
            message = f"reply did not match the agent schema: {str(exc)[:200]}"
            return None, message, True, None
        except LLMUnavailable as exc:
            with self._lock:
                self.unavailable = True
            return None, str(exc), False, None
        except LLMError as exc:
            return None, self._record_failure(f"{type(exc).__name__}: {exc}"), False, None

    def _record_failure(self, reason: str) -> str:
        with self._lock:
            self.failure_streak += 1
            if self.failure_streak >= BREAKER_THRESHOLD and self.open_reason is None:
                self.open_reason = reason
        return reason

    def _invoke(
        self, system: str, user: str, schema: JsonSchema, deadline: float
    ) -> tuple[dict[str, Any], str | None]:
        result = self.client.complete(system, user, schema, deadline)
        return result, getattr(self.client, "last_used", None)

    def _call(
        self, system: str, user: str, schema: JsonSchema, deadline: float
    ) -> tuple[dict[str, Any], str | None]:
        # Each provider in a fallback chain gets its own deadline, so the outer wait covers all.
        budget = deadline * max(1, len(getattr(self.client, "labels", [])))
        future = _EXECUTOR.submit(self._invoke, system, user, schema, deadline)
        try:
            return future.result(timeout=budget)
        except FutureTimeout as exc:
            future.cancel()
            raise LLMTimeout(f"No reply within {budget:.0f}s.") from exc
