"""Shared runtime for every LLM agent: deadline, one retry, circuit breaker, redaction.

* Each call has a hard deadline (``timeout``).
* A reply that does not match the agent's schema is retried once.
* The first provider-level failure (timeout, auth, rate limit, network) opens
  the breaker: no agent calls the model again in this run.
* Input is redacted for secrets and wrapped as untrusted data before sending.
"""

from __future__ import annotations

import json
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
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="guardian-llm")


@dataclass
class AgentRuntime:
    ctx: ReviewContext
    client: LLMClient
    timeout: float
    calls: int = 0
    redactions: int = 0
    unavailable: bool = False
    open_reason: str | None = None
    attempted: set[str] = field(default_factory=set)
    succeeded: set[str] = field(default_factory=set)
    answered_by: dict[str, str] = field(default_factory=dict)

    @property
    def blocked(self) -> str | None:
        if self.unavailable:
            return "LLM unavailable"
        return self.open_reason

    def ask(
        self,
        agent: AgentRole,
        data: dict[str, Any],
        schema: JsonSchema,
        reply: type[ReplyT],
    ) -> tuple[ReplyT | None, str | None]:
        """Call the model for one agent. Returns (reply, None) or (None, error)."""
        if self.blocked is not None:
            return None, self.blocked
        self.attempted.add(agent.name)
        redacted, count = redact_secrets(json.dumps(data, sort_keys=True, default=str))
        self.redactions += count
        system, user = system_prompt(agent, schema), user_prompt(agent, redacted)
        error = ""
        for _attempt in range(2):
            parsed, error, retry = self._attempt(system, user, schema, reply)
            if parsed is not None:
                self.succeeded.add(agent.name)
                self.answered_by[agent.name] = (
                    getattr(self.client, "last_used", None) or self.client.name
                )
                return parsed, None
            if not retry:
                break
        return None, error

    def _attempt(
        self,
        system: str,
        user: str,
        schema: JsonSchema,
        reply: type[ReplyT],
    ) -> tuple[ReplyT | None, str, bool]:
        if self.blocked is not None:
            return None, self.blocked, False
        self.calls += 1
        try:
            return reply.model_validate(self._call(system, user, schema)), "", False
        except (ValidationError, LLMBadResponse) as exc:
            return None, f"reply did not match the agent schema: {str(exc)[:200]}", True
        except LLMUnavailable as exc:
            self.unavailable = True
            return None, str(exc), False
        except LLMError as exc:
            self.open_reason = f"{type(exc).__name__}: {exc}"
            return None, self.open_reason, False

    def _call(self, system: str, user: str, schema: JsonSchema) -> dict[str, Any]:
        # Each provider in a fallback chain gets its own deadline, so the outer wait covers all.
        budget = self.timeout * max(1, len(getattr(self.client, "labels", [])))
        future = _EXECUTOR.submit(self.client.complete, system, user, schema, self.timeout)
        try:
            return future.result(timeout=budget)
        except FutureTimeout as exc:
            future.cancel()
            raise LLMTimeout(f"No reply within {budget:.0f}s.") from exc
