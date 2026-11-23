"""Adversarial test doubles for the LLM interface."""

from __future__ import annotations

import re
import time
from typing import Any

from guardian.ai.llm import LLMError

_AGENT = re.compile(r"^Agent: (\w+)", re.MULTILINE)


class RoutingLLM:
    """Answers per agent (read from the system prompt) and records every call.

    ``replies[agent]`` is a list; the last reply repeats. Agents without a
    scripted reply get an empty, schema-valid answer.
    """

    name = "routing"
    EMPTY = {"claims": [], "reviews": [], "proposals": []}

    def __init__(self, **replies: list[dict[str, Any]]) -> None:
        self.replies = replies
        self.calls: list[tuple[str, str, str]] = []

    def complete(
        self, system: str, user: str, schema: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        match = _AGENT.search(system)
        agent = match.group(1) if match else "unknown"
        self.calls.append((agent, system, user))
        scripted = self.replies.get(agent)
        if not scripted:
            key = next(iter(schema["properties"]))
            return {key: []}
        count = sum(1 for a, _, _ in self.calls if a == agent)
        return scripted[min(count - 1, len(scripted) - 1)]

    def agents_called(self) -> list[str]:
        return [agent for agent, _, _ in self.calls]


class SlowLLM:
    name = "slow"

    def __init__(self) -> None:
        self.calls = 0

    def complete(
        self, system: str, user: str, schema: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        self.calls += 1
        time.sleep(timeout + 1)
        return {"claims": []}


class BrokenLLM:
    name = "broken"

    def complete(
        self, system: str, user: str, schema: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        raise LLMError("Provider returned HTTP 500.")
