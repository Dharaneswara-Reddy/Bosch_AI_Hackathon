"""Adversarial test doubles for the LLM interface."""

from __future__ import annotations

import time
from typing import Any

from guardian.ai.llm import LLMError


class ScriptedLLM:
    """Returns the given replies in order (the last one repeats) and records every prompt."""

    name = "scripted"

    def __init__(self, *replies: dict[str, Any]) -> None:
        self.replies = list(replies)
        self.prompts: list[tuple[str, str]] = []

    def complete(
        self, system: str, user: str, schema: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        self.prompts.append((system, user))
        return self.replies[min(len(self.prompts) - 1, len(self.replies) - 1)]


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
