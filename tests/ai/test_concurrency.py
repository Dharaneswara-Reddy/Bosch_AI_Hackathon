from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from guardian.ai.llm import FallbackClient, LLMError
from guardian.ai.prompts import VULN_ANALYST
from guardian.ai.runtime import AgentRuntime
from guardian.ai.schemas import STRICT_REPLY_SCHEMA, LLMReply
from tests.ai.factories import make_context

WORKERS = 32


class Failing:
    name = "failing"

    def __init__(self) -> None:
        self.calls = 0
        self._lock = threading.Lock()

    def complete(self, system: str, user: str, schema: dict[str, Any], timeout: float) -> Any:
        with self._lock:
            self.calls += 1
        raise LLMError("Provider returned HTTP 429. Rate limited.")


class Echo:
    def __init__(self, name: str, tag: bool = True) -> None:
        self.name = name
        self._tag = tag

    def complete(self, system: str, user: str, schema: dict[str, Any], timeout: float) -> Any:
        return {"claims": [], "who": self.name} if self._tag else {"claims": []}


def test_fallback_client_state_is_consistent_under_concurrent_calls() -> None:
    client = FallbackClient([("a", Failing()), ("b", Echo("b")), ("c", Echo("c"))], skipped={})
    with ThreadPoolExecutor(WORKERS) as pool:
        results = list(pool.map(lambda _: client.complete("s", "u", {}, 1.0), range(400)))
    assert {r["who"] for r in results} == {"b"}
    assert list(client.failed) == ["a"]
    client.complete("s", "u", {}, 1.0)
    assert client.last_used == "b"


def test_last_used_is_per_thread() -> None:
    client = FallbackClient([("a", Echo("a"))], skipped={})
    seen: list[str | None] = []
    thread = threading.Thread(target=lambda: seen.append(client.last_used))
    client.complete("s", "u", {}, 1.0)
    thread.start()
    thread.join()
    assert client.last_used == "a" and seen == [None]


def test_runtime_counters_are_consistent_under_concurrent_asks() -> None:
    client = FallbackClient([("a", Failing()), ("b", Echo("b", tag=False))], skipped={})
    runtime = AgentRuntime(ctx=make_context(), client=client, timeout=5)

    def ask(i: int) -> str | None:
        branch = f"g{i % 8}"
        reply, error = runtime.ask(
            VULN_ANALYST, {"n": i}, STRICT_REPLY_SCHEMA, LLMReply, branch=branch
        )
        assert reply is not None and error is None
        return runtime.answered_by[f"vuln_analyst:{branch}"]

    with ThreadPoolExecutor(WORKERS) as pool:
        providers = set(pool.map(ask, range(200)))
    assert providers == {"b"}
    assert runtime.calls == 200
    assert sum(runtime.calls_by.values()) == 200
    assert set(runtime.calls_by) == {f"vuln_analyst:g{i}" for i in range(8)}
    assert runtime.blocked is None
