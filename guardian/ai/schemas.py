"""Strict shape of what the model is allowed to return.

Anything that does not parse against ``LLMReply`` is rejected (and retried once
by the step runner). ``extra="forbid"`` stops the model from smuggling in extra
fields such as a risk level or a verdict.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_CLAIMS_PER_STEP = 8
MAX_CLAIM_CHARS = 600


class LLMClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=MAX_CLAIM_CHARS)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    kind: Literal["evidence", "inference"]
    uncertainty: str | None = Field(default=None, max_length=200)


class LLMReply(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claims: list[LLMClaim] = Field(max_length=MAX_CLAIMS_PER_STEP)
