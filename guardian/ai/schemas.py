"""The only reply shapes each agent may return.

Every agent has its own Pydantic model (re-validates every reply, including
length limits) and a hand-written strict JSON Schema (sent to Groq so decoding
is constrained to that shape: every field required, no extra properties,
optional values as a null union).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from guardian.ai.state import FixAction, RiskAdjustment

MAX_CLAIMS_PER_STEP = 8
MAX_CLAIM_CHARS = 600
JsonSchema = dict[str, Any]


class LLMClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=MAX_CLAIM_CHARS)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    kind: Literal["evidence", "inference"]
    uncertainty: str | None = Field(default=None, max_length=200)


class LLMReply(BaseModel):
    """Analysts and the report writer."""

    model_config = ConfigDict(extra="forbid")

    claims: list[LLMClaim] = Field(max_length=MAX_CLAIMS_PER_STEP)


class ClaimReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str
    verdict: Literal["supported", "overstated", "unsupported"]
    reason: str = Field(min_length=1, max_length=300)


class AdjustmentReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    verdict: Literal["supported", "overstated", "unsupported"]
    reason: str = Field(min_length=1, max_length=300)


class CriticReply(BaseModel):
    """Independent reviewer: may only keep, downgrade or reject accepted claims and adjustments."""

    model_config = ConfigDict(extra="forbid")

    reviews: list[ClaimReview] = Field(max_length=40)
    adjustment_reviews: list[AdjustmentReview] = Field(default_factory=list, max_length=40)


class RiskReply(BaseModel):
    """Risk analyst: one-level adjustments only; an empty list means no change."""

    model_config = ConfigDict(extra="forbid")

    adjustments: list[RiskAdjustment] = Field(max_length=40)


class LLMProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    action: FixAction
    target_version: str | None = None
    rationale: str = Field(min_length=1, max_length=MAX_CLAIM_CHARS)
    rollback: str = Field(min_length=1, max_length=300)
    breaking_change_risk: Literal["low", "medium", "high", "unknown"]
    evidence_ids: list[str] = Field(min_length=1, max_length=20)


class PlannerReply(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposals: list[LLMProposal] = Field(max_length=20)


def _strict_object(properties: JsonSchema) -> JsonSchema:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def _list_of(properties: JsonSchema, key: str) -> JsonSchema:
    return _strict_object({key: {"type": "array", "items": _strict_object(properties)}})


_STRINGS: JsonSchema = {"type": "array", "items": {"type": "string"}}

STRICT_REPLY_SCHEMA: JsonSchema = _list_of(
    {
        "text": {"type": "string"},
        "evidence_ids": _STRINGS,
        "kind": {"type": "string", "enum": ["evidence", "inference"]},
        "uncertainty": {"type": ["string", "null"]},
    },
    "claims",
)

_VERDICT: JsonSchema = {"type": "string", "enum": ["supported", "overstated", "unsupported"]}
_LEVEL: JsonSchema = {"type": "string", "enum": ["critical", "high", "medium", "low"]}

STRICT_CRITIC_SCHEMA: JsonSchema = _strict_object(
    {
        "reviews": {
            "type": "array",
            "items": _strict_object(
                {"claim_id": {"type": "string"}, "verdict": _VERDICT, "reason": {"type": "string"}}
            ),
        },
        "adjustment_reviews": {
            "type": "array",
            "items": _strict_object(
                {
                    "finding_id": {"type": "string"},
                    "verdict": _VERDICT,
                    "reason": {"type": "string"},
                }
            ),
        },
    }
)

STRICT_RISK_SCHEMA: JsonSchema = _list_of(
    {
        "finding_id": {"type": "string"},
        "from_level": _LEVEL,
        "to_level": _LEVEL,
        "direction": {"type": "string", "enum": ["raise", "lower"]},
        "reason": {"type": "string"},
        "evidence_ids": _STRINGS,
    },
    "adjustments",
)

STRICT_PLANNER_SCHEMA: JsonSchema = _list_of(
    {
        "finding_id": {"type": "string"},
        "action": {"type": "string", "enum": [a.value for a in FixAction]},
        "target_version": {"type": ["string", "null"]},
        "rationale": {"type": "string"},
        "rollback": {"type": "string"},
        "breaking_change_risk": {"type": "string", "enum": ["low", "medium", "high", "unknown"]},
        "evidence_ids": _STRINGS,
    },
    "proposals",
)
