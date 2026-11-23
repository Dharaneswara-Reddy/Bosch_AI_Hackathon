"""Risk policy: thresholds and weights loaded from policy/risk.toml and validated once."""

import tomllib
from functools import cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "policy" / "risk.toml"


class PolicyError(ValueError):
    """The risk policy file is missing, malformed or has an invalid value."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExposureFactors(_Strict):
    open: float = Field(default=1.0, ge=0, le=1)
    limited: float = Field(default=0.85, ge=0, le=1)
    small: float = Field(default=0.6, ge=0, le=1)


class ConfidenceWeights(_Strict):
    version_confirmed: float = Field(default=0.25, ge=0)
    path_resolved: float = Field(default=0.15, ge=0)
    scanners_agree: float = Field(default=0.15, ge=0)
    exploit_data: float = Field(default=0.15, ge=0)
    reachability_known: float = Field(default=0.15, ge=0)
    analyst_critic_agreement: float = Field(default=0.15, ge=0)

    @property
    def total(self) -> float:
        """Sum of the five code-computed factors, the denominator for unreviewed findings."""
        return float(sum(self.model_dump(exclude={"analyst_critic_agreement"}).values()))

    @property
    def total_reviewed(self) -> float:
        return self.total + self.analyst_critic_agreement


class RiskPolicy(_Strict):
    epss_threshold: float = Field(default=0.1, ge=0, le=1)
    epss_percentile_threshold: float = Field(default=0.95, ge=0, le=1)
    epss_weight: float = Field(default=0.3, ge=0, le=1)
    review_confidence_threshold: float = Field(default=0.6, ge=0, le=1)
    exposure_factor: ExposureFactors = Field(default_factory=ExposureFactors)
    confidence_weights: ConfidenceWeights = Field(default_factory=ConfidenceWeights)


def _describe(error: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}" for item in error.errors()
    )


@cache
def load_policy(path: Path = DEFAULT_POLICY_PATH) -> RiskPolicy:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise PolicyError(f"Cannot read risk policy {path}: {error}") from error
    try:
        policy = RiskPolicy.model_validate(data)
    except ValidationError as error:
        raise PolicyError(f"Invalid risk policy {path}: {_describe(error)}") from error
    if policy.confidence_weights.total <= 0:
        raise PolicyError(f"Invalid risk policy {path}: confidence_weights must not all be zero")
    return policy
