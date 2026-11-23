"""Request and response models for the Guardian API."""

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from guardian.fetch import FetchedFile
from guardian.models import (
    AgentClaim,
    AgentTrace,
    CoverageArtifact,
    Evidence,
    Finding,
    RiskAdjustment,
    Scan,
)

Status = Literal["running", "complete", "partial", "failed"]


class ScanRequest(BaseModel):
    url: str = Field(default="", max_length=400)
    ref: str = Field(default="", max_length=120)
    inject_fake_claim: bool = False
    demo: bool = False

    @model_validator(mode="after")
    def require_url_unless_demo(self) -> "ScanRequest":
        if not self.demo and not self.url.strip():
            raise ValueError("Enter a GitHub repository URL, or choose the built-in demo app.")
        return self


class ScanRecord(BaseModel):
    scan_id: str
    status: Status = "running"
    stage: str = "queued"
    repository_url: str
    ref: str = ""
    commit_sha: str = ""
    llm_status: str = "unavailable"
    demo: bool = False
    error: str | None = None
    errors: dict[str, str] = Field(default_factory=dict)
    created_at: datetime
    work_dir: Path = Field(exclude=True)


class ScanStarted(BaseModel):
    scan_id: str
    status: Status


class FetchSummary(BaseModel):
    ref: str
    commit_sha: str
    files: list[FetchedFile]
    skipped: list[str]
    errors: dict[str, str]


class ScanResult(BaseModel):
    scan: Scan
    findings: list[Finding]
    evidence: list[Evidence]
    coverage: CoverageArtifact
    counts_by_risk: dict[str, int]
    fetch: FetchSummary
    claims: list[AgentClaim] = Field(default_factory=list)
    agent_trace: list[AgentTrace] = Field(default_factory=list)
    risk_adjustments: list[RiskAdjustment] = Field(default_factory=list)
    agreement: dict[str, bool] = Field(default_factory=dict)
