"""Request and response models for the Guardian API."""

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from guardian.fetch import FetchedFile
from guardian.models import CoverageArtifact, Evidence, Finding, Scan

Status = Literal["running", "complete", "partial", "failed"]


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=400)
    ref: str = Field(default="", max_length=120)


class ScanRecord(BaseModel):
    scan_id: str
    status: Status = "running"
    stage: str = "queued"
    repository_url: str
    ref: str = ""
    commit_sha: str = ""
    llm_status: str = "unavailable"
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
