"""Fetch selected files, prepare lockfiles and run the Guardian scan in a worker thread."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import uuid4

from guardian import runner
from guardian.fetch import (
    MANIFEST_NAME,
    FetchError,
    FetchResult,
    fetch_repo_files,
    parse_github_url,
)
from guardian.models import RunResult
from guardian.prepare import generate_npm_lockfiles

from .schemas import FetchSummary, ScanRecord, ScanResult

SCANS: Final[dict[str, ScanRecord]] = {}


def create_record(url: str, ref: str, base: Path) -> ScanRecord:
    owner, repo = parse_github_url(url)
    scan_id = uuid4().hex
    record = ScanRecord(
        scan_id=scan_id, repository_url=f"https://github.com/{owner}/{repo}", ref=ref,
        created_at=datetime.now(UTC), work_dir=base / scan_id,
    )
    SCANS[scan_id] = record
    return record


def _fail(record: ScanRecord, message: str) -> None:
    record.status = "failed"
    record.error = message
    record.stage = "done"


def _apply_result(record: ScanRecord, result: RunResult) -> None:
    record.status = result.scan.status.value  # type: ignore[assignment]
    record.llm_status = result.scan.llm_status.value
    record.errors = {**record.errors, **result.scan.errors}
    record.stage = "done"


def run_pipeline(record: ScanRecord, token: str | None) -> None:
    repo_dir = record.work_dir / "repo"
    out_dir = record.work_dir / "out"
    try:
        record.stage = "fetching"
        fetched = fetch_repo_files(record.repository_url, record.ref, repo_dir, token)
        record.commit_sha, record.ref = fetched.commit_sha, fetched.ref
        record.stage = "preparing"
        prepared = generate_npm_lockfiles(fetched)
        record.errors.update(prepared.errors)
        if not prepared.files:
            _fail(record, "No dependency manifests or lockfiles found in the repository")
            return
        record.stage = "scanning"
        _apply_result(record, runner.scan(repo_dir, out_dir, use_llm=False))
    except FetchError as error:
        _fail(record, str(error))
    except Exception as error:  # noqa: BLE001 - worker boundary: report, never lose the failure
        _fail(record, f"{type(error).__name__}: {error}")


def _fetch_summary(record: ScanRecord) -> FetchSummary:
    manifest = FetchResult.model_validate_json(
        (record.work_dir / MANIFEST_NAME).read_text(encoding="utf-8"),
    )
    return FetchSummary(
        ref=manifest.ref, commit_sha=manifest.commit_sha, files=manifest.files,
        skipped=manifest.skipped, errors=manifest.errors,
    )


def load_result(record: ScanRecord) -> ScanResult:
    out = record.work_dir / "out"
    run = RunResult.model_validate({
        "scan": json.loads((out / "run.json").read_text(encoding="utf-8")),
        "coverage": json.loads((out / "coverage.json").read_text(encoding="utf-8")),
        **json.loads((out / "findings.json").read_text(encoding="utf-8")),
    })
    counts: dict[str, int] = {}
    for finding in run.findings:
        counts[finding.risk_level.value] = counts.get(finding.risk_level.value, 0) + 1
    return ScanResult(
        scan=run.scan, findings=run.findings, evidence=run.evidence, coverage=run.coverage,
        counts_by_risk=counts, fetch=_fetch_summary(record),
    )
