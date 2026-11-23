"""Fetch selected files, prepare lockfiles and run the Guardian scan in a worker thread."""

import hashlib
import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import uuid4

from guardian import runner
from guardian.ai.llm import read_env_file
from guardian.changes import ChangeSummary, compute_changes
from guardian.fetch import (
    MANIFEST_NAME,
    FetchedFile,
    FetchError,
    FetchResult,
    fetch_repo_files,
    parse_github_url,
    write_manifest,
)
from guardian.models import FindingsArtifact, GraphArtifact, RunResult
from guardian.prepare import generate_npm_lockfiles

from .schemas import FetchSummary, ScanRecord, ScanResult

SCANS: Final[dict[str, ScanRecord]] = {}
REPO_ROOT: Final = Path(__file__).resolve().parents[3]
FAKE_CLAIM: Final = REPO_ROOT / "tests" / "fixtures" / "fake_cve_claim.json"
DEMO_APP: Final = REPO_ROOT / "demo" / "vulnerable-app"
DEMO_LABEL: Final = "Built-in demo app (demo/vulnerable-app, local, no network)"
CHANGES_FILE: Final = "changes.json"
DEMO_FILES: Final = frozenset({"package.json", "package-lock.json", "ci.yml"})


def load_root_env(path: Path = REPO_ROOT / ".env") -> None:
    """Load the repository-root ``.env`` once; real environment variables win."""
    for key, value in read_env_file(path).items():
        os.environ.setdefault(key, value)


def ai_enabled() -> bool:
    """AI agents run only when a provider and its key are configured."""
    provider = os.environ.get("GUARDIAN_LLM_PROVIDER", "none").strip().lower()
    return provider not in ("", "none") and bool(os.environ.get("GUARDIAN_LLM_API_KEY", "").strip())


def create_record(url: str, ref: str, base: Path, baseline_ref: str = "") -> ScanRecord:
    owner, repo = parse_github_url(url)
    scan_id = uuid4().hex
    record = ScanRecord(
        scan_id=scan_id, repository_url=f"https://github.com/{owner}/{repo}", ref=ref,
        baseline_ref=baseline_ref,
        created_at=datetime.now(UTC), work_dir=base / scan_id,
    )
    SCANS[scan_id] = record
    return record


def create_demo_record(base: Path) -> ScanRecord:
    scan_id = uuid4().hex
    record = ScanRecord(scan_id=scan_id, repository_url=DEMO_LABEL, ref="local", demo=True,
                        created_at=datetime.now(UTC), work_dir=base / scan_id)
    SCANS[scan_id] = record
    return record


def prepare_demo(repo_dir: Path) -> FetchResult:
    """Copy the local demo app (source included, so reachability can be checked)."""
    shutil.copytree(DEMO_APP, repo_dir, ignore=shutil.ignore_patterns("node_modules"))
    files = [
        FetchedFile(path=path.relative_to(repo_dir).as_posix(), size=path.stat().st_size,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        for path in sorted(repo_dir.rglob("*"))
        if path.is_file() and path.name in DEMO_FILES and "vendor" not in path.parts
    ]
    result = FetchResult(url=DEMO_LABEL, ref="local", commit_sha="local-demo", dest=repo_dir,
                         files=files)
    write_manifest(result)
    return result


def _fail(record: ScanRecord, message: str) -> None:
    record.status = "failed"
    record.error = message
    record.stage = "done"


def _apply_result(record: ScanRecord, result: RunResult) -> None:
    record.status = result.scan.status.value  # type: ignore[assignment]
    record.llm_status = result.scan.llm_status.value
    record.errors = {**record.errors, **result.scan.errors}
    record.stage = "done"


def _fetch_and_prepare(record: ScanRecord, repo_dir: Path, token: str | None) -> bool:
    record.stage = "fetching"
    fetched = fetch_repo_files(record.repository_url, record.ref, repo_dir, token)
    record.commit_sha, record.ref = fetched.commit_sha, fetched.ref
    record.stage = "preparing"
    prepared = generate_npm_lockfiles(fetched)
    record.errors.update(prepared.errors)
    if not prepared.files:
        _fail(record, "No dependency manifests or lockfiles found in the repository")
        return False
    return True


def _scan_baseline(record: ScanRecord, token: str | None) -> tuple[Path, str] | None:
    record.stage = "baseline"
    base_dir = record.work_dir / "baseline"
    try:
        fetched = fetch_repo_files(record.repository_url, record.baseline_ref,
                                   base_dir / "repo", token)
        if not generate_npm_lockfiles(fetched).files:
            raise FetchError(f"No dependency manifests found at baseline '{record.baseline_ref}'")
        runner.scan(base_dir / "repo", base_dir / "out", use_llm=False)
    except Exception as error:  # noqa: BLE001 - the main scan stays useful without a baseline
        record.errors["baseline"] = f"{type(error).__name__}: {error}"
        return None
    return base_dir / "out", fetched.commit_sha


def _read_artifacts(out: Path) -> tuple[GraphArtifact, FindingsArtifact]:
    return (
        GraphArtifact.model_validate_json((out / "graph.json").read_text(encoding="utf-8")),
        FindingsArtifact.model_validate_json((out / "findings.json").read_text(encoding="utf-8")),
    )


def _write_changes(record: ScanRecord, baseline_out: Path, baseline_commit: str) -> None:
    out = record.work_dir / "out"
    old_graph, old_findings = _read_artifacts(baseline_out)
    new_graph, new_findings = _read_artifacts(out)
    changes = compute_changes(old_graph, new_graph, old_findings.findings, new_findings.findings,
                              record.baseline_ref, baseline_commit)
    (out / CHANGES_FILE).write_text(changes.model_dump_json(indent=2), encoding="utf-8")


def _record_changes(record: ScanRecord, baseline_out: Path, baseline_commit: str) -> None:
    try:
        _write_changes(record, baseline_out, baseline_commit)
    except (OSError, ValueError) as error:
        record.errors["baseline"] = f"Could not compare with the baseline: {error}"


def run_pipeline(record: ScanRecord, token: str | None, inject_fake_claim: bool = False) -> None:
    repo_dir = record.work_dir / "repo"
    out_dir = record.work_dir / "out"
    try:
        if record.demo:
            record.stage = "preparing"
            record.commit_sha = prepare_demo(repo_dir).commit_sha
        elif not _fetch_and_prepare(record, repo_dir, token):
            return
        baseline = _scan_baseline(record, token) if record.baseline_ref else None
        record.stage = "scanning"
        inject = FAKE_CLAIM if inject_fake_claim else None
        result = runner.scan(repo_dir, out_dir, baseline=baseline[0] if baseline else None,
                             use_llm=ai_enabled(), inject_claim=inject)
        if baseline:
            _record_changes(record, *baseline)
        _apply_result(record, result)
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
    changes_path = out / CHANGES_FILE
    changes = (ChangeSummary.model_validate_json(changes_path.read_text(encoding="utf-8"))
               if changes_path.is_file() else None)
    return ScanResult(
        scan=run.scan, findings=run.findings, evidence=run.evidence, coverage=run.coverage,
        counts_by_risk=counts, fetch=_fetch_summary(record), claims=run.claims,
        agent_trace=run.agent_trace, risk_adjustments=run.risk_adjustments,
        agreement=run.agreement, changes=changes,
    )
