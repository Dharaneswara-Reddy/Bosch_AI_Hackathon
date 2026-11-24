"""Guardian API: fetch selected files from a public GitHub repo and run the team scan pipeline."""

import json
import os
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from guardian.ai.llm import FALLBACK_PROVIDERS
from guardian.changes import ChangeSummary
from guardian.fetch import FetchError
from guardian.models import GraphArtifact

from . import pipeline, remediation, review
from .schemas import ReachabilityStatus, ScanRecord, ScanRequest, ScanResult, ScanStarted

pipeline.load_root_env()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    pipeline.load_records(scan_base())
    yield


app = FastAPI(title="Bosch Guardian API", version="0.3.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.include_router(remediation.router)
_default_base: Path | None = None
_reachability_jobs: set[str] = set()


def scan_base() -> Path:
    global _default_base
    configured = os.environ.get("GUARDIAN_SCAN_DIR")
    if configured:
        base = Path(configured)
        base.mkdir(parents=True, exist_ok=True)
        return base
    if _default_base is None:
        _default_base = Path(tempfile.mkdtemp(prefix="guardian-scans-"))
    return _default_base


def _record(scan_id: str) -> ScanRecord:
    record = pipeline.SCANS.get(scan_id)
    if record is None:
        raise HTTPException(404, "Scan not found")
    return record


def _finished(scan_id: str) -> ScanRecord:
    record = _record(scan_id)
    if record.status == "running":
        raise HTTPException(409, "Scan is still running")
    if not (record.work_dir / "out" / "run.json").is_file():
        raise HTTPException(409, record.error or "Scan produced no result files")
    return record


def _artifact(scan_id: str, name: str) -> Path:
    path = _finished(scan_id).work_dir / "out" / name
    if not path.is_file():
        raise HTTPException(404, f"{name} was not produced by this scan")
    return path


@app.get("/health")
def health() -> dict[str, str]:
    if not pipeline.ai_enabled():
        return {"status": "ok", "service": "bosch-guardian", "ai": "off"}
    chain = [os.environ.get("GUARDIAN_LLM_PROVIDER", "none").strip().lower()]
    for name in os.environ.get("GUARDIAN_LLM_FALLBACKS", "").split(","):
        name = name.strip().lower()
        if name in FALLBACK_PROVIDERS and os.environ.get(FALLBACK_PROVIDERS[name][0], "").strip():
            chain.append(name)
    return {"status": "ok", "service": "bosch-guardian", "ai": "→".join(chain)}


@app.post("/scan", status_code=202)
def start_scan(request: ScanRequest, background: BackgroundTasks) -> ScanStarted:
    try:
        record = (
            pipeline.create_demo_record(scan_base())
            if request.demo
            else pipeline.create_record(
                request.url, request.ref, scan_base(), request.baseline_ref.strip()
            )
        )
    except FetchError as error:
        raise HTTPException(422, str(error)) from error
    background.add_task(
        pipeline.run_pipeline,
        record,
        os.environ.get("GITHUB_TOKEN"),
        request.inject_fake_claim,
    )
    return ScanStarted(scan_id=record.scan_id, status=record.status)


@app.get("/scan/{scan_id}")
def scan_status(scan_id: str) -> ScanRecord:
    return _record(scan_id)


@app.get("/scan/{scan_id}/result")
def scan_result(scan_id: str) -> ScanResult:
    return pipeline.load_result(_finished(scan_id))


def _write_reachability_status(path: Path, data: dict[str, object]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _run_reachability(record: ScanRecord) -> None:
    path = record.work_dir / "out" / "reachability.json"
    try:
        from guardian.remediate.workflow import find_engine
        from guardian.runtime_reachability import run_reachability, update_findings

        result = run_reachability(record.work_dir, find_engine())
        if result.get("status") == "complete":
            result["status"] = "running"
            _write_reachability_status(path, result)
            try:
                update_findings(record.work_dir)
                result["status"] = "complete"
                _write_reachability_status(path, result)
            except Exception as error:  # report refresh failures are visible to the user
                result["status"] = "error"
                result["reason"] = f"Evidence collected but report refresh failed: {error}"
                _write_reachability_status(path, result)
    except Exception as error:  # worker boundary: leave a terminal status for the poller
        _write_reachability_status(path, {"status": "error", "reason": str(error), "evidence": []})
    finally:
        _reachability_jobs.discard(record.scan_id)


@app.post("/scan/{scan_id}/reachability", status_code=202)
def start_reachability(scan_id: str, background: BackgroundTasks) -> ReachabilityStatus:
    record = _finished(scan_id)
    if scan_id in _reachability_jobs:
        raise HTTPException(409, "Reachability check is already running")
    path = record.work_dir / "out" / "reachability.json"
    if path.is_file():
        current = json.loads(path.read_text(encoding="utf-8"))
        if current.get("status") == "complete":
            raise HTTPException(409, "Reachability check already completed for this scan")
    _reachability_jobs.add(scan_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_reachability_status(
        path,
        {
            "status": "running",
            "reason": "",
            "ran_at": "pending",
            "tests_status": "not_run",
            "app_status": "not_run",
            "evidence": [],
            "packages_loaded_count": 0,
        },
    )
    background.add_task(_run_reachability, record)
    return ReachabilityStatus(scan_id=scan_id, status="running")


@app.get("/scan/{scan_id}/reachability")
def reachability_status(scan_id: str) -> ReachabilityStatus:
    record = _record(scan_id)
    path = record.work_dir / "out" / "reachability.json"
    if not path.is_file():
        return ReachabilityStatus(status="not_run", reason="Reachability has not been requested.")
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("status") == "running" and scan_id not in _reachability_jobs:
        state.update({"status": "error", "reason": "The check was interrupted; start it again."})
        _write_reachability_status(path, state)
    return ReachabilityStatus.model_validate(state)


@app.get("/scan/{scan_id}/changes")
def scan_changes(scan_id: str) -> ChangeSummary:
    record = _finished(scan_id)
    path = record.work_dir / "out" / pipeline.CHANGES_FILE
    if not path.is_file():
        reason = record.errors.get("baseline") or "no baseline_ref was requested for this scan"
        raise HTTPException(404, f"No change summary: {reason}")
    return ChangeSummary.model_validate_json(path.read_text("utf-8"))


@app.get("/scan/{scan_id}/graph")
def scan_graph(scan_id: str) -> GraphArtifact:
    return GraphArtifact.model_validate_json(_artifact(scan_id, "graph.json").read_text("utf-8"))


@app.get("/scan/{scan_id}/sbom")
def scan_sbom(scan_id: str) -> FileResponse:
    return FileResponse(
        _artifact(scan_id, "sbom.cdx.json"),
        media_type="application/json",
        filename="sbom.cdx.json",
    )


@app.get("/scan/{scan_id}/report")
def scan_report(scan_id: str) -> FileResponse:
    return FileResponse(_artifact(scan_id, "report.html"), media_type="text/html")


@app.get("/scan/{scan_id}/report.json")
def scan_report_json(scan_id: str) -> FileResponse:
    return FileResponse(_artifact(scan_id, "report.json"), media_type="application/json")


app.include_router(review.build_router(_finished))
