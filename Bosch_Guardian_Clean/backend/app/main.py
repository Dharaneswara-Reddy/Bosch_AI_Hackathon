"""Guardian API: fetch selected files from a public GitHub repo and run the team scan pipeline."""

import os
import tempfile
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from guardian.ai.llm import FALLBACK_PROVIDERS
from guardian.changes import ChangeSummary
from guardian.fetch import FetchError
from guardian.models import GraphArtifact

from . import pipeline, remediation, review
from .schemas import ScanRecord, ScanRequest, ScanResult, ScanStarted

pipeline.load_root_env()
app = FastAPI(title="Bosch Guardian API", version="0.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.include_router(remediation.router)
_default_base: Path | None = None


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
        raise HTTPException(404, "Scan not found; scans are kept in memory and reset on restart")
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
                request.url, request.ref, scan_base(), request.baseline_ref.strip())
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


app.include_router(review.build_router(_finished))
