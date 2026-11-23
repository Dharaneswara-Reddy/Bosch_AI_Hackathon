import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app import main, pipeline
from app.schemas import ScanRecord
from fastapi.testclient import TestClient


def _record(base: Path, scan_id: str, status: str = "complete") -> ScanRecord:
    return ScanRecord(
        scan_id=scan_id, status=status, stage="scanning",  # type: ignore[arg-type]
        repository_url="https://github.com/o/r", ref="main",
        created_at=datetime.now(UTC), work_dir=base / scan_id)


def _stored(base: Path, scan_id: str) -> ScanRecord:
    data = json.loads((base / scan_id / "record.json").read_bytes())
    return ScanRecord.model_validate({**data, "work_dir": base / scan_id})


def test_every_stage_change_is_written_to_record_json(tmp_path: Path) -> None:
    record = _record(tmp_path, "a", "running")
    pipeline.set_stage(record, "fetching")
    stored = _stored(tmp_path, "a")
    assert (stored.stage, stored.status) == ("fetching", "running")


def test_failure_is_persisted(tmp_path: Path) -> None:
    record = _record(tmp_path, "a", "running")
    pipeline.fail(record, "boom")
    stored = _stored(tmp_path, "a")
    assert (stored.status, stored.error, stored.stage) == ("failed", "boom", "done")


def test_startup_reloads_scans_and_fails_interrupted_ones(tmp_path: Path) -> None:
    pipeline.persist(_record(tmp_path, "done"))
    pipeline.persist(_record(tmp_path, "busy", "running"))
    (tmp_path / "junk").mkdir()
    (tmp_path / "junk" / "record.json").write_text("{not json")
    pipeline.SCANS.clear()

    pipeline.load_records(tmp_path)

    assert set(pipeline.SCANS) == {"done", "busy"}
    assert pipeline.SCANS["done"].status == "complete"
    assert pipeline.SCANS["done"].work_dir == tmp_path / "done"
    busy = pipeline.SCANS["busy"]
    assert (busy.status, busy.error) == ("failed", "interrupted by server restart")
    again = _stored(tmp_path, "busy")
    assert again.status == "failed"


def test_app_startup_restores_scans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_SCAN_DIR", str(tmp_path))
    pipeline.persist(_record(tmp_path, "kept"))
    pipeline.SCANS.clear()
    with TestClient(main.app) as client:
        assert client.get("/scan/kept").json()["status"] == "complete"
