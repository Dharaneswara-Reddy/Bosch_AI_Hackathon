from datetime import UTC, datetime
from pathlib import Path

import pytest
from app import main, pipeline
from app.schemas import ScanRecord
from fastapi.testclient import TestClient

from guardian.fetch import FetchedFile, FetchResult, write_manifest
from guardian.models import (
    Component,
    Finding,
    FindingKind,
    FindingsArtifact,
    GraphArtifact,
    RiskLevel,
    Scan,
    ScanStatus,
)


def _finding(finding_id: str, review: bool, level: RiskLevel = RiskLevel.HIGH) -> Finding:
    return Finding(
        finding_id=finding_id, kind=FindingKind.VULNERABILITY, component_id="lib",
        purl="pkg:npm/lib@1.0.0", advisory_id=f"CVE-{finding_id}", risk_level=level,
        review_required=review, review_reasons=["low confidence"] if review else [],
        confidence_score=0.4,
    )


def _make_scan(work: Path, status: str = "complete") -> ScanRecord:
    out = work / "out"
    out.mkdir(parents=True)
    scan = Scan(scan_id="s", target="t", started_at=datetime.now(UTC), status=ScanStatus.COMPLETE)
    (out / "run.json").write_text(scan.model_dump_json())
    (out / "coverage.json").write_text("{}")
    findings = [_finding("a", True), _finding("b", True), _finding("c", False)]
    (out / "findings.json").write_text(FindingsArtifact(findings=findings).model_dump_json())
    node = Component(component_id="lib", purl="pkg:npm/lib@1.0.0", name="lib", version="1.0.0")
    (out / "graph.json").write_text(GraphArtifact(nodes=[node]).model_dump_json())
    write_manifest(FetchResult(
        url="u", ref="main", commit_sha="c" * 40, dest=work / "repo",
        files=[FetchedFile(path="package-lock.json", size=2, sha256="x")],
    ))
    record = ScanRecord(
        scan_id="scan1", status=status, repository_url="u",  # type: ignore[arg-type]
        created_at=datetime.now(UTC), work_dir=work,
    )
    pipeline.SCANS[record.scan_id] = record
    return record


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    pipeline.SCANS.clear()
    _make_scan(tmp_path)
    return TestClient(main.app)


def test_queue_lists_only_review_required_findings_with_counts(client: TestClient) -> None:
    body = client.get("/scan/scan1/review").json()
    assert [item["finding_id"] for item in body["items"]] == ["a", "b"]
    assert body["items"][0]["package"] == "lib@1.0.0"
    assert body["items"][0]["review_reasons"] == ["low confidence"]
    assert body["items"][0]["decision"] is None
    assert body["counts"] == {"pending": 2, "confirmed": 0, "dismissed": 0, "escalated": 0}


def test_decision_is_stored_and_reflected_in_queue_and_result(client: TestClient) -> None:
    response = client.post(
        "/scan/scan1/review/a", json={"decision": "escalated", "note": "exposed", "reviewer": "ana"}
    )
    assert response.status_code == 200
    assert response.json()["decision"]["reviewer"] == "ana"
    assert client.get("/scan/scan1/review").json()["counts"]["escalated"] == 1
    result = client.get("/scan/scan1/result").json()
    by_id = {f["finding_id"]: f for f in result["findings"]}
    assert by_id["a"]["risk_level"] == "critical"
    assert by_id["a"]["human_decision"] == "escalated"
    assert result["review_summary"] == {
        "pending": 1, "confirmed": 0, "dismissed": 0, "escalated": 1,
    }


def test_decision_rerenders_the_report_with_a_review_section(
    client: TestClient, tmp_path: Path
) -> None:
    client.post("/scan/scan1/review/b", json={"decision": "dismissed", "note": "test-only code"})
    html = client.get("/scan/scan1/report").text
    assert "Human review decisions" in html
    assert "test-only code" in html


def test_dismissal_without_note_is_a_validation_error(client: TestClient) -> None:
    response = client.post("/scan/scan1/review/a", json={"decision": "dismissed", "note": ""})
    assert response.status_code == 422


def test_unknown_scan_and_unknown_or_unqueued_finding_are_404(client: TestClient) -> None:
    assert client.get("/scan/nope/review").status_code == 404
    assert client.post("/scan/scan1/review/zzz", json={"decision": "confirmed"}).status_code == 404
    assert client.post("/scan/scan1/review/c", json={"decision": "confirmed"}).status_code == 404


def test_running_scan_is_a_409(client: TestClient) -> None:
    pipeline.SCANS["scan1"].status = "running"
    assert client.get("/scan/scan1/review").status_code == 409
    assert client.post("/scan/scan1/review/a", json={"decision": "confirmed"}).status_code == 409
