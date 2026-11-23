import json
from pathlib import Path
from typing import Any

import pytest
from app import main, pipeline
from fastapi.testclient import TestClient

from guardian.models import RunResult, Scan, ScanStatus


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("GUARDIAN_SCAN_DIR", str(tmp_path))
    pipeline.SCANS.clear()
    return TestClient(main.app)


def _fake_fetch(url: str, ref: str, dest: Path, token: str | None) -> Any:
    from guardian.fetch import FetchedFile, FetchResult, write_manifest

    dest.mkdir(parents=True)
    (dest / "package-lock.json").write_text("{}")
    result = FetchResult(
        url=url, ref="main", commit_sha="b" * 40, dest=dest,
        files=[FetchedFile(path="package-lock.json", size=2, sha256="x")],
    )
    write_manifest(result)
    return result


def _fake_scan(target: Path, out: Path, **_: object) -> RunResult:
    from datetime import UTC, datetime

    out.mkdir(parents=True)
    scan = Scan(scan_id="s", target=str(target), started_at=datetime.now(UTC),
                status=ScanStatus.PARTIAL, errors={"osv": "boom"})
    (out / "run.json").write_text(scan.model_dump_json())
    (out / "coverage.json").write_text("{}")
    (out / "findings.json").write_text(json.dumps({"findings": [], "evidence": []}))
    (out / "graph.json").write_text("{}")
    (out / "sbom.cdx.json").write_text('{"bomFormat": "CycloneDX"}')
    (out / "report.html").write_text("<html>ok</html>")
    return RunResult(scan=scan)


def test_scan_flow_reports_guardian_status(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pipeline, "fetch_repo_files", _fake_fetch)
    monkeypatch.setattr(pipeline.runner, "scan", _fake_scan)
    started = client.post("/scan", json={"url": "https://github.com/o/r", "ref": "main"})
    assert started.status_code == 202
    scan_id = started.json()["scan_id"]
    status = client.get(f"/scan/{scan_id}").json()
    assert status["status"] == "partial"
    assert status["errors"] == {"osv": "boom"}
    assert status["commit_sha"] == "b" * 40
    result = client.get(f"/scan/{scan_id}/result").json()
    assert result["fetch"]["files"][0]["source"] == "repo"
    assert client.get(f"/scan/{scan_id}/sbom").json()["bomFormat"] == "CycloneDX"
    assert "ok" in client.get(f"/scan/{scan_id}/report").text
    assert client.get(f"/scan/{scan_id}/graph").status_code == 200


def test_fetch_failure_is_reported_as_failed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guardian.fetch import FetchError

    def boom(*_: object) -> None:
        raise FetchError("GitHub API rate limit reached; set GITHUB_TOKEN")

    monkeypatch.setattr(pipeline, "fetch_repo_files", boom)
    scan_id = client.post("/scan", json={"url": "https://github.com/o/r"}).json()["scan_id"]
    status = client.get(f"/scan/{scan_id}").json()
    assert status["status"] == "failed"
    assert "rate limit" in status["error"]
    assert client.get(f"/scan/{scan_id}/result").status_code == 409


def test_invalid_url_is_422(client: TestClient) -> None:
    response = client.post("/scan", json={"url": "https://evil.com/o/r"})
    assert response.status_code == 422


def test_unknown_scan_is_404(client: TestClient) -> None:
    assert client.get("/scan/nope").status_code == 404


def test_ai_is_enabled_only_with_provider_and_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "groq")
    monkeypatch.delenv("GUARDIAN_LLM_API_KEY", raising=False)
    assert not pipeline.ai_enabled()
    monkeypatch.setenv("GUARDIAN_LLM_API_KEY", "gsk_test")
    assert pipeline.ai_enabled()
    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "none")
    assert not pipeline.ai_enabled()


def test_fake_claim_injection_and_claims_in_result(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guardian.models import AgentClaim, ClaimKind

    seen: dict[str, object] = {}

    def scan(target: Path, out: Path, **kwargs: object) -> RunResult:
        seen.update(kwargs)
        result = _fake_scan(target, out)
        claim = AgentClaim(claim_id="c1", step="injected", text="fake", kind=ClaimKind.EVIDENCE,
                           rejected_reason="advisory CVE-2026-31337 is not in the cited findings")
        (out / "findings.json").write_text(json.dumps(
            {"findings": [], "evidence": [], "claims": [claim.model_dump(mode="json")]}))
        return result

    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "none")
    monkeypatch.setattr(pipeline, "fetch_repo_files", _fake_fetch)
    monkeypatch.setattr(pipeline.runner, "scan", scan)
    scan_id = client.post("/scan", json={"url": "https://github.com/o/r",
                                         "inject_fake_claim": True}).json()["scan_id"]
    assert seen["use_llm"] is False
    assert seen["inject_claim"] == pipeline.FAKE_CLAIM and pipeline.FAKE_CLAIM.is_file()
    claims = client.get(f"/scan/{scan_id}/result").json()["claims"]
    assert claims[0]["rejected_reason"].startswith("advisory CVE-2026-31337")


def test_root_env_file_is_loaded_without_overriding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = tmp_path / ".env"
    env.write_text("GUARDIAN_TEST_A=from_file\nGUARDIAN_TEST_B=from_file\n")
    monkeypatch.setenv("GUARDIAN_TEST_B", "from_env")
    monkeypatch.delenv("GUARDIAN_TEST_A", raising=False)
    pipeline.load_root_env(env)
    import os
    assert os.environ["GUARDIAN_TEST_A"] == "from_file"
    assert os.environ["GUARDIAN_TEST_B"] == "from_env"
    monkeypatch.delenv("GUARDIAN_TEST_A")


def test_demo_scan_copies_the_local_demo_app_with_source(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Path] = {}

    def scan(target: Path, out: Path, **kwargs: object) -> RunResult:
        seen["target"] = target
        return _fake_scan(target, out)

    def no_fetch(*_: object) -> None:
        raise AssertionError("the demo must not fetch from GitHub")

    monkeypatch.setattr(pipeline, "fetch_repo_files", no_fetch)
    monkeypatch.setattr(pipeline.runner, "scan", scan)
    scan_id = client.post("/scan", json={"demo": True}).json()["scan_id"]
    status = client.get(f"/scan/{scan_id}").json()
    assert status["demo"] is True and status["commit_sha"] == "local-demo"
    assert (seen["target"] / "src" / "server.js").is_file()
    assert (seen["target"] / "vendor" / "expresss-session" / "package.json").is_file()
    files = {f["path"] for f in client.get(f"/scan/{scan_id}/result").json()["fetch"]["files"]}
    assert {"package.json", "package-lock.json"} <= files


def test_url_is_required_unless_demo(client: TestClient) -> None:
    assert client.post("/scan", json={"url": ""}).status_code == 422
