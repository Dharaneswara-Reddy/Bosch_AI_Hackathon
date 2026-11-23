import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app import main, pipeline, remediation
from app.schemas import ScanRecord
from fastapi.testclient import TestClient

from guardian.models import (
    Component,
    Finding,
    FindingKind,
    FixAction,
    GraphArtifact,
    RemediationProposal,
    RiskLevel,
    RunResult,
    Scan,
    Scope,
)
from guardian.remediate.sandbox import CommandResult
from guardian.remediate.workflow import FixDeps

SCAN_ID = "abc"


def _run(version: str, with_finding: bool) -> RunResult:
    purl = f"pkg:npm/lodash@{version}"
    node = Component(component_id=purl, purl=purl, name="lodash", version=version,
                     ecosystem="npm", scope=Scope.DIRECT)
    findings = [Finding(
        finding_id="f1", kind=FindingKind.VULNERABILITY, component_id=purl, purl=purl,
        advisory_id="CVE-2021-23337", risk_level=RiskLevel.HIGH, fixed_versions=["4.17.21"],
    )] if with_finding else []
    proposals = [RemediationProposal(
        proposal_id="rule-f1", finding_id="f1", action=FixAction.UPGRADE,
        target_version="4.17.21", rationale="r", rollback="b", breaking_change_risk="low",
        evidence_ids=[], validated=True,
    ), RemediationProposal(
        proposal_id="ai-2", finding_id="f1", action=FixAction.REMOVE_DEPENDENCY,
        target_version=None, rationale="r", rollback="b", breaking_change_risk="high",
        evidence_ids=[], validated=True,
    )] if with_finding else []
    return RunResult(scan=Scan(scan_id="s", target="t", started_at=datetime.now(UTC)),
                     graph=GraphArtifact(nodes=[node]), findings=findings, proposals=proposals)


def _write_out(out: Path, run: RunResult) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "run.json").write_text(run.scan.model_dump_json(), encoding="utf-8")
    (out / "coverage.json").write_text(run.coverage.model_dump_json(), encoding="utf-8")
    (out / "graph.json").write_text(run.graph.model_dump_json(), encoding="utf-8")
    (out / "findings.json").write_text(
        json.dumps({"findings": [f.model_dump(mode="json") for f in run.findings],
                    "proposals": [p.model_dump(mode="json") for p in run.proposals]}),
        encoding="utf-8")


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    pipeline.SCANS.clear()
    work = tmp_path / SCAN_ID
    (work / "repo").mkdir(parents=True)
    (work / "repo" / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.4"}}), encoding="utf-8")
    _write_out(work / "out", _run("4.17.4", True))
    pipeline.SCANS[SCAN_ID] = ScanRecord(
        scan_id=SCAN_ID, status="complete", repository_url="x", created_at=datetime.now(UTC),
        work_dir=work)

    def command(cmd: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
        (cwd / "package-lock.json").write_text("{}", encoding="utf-8")
        return CommandResult(0, "")

    def scan(target: Path, out: Path) -> RunResult:
        result = _run("4.17.21", False)
        _write_out(out, result)
        return result

    monkeypatch.setattr(remediation, "fix_deps", lambda: FixDeps(command, scan, None))
    monkeypatch.setattr(remediation, "CHECKPOINTER", remediation.MemorySaver())
    return TestClient(main.app)


def _fixes(client: TestClient) -> dict[str, dict[str, object]]:
    listed = client.get(f"/scan/{SCAN_ID}/fixes")
    assert listed.status_code == 200
    return {entry["proposal"]["proposal_id"]: entry for entry in listed.json()}


def test_lists_proposals_with_source_target_and_applicability(client: TestClient) -> None:
    fixes = _fixes(client)
    rule = fixes["rule-f1"]
    assert (rule["source"], rule["status"]) == ("rule", "proposed")
    assert rule["target"] == {"ecosystem": "npm", "package": "lodash",
                              "from_version": "4.17.4", "to_version": "4.17.21",
                              "transitive": False, "parent": None, "parent_version": None}
    assert rule["expected_reduction"] == {
        "fixes": {"high": 1}, "finding_ids": ["f1"], "advisories": ["CVE-2021-23337"],
        "remaining_on_package": 0}
    assert rule["unavailable_reason"] is None
    ai = fixes["ai-2"]
    assert ai["source"] == "ai" and "manually" in str(ai["unavailable_reason"])
    assert ai["expected_reduction"] is None


def test_start_pauses_for_approval_then_approval_runs_in_the_background(
    client: TestClient,
) -> None:
    base = f"/scan/{SCAN_ID}/fixes/rule-f1"
    assert client.post(f"{base}/start").json()["status"] == "awaiting_approval"
    assert _fixes(client)["rule-f1"]["status"] == "awaiting_approval"
    decided = client.post(f"{base}/decision", json={"approved": True, "reviewer": "ana"})
    assert decided.status_code == 200
    entry = _fixes(client)["rule-f1"]
    assert entry["status"] == "verified"
    result = entry["result"]
    assert isinstance(result, dict)
    assert result["diff"]["fixed"][0]["advisory_id"] == "CVE-2021-23337"
    assert "Fixed 1 High" in result["summary"]


def test_rejection_is_recorded(client: TestClient) -> None:
    base = f"/scan/{SCAN_ID}/fixes/rule-f1"
    client.post(f"{base}/start")
    response = client.post(f"{base}/decision",
                           json={"approved": False, "reviewer": "ana", "note": "later"})
    assert response.json()["status"] == "rejected"
    assert _fixes(client)["rule-f1"]["status"] == "rejected"


def test_error_responses_are_actionable(client: TestClient) -> None:
    base = f"/scan/{SCAN_ID}/fixes"
    assert client.get("/scan/nope/fixes").status_code == 404
    assert client.post(f"{base}/missing/start").status_code == 404
    unplannable = client.post(f"{base}/ai-2/start")
    assert unplannable.status_code == 422 and "manually" in unplannable.json()["detail"]
    early = client.post(f"{base}/rule-f1/decision", json={"approved": True, "reviewer": "ana"})
    assert early.status_code == 409 and "start" in early.json()["detail"]
    invalid = client.post(f"{base}/rule-f1/decision", json={"approved": True, "reviewer": ""})
    assert invalid.status_code == 422
