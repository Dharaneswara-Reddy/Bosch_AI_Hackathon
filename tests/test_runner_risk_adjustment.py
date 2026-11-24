import json
from pathlib import Path
from typing import Any

import pytest

from guardian import runner
from guardian.models import Component, Finding, GraphArtifact, RunResult
from tests.ai.fake_llms import RoutingLLM

REASON = "The advisory text says the flaw needs the legacy parser to be enabled."


def _inventory(context: runner.ScanContext) -> None:
    context.sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
    context.result.graph = GraphArtifact(nodes=[
        Component(component_id="lib", purl="pkg:npm/lib@1", name="lib", ecosystem="npm", dev=True),
    ])


def _scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, to_level: str, direction: str
) -> RunResult:
    proposal: dict[str, Any] = {
        "finding_id": "f1", "from_level": "medium", "to_level": to_level,
        "direction": direction, "reason": REASON, "evidence_ids": [],
    }
    critic = {"reviews": [], "adjustment_reviews": [
        {"finding_id": "f1", "verdict": "supported", "reason": "Judged against the pack."},
    ]}
    llm = RoutingLLM(risk_analyst=[{"adjustments": [proposal]}], risk_critic=[critic])

    def detect(context: runner.ScanContext) -> None:
        raw = context.out / "raw"
        raw.mkdir(exist_ok=True)
        (raw / "g.json").write_text("{}", encoding="utf-8")
        evidence_id = context.evidence.add("grype", "raw/g.json", "/matches/0")
        context.result.findings = [Finding(
            finding_id="f1", kind="vulnerability", component_id="lib", purl="pkg:npm/lib@1",
            advisory_id="CVE-2000-1234", source_severity="high", evidence_ids=[evidence_id],
        )]
        proposal["evidence_ids"] = [evidence_id]

    (tmp_path / "target").mkdir()
    monkeypatch.setattr(runner, "_inventory", _inventory)
    monkeypatch.setattr(runner, "_scanners", lambda context: None)
    monkeypatch.setattr(runner, "_detectors", detect)
    monkeypatch.setattr(runner, "_render", lambda directory: None)
    monkeypatch.setattr("guardian.ai.review.review_client", lambda settings, env: llm)
    return runner.scan(tmp_path / "target", tmp_path / "scan", use_llm=True)


def test_valid_adjustment_reaches_findings_json_with_engine_level_and_agreement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _scan(monkeypatch, tmp_path, "high", "raise")
    stored = json.loads((tmp_path / "scan" / "findings.json").read_text(encoding="utf-8"))
    [finding] = stored["findings"]
    assert finding["risk_level"] == "high"
    assert finding["engine_risk_level"] == "medium"
    assert finding["ai_adjusted"] is True
    assert f"AI risk analyst: {REASON}" in finding["risk_reasons"]
    assert stored["agreement"] == {"f1": True}
    assert [a["status"] for a in stored["risk_adjustments"]] == ["accepted"]
    assert result.findings[0].confidence_score == 0.15


def test_two_level_adjustment_is_recorded_rejected_and_the_finding_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _scan(monkeypatch, tmp_path, "critical", "raise")
    stored = json.loads((tmp_path / "scan" / "findings.json").read_text(encoding="utf-8"))
    [finding] = stored["findings"]
    assert finding["risk_level"] == "medium" and finding["ai_adjusted"] is False
    assert finding["engine_risk_level"] is None
    [adjustment] = stored["risk_adjustments"]
    assert adjustment["status"] == "rejected" and "one level" in adjustment["rejected_reason"]
