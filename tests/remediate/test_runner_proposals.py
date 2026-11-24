import json
from pathlib import Path

import pytest

from guardian import runner
from guardian.ai.graph import AIReviewResult
from guardian.models import (
    Component,
    Finding,
    FixAction,
    GraphArtifact,
    LlmStatus,
    RemediationProposal,
    RunResult,
    Scope,
)


def _inventory(context: runner.ScanContext) -> None:
    context.sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
    context.result.graph = GraphArtifact(nodes=[
        Component(component_id="lib", purl="pkg:npm/lib@1.0.0", name="lib", version="1.0.0",
                  ecosystem="npm", scope=Scope.DIRECT),
    ])


def _detect(context: runner.ScanContext) -> None:
    context.result.findings = [Finding(
        finding_id="f1", kind="vulnerability", component_id="lib", purl="pkg:npm/lib@1.0.0",
        advisory_id="CVE-2000-1234", source_severity="high", fixed_versions=["1.0.5"],
    )]


def _scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, use_llm: bool) -> RunResult:
    (tmp_path / "target").mkdir()
    monkeypatch.setattr(runner, "_inventory", _inventory)
    monkeypatch.setattr(runner, "_scanners", lambda context: None)
    monkeypatch.setattr(runner, "_detectors", _detect)
    monkeypatch.setattr(runner, "_render", lambda directory: None)
    return runner.scan(tmp_path / "target", tmp_path / "scan", use_llm=use_llm)


def _persisted(tmp_path: Path) -> list[dict[str, object]]:
    data = json.loads((tmp_path / "scan" / "findings.json").read_text(encoding="utf-8"))
    return data["proposals"]


def test_rule_based_proposals_are_persisted_when_ai_is_off(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _scan(monkeypatch, tmp_path, use_llm=False)
    assert [p.target_version for p in result.proposals] == ["1.0.5"]
    assert [p["proposal_id"] for p in _persisted(tmp_path)] == ["rule-f1"]


def test_ai_proposals_are_persisted_and_beat_the_rule_based_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ai = RemediationProposal(
        proposal_id="ai-1", finding_id="f1", action=FixAction.UPGRADE, target_version="1.0.5",
        rationale="AI.", rollback="Revert.", breaking_change_risk="low", evidence_ids=[],
        validated=True,
    )
    review = AIReviewResult(claims=[], proposals=[ai], llm_status=LlmStatus.OK)
    monkeypatch.setattr(runner, "run_review", lambda result, settings, injected: review)
    result = _scan(monkeypatch, tmp_path, use_llm=True)
    assert [p.proposal_id for p in result.proposals] == ["ai-1"]
    assert [p["proposal_id"] for p in _persisted(tmp_path)] == ["ai-1"]
