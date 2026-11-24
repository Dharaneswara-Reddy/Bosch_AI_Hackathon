import json
from datetime import UTC, datetime
from pathlib import Path

from guardian.decisions import DecisionLog, HumanDecision
from guardian.models import (
    AgentTrace,
    Component,
    Evidence,
    Finding,
    FindingKind,
    FindingsArtifact,
    FixAction,
    GraphArtifact,
    RemediationProposal,
    RiskLevel,
    Scan,
    Scope,
)
from guardian.remediate.diff import FindingRef, RescanDiff
from guardian.remediate.run import Decision, FixRun, FixStatus, save_fix
from guardian.remediate.sandbox import FixTarget, StepResult, TestRun
from guardian.report.final import GuardianReport
from guardian.report.render import render

T0 = datetime(2026, 11, 24, 9, 0, tzinfo=UTC)
T1 = datetime(2026, 11, 24, 9, 5, tzinfo=UTC)
T2 = datetime(2026, 11, 24, 9, 10, tzinfo=UTC)
T3 = datetime(2026, 11, 24, 9, 20, tzinfo=UTC)
T_DONE = datetime(2026, 11, 24, 9, 15, tzinfo=UTC)


def _finding(finding_id: str, advisory: str, level: RiskLevel) -> Finding:
    return Finding(
        finding_id=finding_id, kind=FindingKind.VULNERABILITY, component_id="lodash",
        purl="pkg:npm/lodash@4.17.4", advisory_id=advisory, risk_level=level,
        dependency_path=["app", "lodash"], evidence_ids=["e1"], risk_score=80,
        confidence_score=0.9, fixed_versions=["4.17.21"])


def _proposal(proposal_id: str, finding_id: str) -> RemediationProposal:
    return RemediationProposal(
        proposal_id=proposal_id, finding_id=finding_id, action=FixAction.UPGRADE,
        target_version="4.17.21", rationale="patched upstream", rollback="revert lockfile",
        breaking_change_risk="low", evidence_ids=["e1"], validated=True)


def _scan_out(tmp_path: Path) -> Path:
    out = tmp_path / "scan" / "out"
    out.mkdir(parents=True)
    scan = Scan(scan_id="s1", target="demo", started_at=T0, ended_at=T1)
    node = Component(component_id="lodash", purl="pkg:npm/lodash@4.17.4", name="lodash",
                     version="4.17.4", ecosystem="npm", scope=Scope.DIRECT)
    evidence = Evidence(evidence_id="e1", tool="osv", tool_version="1", file="raw/osv.json",
                        sha256="a" * 64)
    findings = FindingsArtifact(
        findings=[_finding("f1", "CVE-1", RiskLevel.HIGH),
                  _finding("f2", "CVE-2", RiskLevel.MEDIUM),
                  _finding("f3", "CVE-3", RiskLevel.LOW)],
        evidence=[evidence],
        proposals=[_proposal("rule-f1", "f1"), _proposal("rule-f2", "f2")],
        agent_trace=[AgentTrace(agent="triage", consumed=["f1"], produced=["pack-f1"],
                                accepted=1, llm_calls=1)])
    (out / "run.json").write_text(scan.model_dump_json(), encoding="utf-8")
    (out / "graph.json").write_text(GraphArtifact(nodes=[node]).model_dump_json(),
                                    encoding="utf-8")
    (out / "coverage.json").write_text("{}", encoding="utf-8")
    (out / "findings.json").write_text(findings.model_dump_json(), encoding="utf-8")
    return out


def _fix(scan_id: str = "s1", introduced: bool = False) -> FixRun:
    ref = FindingRef(finding_id="f1", advisory_id="CVE-1", package="lodash",
                     version="4.17.4", risk_level=RiskLevel.HIGH)
    new = FindingRef(finding_id="n1", advisory_id="CVE-9", package="left-pad",
                     version="1.0.0", risk_level=RiskLevel.LOW)
    return FixRun(
        scan_id=scan_id, proposal=_proposal("rule-f1", "f1"), status=FixStatus.VERIFIED,
        decision=Decision(approved=True, reviewer="ana", note="ship it", decided_at=T2),
        target=FixTarget(ecosystem="npm", package="lodash", from_version="4.17.4",
                         to_version="4.17.21"),
        build=StepResult(status="passed", detail="lockfile resolved"),
        tests=TestRun(status="not_run", reason="no source to test"),
        diff=RescanDiff(
            counts_before={"critical": 0, "high": 1, "medium": 1, "low": 1},
            counts_after={"critical": 0, "high": 0, "medium": 1, "low": 2 if introduced else 1},
            fixed=[ref], introduced=[new] if introduced else []),
        summary="Fixed 1 High (CVE-1). No new findings.", completed_at=T_DONE)


def _report(out: Path) -> GuardianReport:
    return GuardianReport.model_validate_json((out / "report.json").read_bytes())


def test_report_json_lists_inventory_ranked_findings_and_recommended_actions(
    tmp_path: Path,
) -> None:
    out = _scan_out(tmp_path)
    render(out)
    report = _report(out)
    assert report.scan_id == "s1" and report.inventory.components == 1
    assert [f.advisory_id for f in report.findings] == ["CVE-1", "CVE-2", "CVE-3"]
    top = report.findings[0]
    assert (top.risk_level, top.risk_score, top.confidence_score) == ("high", 80, 0.9)
    assert top.dependency_path == ["app", "lodash"] and top.evidence_ids == ["e1"]
    assert [(a.proposal_id, a.source, a.status) for a in report.recommended_actions] == [
        ("rule-f1", "rule", "proposed"), ("rule-f2", "rule", "proposed")]
    assert report.validations == []
    assert [r.finding_id for r in report.remaining_risks] == ["f1", "f2", "f3"]


def test_html_and_markdown_have_the_remediation_section_with_rule_proposals(
    tmp_path: Path,
) -> None:
    out = _scan_out(tmp_path)
    render(out)
    for name in ("report.html", "report.md"):
        text = (out / name).read_text(encoding="utf-8")
        assert "Remediation &amp; validation" in text or "Remediation & validation" in text
        assert "rule-f2" in text


def test_a_verified_fix_tells_the_whole_story(tmp_path: Path) -> None:
    out = _scan_out(tmp_path)
    save_fix(out.parent, _fix(introduced=True))
    render(out)
    [validation] = _report(out).validations
    assert validation.finding_id == "f1" and validation.advisory_id == "CVE-1"
    assert (validation.approved, validation.reviewer, validation.note) == (True, "ana", "ship it")
    assert validation.decided_at == T2
    assert (validation.build_status, validation.tests_status) == ("passed", "not_run")
    assert validation.counts_before["high"] == 1 and validation.counts_after["high"] == 0
    assert [f.advisory_id for f in validation.fixed] == ["CVE-1"]
    assert [f.advisory_id for f in validation.introduced] == ["CVE-9"]
    assert validation.verdict == "fixed_with_new_findings"
    assert validation.confidence == "low"
    html = (out / "report.html").read_text(encoding="utf-8")
    for expected in ("ana", "ship it", "lockfile resolved", "no source to test", "CVE-9",
                     "Fixed 1 High"):
        assert expected in html
    markdown = (out / "report.md").read_text(encoding="utf-8")
    assert "ana" in markdown and "CVE-9" in markdown


def test_verified_fixes_remove_findings_from_remaining_risk_and_new_ones_join(
    tmp_path: Path,
) -> None:
    out = _scan_out(tmp_path)
    save_fix(out.parent, _fix(introduced=True))
    render(out)
    remaining = {r.finding_id: r.origin for r in _report(out).remaining_risks}
    assert remaining == {"f2": "open", "f3": "open", "n1": "introduced by fix rule-f1"}


def test_dismissed_findings_are_accepted_risks_with_reviewer_and_note(tmp_path: Path) -> None:
    out = _scan_out(tmp_path)
    DecisionLog(out).record(HumanDecision(
        finding_id="f3", decision="dismissed", note="dev only", reviewer="bo", decided_at=T3))
    DecisionLog(out).record(HumanDecision(
        finding_id="f2", decision="escalated", reviewer="bo", decided_at=T3))
    render(out)
    report = _report(out)
    [accepted] = report.accepted_risks
    assert (accepted.finding_id, accepted.reviewer, accepted.note) == ("f3", "bo", "dev only")
    assert [e.finding_id for e in report.escalated] == ["f2"]
    assert "f3" not in {r.finding_id for r in report.remaining_risks}


def test_audit_trail_is_chronological_and_merges_every_source(tmp_path: Path) -> None:
    out = _scan_out(tmp_path)
    DecisionLog(out).record(HumanDecision(
        finding_id="f3", decision="dismissed", note="dev only", reviewer="bo", decided_at=T3))
    save_fix(out.parent, _fix())
    render(out)
    trail = _report(out).audit_trail
    assert [e.kind for e in trail] == [
        "scan_started", "ai_review", "scan_completed", "fix_approved", "fix_result",
        "human_decision"]
    times = [e.at for e in trail]
    assert times == sorted(times)
    assert "ana" in trail[3].summary and "bo" in trail[5].summary


def test_report_json_is_valid_json_without_fix_runs(tmp_path: Path) -> None:
    out = _scan_out(tmp_path)
    render(out)
    assert json.loads((out / "report.json").read_text(encoding="utf-8"))["scan_id"] == "s1"


def test_a_clean_verified_fix_without_tests_has_medium_confidence(tmp_path: Path) -> None:
    out = _scan_out(tmp_path)
    save_fix(out.parent, _fix())
    render(out)
    [validation] = _report(out).validations
    assert (validation.verdict, validation.confidence) == ("fixed", "medium")


def test_a_dismissed_suspicious_package_is_an_accepted_risk(tmp_path: Path) -> None:
    out = _scan_out(tmp_path)
    artifact = FindingsArtifact.model_validate_json((out / "findings.json").read_bytes())
    anomaly = _finding("a1", "CVE-A", RiskLevel.LOW).model_copy(
        update={"kind": FindingKind.ANOMALY, "advisory_id": None, "anomaly_type": "typosquat"})
    artifact.findings.append(anomaly)
    (out / "findings.json").write_text(artifact.model_dump_json(), encoding="utf-8")
    DecisionLog(out).record(HumanDecision(
        finding_id="a1", decision="dismissed", note="internal fork", reviewer="bo"))
    render(out)
    assert [a.finding_id for a in _report(out).accepted_risks] == ["a1"]
