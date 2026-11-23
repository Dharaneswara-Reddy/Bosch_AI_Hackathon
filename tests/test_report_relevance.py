from __future__ import annotations

from html import escape
from pathlib import Path

from guardian.analysis import apply_relevance, apply_scope
from guardian.models import (
    AgentClaim,
    AgentTrace,
    ClaimKind,
    CoverageArtifact,
    Finding,
    FindingKind,
    FindingsArtifact,
    RiskAdjustment,
    RiskLevel,
    SsvcDecision,
)
from guardian.report.render import render
from tests.test_relevance import APP, _demo_run

SECTIONS = [
    "SBOM and inventory",
    "How each vulnerability enters the application",
    "Vulnerabilities ranked by relevance",
    "Suspicious and malicious packages",
    "AI analysis",
    "Remediation & validation",
    "Agent trace",
    "Coverage",
    "Remaining unknowns and limitations",
]


def _write_run(tmp_path: Path) -> Path:
    result, target, store = _demo_run(tmp_path)
    apply_scope(result, target, [APP])
    apply_relevance(result, target, store.root, store)
    synthetic = Finding(
        finding_id="f-synth",
        kind=FindingKind.ANOMALY,
        component_id="pkg:npm/expresss-session@1.0.0",
        purl="pkg:npm/expresss-session@1.0.0",
        anomaly_type="unverified_install_script",
        risk_note="SYNTHETIC test package for the Guardian demo.",
    )
    fix = AgentClaim(
        claim_id="fix-1",
        step="remediation_planner",
        kind=ClaimKind.INFERENCE,
        text="Proposed fix: upgrade express-jwt. Requires human approval.",
        validated=True,
    )
    trace = [
        AgentTrace(agent="triage", produced=["pack-f-jsonwebtoken"]),
        AgentTrace(agent="relevance", produced=["pack-f-jsonwebtoken"]),
    ]
    out = store.root
    (out / "run.json").write_text(result.scan.model_dump_json())
    (out / "graph.json").write_text(result.graph.model_dump_json())
    (out / "coverage.json").write_text(CoverageArtifact().model_dump_json())
    artifacts = FindingsArtifact(
        findings=[*result.findings, synthetic],
        evidence=store.records(),
        claims=[fix],
        agent_trace=trace,
    )
    (out / "findings.json").write_text(artifacts.model_dump_json())
    render(out)
    return out


def test_report_sections_follow_the_required_order(tmp_path: Path) -> None:
    out = _write_run(tmp_path)
    for name, heading in (("report.html", "<h2>{}</h2>"), ("report.md", "## {}\n")):
        text = (out / name).read_text()
        titles = [escape(s, quote=False) if name.endswith("html") else s for s in SECTIONS]
        positions = [text.index(heading.format(title)) for title in titles]
        assert positions == sorted(positions), name


def test_report_explains_entry_paths_relevance_and_synthetic_label(tmp_path: Path) -> None:
    out = _write_run(tmp_path)
    html = (out / "report.html").read_text()
    assert "guardian-demo-app@1.0.0" in html and "express-jwt@0.1.3" in html
    assert "Introduced by <strong>express-jwt</strong>" in html
    assert html.index("GHSA-jsonwebtoken") < html.index("GHSA-minimist")
    assert "imported at src/server.js:5" in html
    assert "SYNTHETIC test package" in html
    assert "Proposed:</strong> Proposed fix: upgrade express-jwt" in html
    assert "Reachability is a static import search" in html
    markdown = (out / "report.md").read_text()
    assert "introduced by express-jwt" in markdown
    assert "### relevant: GHSA-jsonwebtoken" in markdown


def test_report_shows_decision_score_reasons_confidence_and_review_tag(tmp_path: Path) -> None:
    out = _write_run(tmp_path)
    artifacts = FindingsArtifact.model_validate_json((out / "findings.json").read_text())
    first = artifacts.findings[0].model_copy(update={
        "ssvc_decision": SsvcDecision.ACT, "risk_score": 91, "confidence_score": 0.47,
        "risk_reasons": ["in CISA KEV", "EPSS 0.33 (98th percentile)"],
        "review_required": True,
        "review_reasons": ["confidence 0.47 is below the 0.60 review threshold"],
    })
    artifacts.findings[0] = first
    (out / "findings.json").write_text(artifacts.model_dump_json())
    render(out)
    html = (out / "report.html").read_text()
    assert "Decision <strong>Act</strong>" in html
    assert "Score 91/100" in html and "Confidence 0.47" in html
    assert "in CISA KEV" in html and "EPSS 0.33 (98th percentile)" in html
    assert "needs human review" in html
    assert "confidence 0.47 is below the 0.60 review threshold" in html
    markdown = (out / "report.md").read_text()
    assert "Decision **Act**" in markdown and "needs human review" in markdown
    assert "EPSS 0.33 \\(98th percentile\\)" in markdown


def test_report_shows_ai_adjusted_tag_reason_and_adjustment_table(tmp_path: Path) -> None:
    out = _write_run(tmp_path)
    artifacts = FindingsArtifact.model_validate_json((out / "findings.json").read_text())
    first = artifacts.findings[0]
    reason = "The advisory only applies when the legacy parser is enabled."
    artifacts.findings[0] = first.model_copy(update={
        "risk_level": RiskLevel.HIGH, "engine_risk_level": RiskLevel.MEDIUM, "ai_adjusted": True,
        "ai_adjustment_reason": reason,
    })
    artifacts.risk_adjustments = [
        RiskAdjustment(
            finding_id=first.finding_id, from_level="medium", to_level="high", direction="raise",
            reason=reason, evidence_ids=first.evidence_ids, status="accepted",
        ),
        RiskAdjustment(
            finding_id="f-other", from_level="low", to_level="critical", direction="raise",
            reason="Too big a jump.", status="rejected",
            rejected_reason="to_level must be exactly one level from the current level",
        ),
    ]
    (out / "findings.json").write_text(artifacts.model_dump_json())
    render(out)
    html = (out / "report.html").read_text()
    assert "AI adjusted: medium → high" in html
    assert html.count(reason) >= 2
    assert "<h3>Risk adjustments</h3>" in html
    assert "to_level must be exactly one level from the current level" in html
    markdown = (out / "report.md").read_text()
    assert "AI adjusted: medium → high" in markdown
    assert "### Risk adjustments" in markdown
    assert "low → critical" in markdown and "rejected" in markdown
