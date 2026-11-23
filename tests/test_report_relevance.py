from __future__ import annotations

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
)
from guardian.report.render import render
from tests.test_relevance import APP, _demo_run

SECTIONS = [
    "SBOM and inventory",
    "How each vulnerability enters the application",
    "Vulnerabilities ranked by relevance",
    "Suspicious and malicious packages",
    "AI analysis",
    "Fix proposals (human approval required)",
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
        positions = [text.index(heading.format(section)) for section in SECTIONS]
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
