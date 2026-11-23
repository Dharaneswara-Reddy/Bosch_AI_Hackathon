"""A small, realistic Juice Shop run used by the AI tests."""

from __future__ import annotations

from guardian.ai.context import ReviewContext
from guardian.models import (
    AgentClaim,
    ClaimKind,
    Component,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    RiskLevel,
    Scope,
)

GRYPE_URL = "https://github.com/advisories/GHSA-c7hr-j4mj-j2w6"


def _component(name: str, version: str) -> Component:
    purl = f"pkg:npm/{name}@{version}"
    return Component(
        component_id=purl,
        purl=purl,
        name=name,
        version=version,
        ecosystem="npm",
        scope=Scope.TRANSITIVE,
        dev=False,
        source_file="package-lock.json",
    )


def make_context(project_text: str = "OWASP Juice Shop") -> ReviewContext:
    app = _component("juice-shop", "19.0.0")
    express_jwt = _component("express-jwt", "0.1.3")
    jwt = _component("jsonwebtoken", "0.4.0")
    left_pad = _component("left-pad", "1.3.0")
    evidence = [
        Evidence(
            evidence_id="ev-grype-0001",
            tool="grype",
            tool_version="0.104.0",
            file="raw/grype.json",
            pointer="/matches/0",
            sha256="a" * 64,
            url=GRYPE_URL,
            collected_at=None,
        ),
        Evidence(
            evidence_id="ev-diff-0001",
            tool="git",
            tool_version="2.43",
            file="raw/git-diff.patch",
            pointer="package.json:12-13",
            sha256="b" * 64,
            url=None,
            collected_at=None,
        ),
    ]
    findings = [
        Finding(
            finding_id="f-jwt",
            kind=FindingKind.VULNERABILITY,
            component_id=jwt.component_id,
            purl=jwt.purl,
            advisory_id="GHSA-c7hr-j4mj-j2w6",
            aliases=["CVE-2015-9235"],
            confirmed_by=["grype", "osv"],
            source_severity="Critical",
            fixed_versions=["4.2.2"],
            dependency_path=[app.component_id, express_jwt.component_id, jwt.component_id],
            path_count=1,
            evidence_ids=["ev-grype-0001"],
            risk_level=RiskLevel.CRITICAL,
            risk_rule_id="R-CVE-1",
            confidence=Confidence.HIGH,
        ),
        Finding(
            finding_id="f-leftpad",
            kind=FindingKind.ANOMALY,
            component_id=left_pad.component_id,
            purl=left_pad.purl,
            anomaly_type="unexpected_dependency",
            evidence_ids=["ev-diff-0001"],
            risk_level=RiskLevel.MEDIUM,
            risk_rule_id="R-AN-2",
            confidence=Confidence.HIGH,
        ),
    ]
    return ReviewContext.build(
        findings, evidence, [app, express_jwt, jwt, left_pad], project_text=project_text
    )


def claim(text: str, evidence_ids: list[str], kind: str = "evidence") -> AgentClaim:
    return AgentClaim(
        claim_id="c-test",
        step="explain_vulns",
        text=text,
        evidence_ids=evidence_ids,
        kind=ClaimKind(kind),
        validated=False,
        rejected_reason=None,
        uncertainty=None,
    )
