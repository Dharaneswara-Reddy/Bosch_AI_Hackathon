from datetime import UTC, datetime

from guardian.models import (
    Component,
    Finding,
    FindingKind,
    GraphArtifact,
    RiskLevel,
    RunResult,
    Scan,
)
from guardian.remediate.diff import diff_runs


def _component(name: str, version: str) -> Component:
    purl = f"pkg:npm/{name}@{version}"
    return Component(component_id=f"{purl}?package-id=x", purl=purl, name=name, version=version,
                     ecosystem="npm")


def _finding(component: Component, advisory: str, level: RiskLevel, fid: str) -> Finding:
    return Finding(finding_id=fid, kind=FindingKind.VULNERABILITY,
                   component_id=component.component_id, purl=component.purl,
                   advisory_id=advisory, risk_level=level)


def _run(components: list[Component], findings: list[Finding]) -> RunResult:
    return RunResult(scan=Scan(scan_id="s", target="t", started_at=datetime.now(UTC)),
                     graph=GraphArtifact(nodes=components), findings=findings)


def test_diff_reports_fixed_introduced_changed_and_version_changes() -> None:
    lodash_old, jwt_old = _component("lodash", "4.17.4"), _component("jwt", "0.1.0")
    lodash_new, jwt_new = _component("lodash", "4.17.21"), _component("jwt", "9.0.0")
    extra = _component("extra", "1.0.0")
    before = _run([lodash_old, jwt_old], [
        _finding(lodash_old, "CVE-A", RiskLevel.HIGH, "a1"),
        _finding(jwt_old, "CVE-B", RiskLevel.HIGH, "b1"),
        _finding(jwt_old, "CVE-C", RiskLevel.MEDIUM, "c1"),
    ])
    after = _run([lodash_new, jwt_new, extra], [
        _finding(jwt_new, "CVE-C", RiskLevel.LOW, "c2"),
        _finding(extra, "CVE-N", RiskLevel.CRITICAL, "n1"),
    ])
    diff = diff_runs(before, after)
    assert diff.counts_before == {"critical": 0, "high": 2, "medium": 1, "low": 0, "unknown": 0}
    assert diff.counts_after == {"critical": 1, "high": 0, "medium": 0, "low": 1, "unknown": 0}
    assert sorted(f.advisory_id for f in diff.fixed) == ["CVE-A", "CVE-B"]
    assert [(f.advisory_id, f.package) for f in diff.introduced] == [("CVE-N", "extra")]
    [changed] = diff.level_changed
    assert (changed.advisory_id, changed.from_level, changed.to_level) == (
        "CVE-C", RiskLevel.MEDIUM, RiskLevel.LOW)
    assert sorted((v.package, v.before, v.after) for v in diff.version_changes) == [
        ("extra", None, "1.0.0"), ("jwt", "0.1.0", "9.0.0"), ("lodash", "4.17.4", "4.17.21")]
