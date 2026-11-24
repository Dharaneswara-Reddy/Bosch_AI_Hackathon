"""Before/after comparison of two scans of the same project."""

from pydantic import BaseModel, Field

from guardian.ai.triage import package_key
from guardian.models import Finding, RiskLevel, RunResult
from guardian.remediate.candidates import RISK_ORDER


class FindingRef(BaseModel):
    finding_id: str
    advisory_id: str | None
    package: str
    version: str
    risk_level: RiskLevel


class LevelChange(BaseModel):
    advisory_id: str | None
    package: str
    from_level: RiskLevel
    to_level: RiskLevel


class VersionChange(BaseModel):
    package: str
    before: str | None
    after: str | None


class RescanDiff(BaseModel):
    counts_before: dict[str, int]
    counts_after: dict[str, int]
    fixed: list[FindingRef] = Field(default_factory=list)
    introduced: list[FindingRef] = Field(default_factory=list)
    level_changed: list[LevelChange] = Field(default_factory=list)
    version_changes: list[VersionChange] = Field(default_factory=list)


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts = {level.value: 0 for level in RiskLevel}
    for finding in findings:
        counts[finding.risk_level.value] += 1
    return counts


def _identity(finding: Finding) -> tuple[str, str]:
    return package_key(finding.purl), finding.advisory_id or finding.anomaly_type or finding.kind


def _by_identity(run: RunResult) -> dict[tuple[str, str], Finding]:
    found: dict[tuple[str, str], Finding] = {}
    for finding in run.findings:
        key = _identity(finding)
        if key not in found or RISK_ORDER[finding.risk_level] > RISK_ORDER[found[key].risk_level]:
            found[key] = finding
    return found


def _ref(run: RunResult, finding: Finding) -> FindingRef:
    node = next((n for n in run.graph.nodes if n.component_id == finding.component_id), None)
    return FindingRef(
        finding_id=finding.finding_id, advisory_id=finding.advisory_id,
        package=node.name if node else package_key(finding.purl).split(":", 1)[1],
        version=node.version if node else "UNKNOWN", risk_level=finding.risk_level,
    )


def _versions(run: RunResult) -> dict[str, str]:
    return {f"{n.ecosystem}:{n.name}": n.version for n in run.graph.nodes}


def _version_changes(before: RunResult, after: RunResult) -> list[VersionChange]:
    old, new = _versions(before), _versions(after)
    return [
        VersionChange(package=key.split(":", 1)[1], before=old.get(key), after=new.get(key))
        for key in sorted(old.keys() | new.keys())
        if old.get(key) != new.get(key)
    ]


def diff_runs(before: RunResult, after: RunResult) -> RescanDiff:
    old, new = _by_identity(before), _by_identity(after)
    changed = [
        LevelChange(advisory_id=new[k].advisory_id, package=_ref(after, new[k]).package,
                    from_level=old[k].risk_level, to_level=new[k].risk_level)
        for k in sorted(old.keys() & new.keys()) if old[k].risk_level != new[k].risk_level
    ]
    return RescanDiff(
        counts_before=_counts(before.findings), counts_after=_counts(after.findings),
        fixed=[_ref(before, old[k]) for k in sorted(old.keys() - new.keys())],
        introduced=[_ref(after, new[k]) for k in sorted(new.keys() - old.keys())],
        level_changed=changed, version_changes=_version_changes(before, after),
    )
