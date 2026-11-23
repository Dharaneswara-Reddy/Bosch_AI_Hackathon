"""Summarise what changed between a baseline scan and the current scan."""

import re

from pydantic import BaseModel, Field

from guardian.models import UNKNOWN, Component, Finding, FindingKind, GraphArtifact

PackageKey = tuple[str, str]
FindingKey = tuple[str, str, str]


class PackageRef(BaseModel):
    name: str
    ecosystem: str
    version: str


class VersionChange(BaseModel):
    name: str
    ecosystem: str
    from_version: str
    to_version: str


class ResolvedFinding(BaseModel):
    finding: str
    package: str


class ChangeSummary(BaseModel):
    baseline_ref: str
    baseline_commit: str = ""
    added: list[PackageRef] = Field(default_factory=list)
    removed: list[PackageRef] = Field(default_factory=list)
    upgraded: list[VersionChange] = Field(default_factory=list)
    downgraded: list[VersionChange] = Field(default_factory=list)
    new_findings: list[str] = Field(default_factory=list)
    resolved_findings: list[ResolvedFinding] = Field(default_factory=list)
    new_anomalies: int = 0


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def _versions(graph: GraphArtifact) -> dict[PackageKey, set[str]]:
    packages: dict[PackageKey, set[str]] = {}
    for node in graph.nodes:
        if node.ecosystem == UNKNOWN:
            continue
        packages.setdefault((node.ecosystem, node.name), set()).add(node.version)
    return packages


def _refs(keys: set[PackageKey], versions: dict[PackageKey, set[str]]) -> list[PackageRef]:
    return [
        PackageRef(name=name, ecosystem=ecosystem, version=version)
        for ecosystem, name in sorted(keys)
        for version in sorted(versions[(ecosystem, name)], key=_version_key)
    ]


def _version_changes(
    baseline: dict[PackageKey, set[str]],
    current: dict[PackageKey, set[str]],
) -> tuple[list[VersionChange], list[VersionChange]]:
    upgraded: list[VersionChange] = []
    downgraded: list[VersionChange] = []
    for key in sorted(baseline.keys() & current.keys()):
        old_only, new_only = baseline[key] - current[key], current[key] - baseline[key]
        if not old_only or not new_only:
            continue
        old, new = max(old_only, key=_version_key), max(new_only, key=_version_key)
        change = VersionChange(name=key[1], ecosystem=key[0], from_version=old, to_version=new)
        (upgraded if _version_key(new) > _version_key(old) else downgraded).append(change)
    return upgraded, downgraded


def _finding_keys(findings: list[Finding], graph: GraphArtifact) -> dict[FindingKey, Finding]:
    nodes: dict[str, Component] = {node.component_id: node for node in graph.nodes}
    keyed: dict[FindingKey, Finding] = {}
    for finding in findings:
        node = nodes.get(finding.component_id)
        package = (node.ecosystem, node.name) if node else ("", finding.purl)
        label = finding.advisory_id or finding.anomaly_type or finding.kind.value
        keyed[(label, *package)] = finding
    return keyed


def compute_changes(
    baseline_graph: GraphArtifact,
    current_graph: GraphArtifact,
    baseline_findings: list[Finding],
    current_findings: list[Finding],
    baseline_ref: str,
    baseline_commit: str,
) -> ChangeSummary:
    old, new = _versions(baseline_graph), _versions(current_graph)
    upgraded, downgraded = _version_changes(old, new)
    before = _finding_keys(baseline_findings, baseline_graph)
    after = _finding_keys(current_findings, current_graph)
    appeared = [finding for key, finding in after.items() if key not in before]
    return ChangeSummary(
        baseline_ref=baseline_ref,
        baseline_commit=baseline_commit,
        added=_refs(new.keys() - old.keys(), new),
        removed=_refs(old.keys() - new.keys(), old),
        upgraded=upgraded,
        downgraded=downgraded,
        new_findings=[finding.finding_id for finding in appeared],
        resolved_findings=[
            ResolvedFinding(finding=key[0], package=key[2]) for key in before if key not in after
        ],
        new_anomalies=sum(finding.kind is FindingKind.ANOMALY for finding in appeared),
    )
