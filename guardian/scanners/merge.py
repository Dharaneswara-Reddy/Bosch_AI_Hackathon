from collections import defaultdict
from collections.abc import Iterable, Mapping

from guardian.models import UNKNOWN, Finding, FindingKind, MatchBasis, finding_id

_SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}
_ID_PREFIXES = ("CVE-", "GHSA-", "MAL-")


def _ids(finding: Finding) -> set[str]:
    ids = set(finding.aliases)
    if finding.advisory_id:
        ids.add(finding.advisory_id)
    return ids


def _components(findings: list[Finding]) -> list[list[Finding]]:
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[tuple[str, str], int] = {}
    for idx, finding in enumerate(findings):
        for advisory in _ids(finding):
            first = owner.setdefault((finding.purl, advisory), idx)
            parent[find(idx)] = find(first)
    groups: dict[int, list[Finding]] = defaultdict(list)
    for idx, finding in enumerate(findings):
        groups[find(idx)].append(finding)
    return list(groups.values())


def _primary_id(ids: set[str]) -> str:
    ordered = sorted(ids)
    for prefix in _ID_PREFIXES:
        for candidate in ordered:
            if candidate.startswith(prefix):
                return candidate
    return ordered[0]


def _union(lists: Iterable[list[str]]) -> list[str]:
    return list(dict.fromkeys(item for items in lists for item in items))


def _normalise_severity(label: str) -> str:
    upper = label.upper()
    if upper == "MODERATE":
        return "MEDIUM"
    return upper if upper in _SEVERITY_RANK else UNKNOWN


def _highest_severity(labels: Iterable[str]) -> str:
    normalised = [_normalise_severity(label) for label in labels]
    return max(normalised, key=lambda label: _SEVERITY_RANK[label], default=UNKNOWN)


def _match_basis(members: list[Finding]) -> MatchBasis:
    bases = {m.match_basis for m in members}
    for basis in (MatchBasis.PURL, MatchBasis.CPE):
        if basis in bases:
            return basis
    return MatchBasis.UNKNOWN


def _merge_group(members: list[Finding]) -> Finding:
    ids: set[str] = set().union(*(_ids(m) for m in members))
    primary = _primary_id(ids)
    severities: dict[str, str] = {}
    for member in members:
        severities.update(member.severities)
    is_malicious = any(m.kind == FindingKind.MALICIOUS for m in members)
    labels = [m.source_severity for m in members]
    return members[0].model_copy(
        update={
            "finding_id": finding_id("vuln", members[0].purl, primary, []),
            "kind": FindingKind.MALICIOUS if is_malicious else FindingKind.VULNERABILITY,
            "advisory_id": primary,
            "aliases": sorted(ids - {primary}),
            "confirmed_by": sorted({s for m in members for s in m.confirmed_by}),
            "severities": severities,
            "source_severity": _highest_severity(labels),
            "fixed_versions": _union(m.fixed_versions for m in members),
            "evidence_ids": _union(m.evidence_ids for m in members),
            "match_basis": _match_basis(members),
        },
        deep=True,
    )


def merge_findings(findings: list[Finding]) -> list[Finding]:
    anomalies = [f for f in findings if f.kind == FindingKind.ANOMALY]
    detections = [f for f in findings if f.kind != FindingKind.ANOMALY]
    merged = [_merge_group(group) for group in _components(detections)]
    merged.sort(key=lambda f: (f.purl, f.advisory_id or ""))
    anomalies.sort(key=lambda f: (f.purl, f.finding_id))
    return merged + anomalies


def attach_paths(
    findings: list[Finding], paths: Mapping[str, tuple[list[str], int]]
) -> list[Finding]:
    result: list[Finding] = []
    for finding in findings:
        entry = paths.get(finding.component_id)
        if entry is None:
            result.append(finding.model_copy(deep=True))
            continue
        path, count = entry
        result.append(
            finding.model_copy(
                update={
                    "dependency_path": list(path),
                    "path_count": count,
                    "finding_id": finding_id("vuln", finding.purl, finding.advisory_id or "", path),
                },
                deep=True,
            )
        )
    return result
