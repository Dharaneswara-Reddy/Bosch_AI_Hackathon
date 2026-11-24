from guardian.changes import compute_changes
from guardian.models import Component, Finding, FindingKind, GraphArtifact


def graph(*packages: tuple[str, str]) -> GraphArtifact:
    return GraphArtifact(
        nodes=[
            Component(
                component_id=f"{name}@{version}",
                purl=f"pkg:npm/{name}@{version}",
                name=name,
                version=version,
                ecosystem="npm",
            )
            for name, version in packages
        ]
    )


def vuln(fid: str, name: str, version: str, advisory: str) -> Finding:
    return Finding(
        finding_id=fid,
        kind=FindingKind.VULNERABILITY,
        advisory_id=advisory,
        component_id=f"{name}@{version}",
        purl=f"pkg:npm/{name}@{version}",
    )


def anomaly(fid: str, name: str, version: str, kind: str) -> Finding:
    return Finding(
        finding_id=fid,
        kind=FindingKind.ANOMALY,
        anomaly_type=kind,
        component_id=f"{name}@{version}",
        purl=f"pkg:npm/{name}@{version}",
    )


def test_package_changes_are_classified() -> None:
    changes = compute_changes(
        graph(("a", "1.0.0"), ("b", "2.0.0"), ("c", "1.2.0"), ("d", "1.0.0")),
        graph(("a", "1.0.0"), ("b", "2.1.0"), ("c", "1.10.0"), ("d", "0.9.0"), ("e", "1.0.0")),
        [],
        [],
        baseline_ref="v1",
        baseline_commit="abc1234",
    )
    assert [p.name for p in changes.added] == ["e"]
    assert changes.removed == []
    assert {(u.name, u.from_version, u.to_version) for u in changes.upgraded} == {
        ("b", "2.0.0", "2.1.0"),
        ("c", "1.2.0", "1.10.0"),
    }
    assert [(u.name, u.from_version, u.to_version) for u in changes.downgraded] == [
        ("d", "1.0.0", "0.9.0")
    ]
    assert (changes.baseline_ref, changes.baseline_commit) == ("v1", "abc1234")


def test_removed_package() -> None:
    changes = compute_changes(graph(("a", "1"), ("b", "1")), graph(("a", "1")), [], [], "v1", "")
    assert [p.name for p in changes.removed] == ["b"]


def test_findings_are_matched_across_versions_by_advisory_and_package() -> None:
    changes = compute_changes(
        graph(("a", "1"), ("b", "1")),
        graph(("a", "2"), ("b", "1"), ("c", "1")),
        [vuln("old-a", "a", "1", "CVE-1"), vuln("old-b", "b", "1", "CVE-2")],
        [
            vuln("new-a", "a", "2", "CVE-1"),
            vuln("new-c", "c", "1", "CVE-3"),
            anomaly("new-an", "c", "1", "install_script"),
        ],
        "v1",
        "",
    )
    assert changes.new_findings == ["new-c", "new-an"]
    assert [(r.finding, r.package) for r in changes.resolved_findings] == [("CVE-2", "b")]
    assert changes.new_anomalies == 1


def test_non_package_nodes_are_not_reported_as_added() -> None:
    current = graph(("a", "1.0.0"))
    current.nodes.append(
        Component(
            component_id="wf",
            purl="UNKNOWN",
            name="/.github/workflows/ci.yml",
            version="UNKNOWN",
            ecosystem="UNKNOWN",
        )
    )
    changes = compute_changes(graph(("a", "1.0.0")), current, [], [], "v1", "abc1234")
    assert changes.added == []
