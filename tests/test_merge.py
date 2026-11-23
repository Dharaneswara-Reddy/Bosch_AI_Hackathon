from guardian.models import Finding, FindingKind, MatchBasis, finding_id
from guardian.scanners.merge import attach_paths, merge_findings

PURL = "pkg:npm/x@1.0.0"


def make(
    scanner: str,
    advisory: str,
    aliases: list[str] | None = None,
    *,
    purl: str = PURL,
    severity: str = "HIGH",
    kind: FindingKind = FindingKind.VULNERABILITY,
    fixed: list[str] | None = None,
    evidence: list[str] | None = None,
    basis: MatchBasis = MatchBasis.PURL,
) -> Finding:
    return Finding(
        finding_id=finding_id(scanner, purl, advisory, []),
        kind=kind,
        component_id=purl,
        purl=purl,
        advisory_id=advisory,
        aliases=aliases or [],
        confirmed_by=[scanner],
        source_severity=severity,
        severities={scanner: severity},
        fixed_versions=fixed or [],
        match_basis=basis,
        evidence_ids=evidence or [],
    )


def test_ghsa_and_cve_alias_merge_with_both_scanners() -> None:
    grype = make("grype", "GHSA-aaaa", ["CVE-2020-1"])
    osv = make("osv", "CVE-2020-1", ["GHSA-aaaa"])
    [merged] = merge_findings([grype, osv])
    assert merged.advisory_id == "CVE-2020-1"
    assert merged.aliases == ["GHSA-aaaa"]
    assert merged.confirmed_by == ["grype", "osv"]
    assert merged.severities == {"grype": "HIGH", "osv": "HIGH"}
    assert merged.finding_id == finding_id("vuln", PURL, "CVE-2020-1", [])


def test_transitive_merge() -> None:
    a = make("grype", "GHSA-a", ["CVE-1"])
    b = make("osv", "CVE-1", ["GHSA-b"])
    c = make("osv", "GHSA-b")
    result = merge_findings([a, b, c])
    assert len(result) == 1
    assert result[0].aliases == ["GHSA-a", "GHSA-b"]


def test_same_cve_different_purls_stays_separate() -> None:
    a = make("grype", "CVE-1", purl="pkg:npm/x@1")
    b = make("osv", "CVE-1", purl="pkg:npm/y@1")
    assert [f.purl for f in merge_findings([a, b])] == ["pkg:npm/x@1", "pkg:npm/y@1"]


def test_highest_severity_wins_including_moderate() -> None:
    a = make("grype", "CVE-1", severity="Moderate")
    b = make("osv", "CVE-1", severity="low")
    assert merge_findings([a, b])[0].source_severity == "MEDIUM"
    c = make("osv", "CVE-1", severity="CRITICAL")
    assert merge_findings([a, c])[0].source_severity == "CRITICAL"


def test_severity_label_normalised_and_raw_kept() -> None:
    a = make("grype", "CVE-1", severity="High")
    merged = merge_findings([a])[0]
    assert merged.source_severity == "HIGH"
    assert merged.severities["grype"] == "High"


def test_unknown_severity_loses_to_known() -> None:
    a = make("grype", "CVE-1", severity="UNKNOWN")
    b = make("osv", "CVE-1", severity="LOW")
    assert merge_findings([a, b])[0].source_severity == "LOW"


def test_primary_id_prefers_cve_then_ghsa_then_mal() -> None:
    ghsa = merge_findings([make("grype", "MAL-1", ["GHSA-z", "GHSA-b"])])[0]
    assert ghsa.advisory_id == "GHSA-b"
    assert ghsa.aliases == ["GHSA-z", "MAL-1"]
    mal = merge_findings([make("osv", "OSV-9", ["MAL-2"])])[0]
    assert mal.advisory_id == "MAL-2"
    other = merge_findings([make("osv", "OSV-9", ["ABC-1"])])[0]
    assert other.advisory_id == "ABC-1"


def test_malicious_propagates() -> None:
    a = make("grype", "CVE-1", ["MAL-1"])
    b = make("osv", "MAL-1", kind=FindingKind.MALICIOUS)
    assert merge_findings([a, b])[0].kind == FindingKind.MALICIOUS


def test_evidence_and_fixed_versions_union_in_order() -> None:
    a = make("grype", "CVE-1", fixed=["2.0", "1.5"], evidence=["e2", "e1"])
    b = make("osv", "CVE-1", fixed=["1.5", "3.0"], evidence=["e1", "e3"])
    merged = merge_findings([a, b])[0]
    assert merged.fixed_versions == ["2.0", "1.5", "3.0"]
    assert merged.evidence_ids == ["e2", "e1", "e3"]


def test_match_basis_precedence() -> None:
    cpe = make("grype", "CVE-1", basis=MatchBasis.CPE)
    unk = make("osv", "CVE-1", basis=MatchBasis.UNKNOWN)
    pur = make("osv", "CVE-1", basis=MatchBasis.PURL)
    assert merge_findings([unk, cpe])[0].match_basis == MatchBasis.CPE
    assert merge_findings([unk, cpe, pur])[0].match_basis == MatchBasis.PURL
    assert merge_findings([unk])[0].match_basis == MatchBasis.UNKNOWN


def test_output_order_is_deterministic() -> None:
    items = [
        make("grype", "CVE-2", purl="pkg:npm/b@1"),
        make("grype", "CVE-9", purl="pkg:npm/a@1"),
        make("grype", "CVE-1", purl="pkg:npm/a@1"),
    ]
    forward = merge_findings(items)
    backward = merge_findings(list(reversed(items)))
    assert forward == backward
    assert [(f.purl, f.advisory_id) for f in forward] == [
        ("pkg:npm/a@1", "CVE-1"),
        ("pkg:npm/a@1", "CVE-9"),
        ("pkg:npm/b@1", "CVE-2"),
    ]


def test_input_not_mutated() -> None:
    a = make("grype", "GHSA-a", ["CVE-1"])
    b = make("osv", "CVE-1", ["GHSA-a"])
    before = [a.model_copy(deep=True), b.model_copy(deep=True)]
    merge_findings([a, b])
    assert [a, b] == before


def test_anomaly_passes_through_unchanged() -> None:
    anomaly = Finding(
        finding_id="an1",
        kind=FindingKind.ANOMALY,
        component_id=PURL,
        purl=PURL,
        anomaly_type="install-script",
    )
    vuln = make("grype", "CVE-1")
    result = merge_findings([anomaly, vuln])
    assert anomaly in result
    assert len(result) == 2


def test_attach_paths_sets_path_count_and_finding_id() -> None:
    f = make("grype", "CVE-1")
    path = ["app", "mid", PURL]
    [out] = attach_paths([f], {PURL: (path, 3)})
    assert out.dependency_path == path
    assert out.path_count == 3
    assert out.finding_id == finding_id("vuln", PURL, "CVE-1", path)
    assert out.finding_id != f.finding_id
    assert f.dependency_path == []


def test_attach_paths_missing_entry_left_empty() -> None:
    f = make("grype", "CVE-1")
    [out] = attach_paths([f], {"other": (["app"], 1)})
    assert out.dependency_path == []
    assert out.path_count is None
    assert out.finding_id == f.finding_id


def test_merge_keeps_exploit_and_cvss_intel_from_whichever_scanner_has_it() -> None:
    grype = make("grype", "GHSA-1", ["CVE-1"]).model_copy(update={
        "epss": 0.3, "epss_percentile": 0.97, "epss_date": "2026-11-22",
        "known_exploited": False, "cvss_vector": "CVSS:3.1/AV:N/UI:N", "cvss_score": 7.5,
        "intel_evidence_ids": ["g-epss"],
    })
    osv = make("osv", "CVE-1").model_copy(update={
        "cvss_vector": "CVSS:3.1/AV:L/UI:N", "intel_evidence_ids": ["o-cvss"],
    })
    (merged,) = merge_findings([osv, grype])
    assert (merged.epss, merged.epss_percentile, merged.epss_date) == (0.3, 0.97, "2026-11-22")
    assert merged.known_exploited is False
    assert (merged.cvss_vector, merged.cvss_score) == ("CVSS:3.1/AV:N/UI:N", 7.5)
    assert merged.intel_evidence_ids == ["o-cvss", "g-epss"]


def test_merge_known_exploited_true_wins_over_false() -> None:
    a = make("grype", "CVE-1").model_copy(update={"known_exploited": False})
    b = make("osv", "CVE-1").model_copy(update={"known_exploited": True})
    assert merge_findings([a, b])[0].known_exploited is True
