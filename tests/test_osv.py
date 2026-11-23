import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from guardian.models import FindingKind, MatchBasis, finding_id
from guardian.scanners.osv import OSV_IMAGE, OsvError, parse_osv, run_osv

FIXTURE = Path(__file__).parent / "fixtures" / "osv.sample.json"
SHA = "abcdef0123456789"


@pytest.fixture
def raw() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text())
    return data


def _synthetic(
    vuln: dict[str, Any], groups: list[dict[str, Any]], eco: str = "npm", purl: str | None = None
) -> dict[str, Any]:
    pkg: dict[str, Any] = {"name": "evil-pkg", "version": "1.0.0", "ecosystem": eco}
    if purl:
        pkg["purl"] = purl
    return {
        "results": [
            {
                "source": {"path": "/in/x"},
                "packages": [{"package": pkg, "groups": groups, "vulnerabilities": [vuln]}],
            }
        ]
    }


def test_one_finding_per_package_vulnerability(raw: dict[str, Any]) -> None:
    findings, evidence = parse_osv(raw, "raw/osv.json", SHA, "2.7.1")
    assert len(findings) == 8
    assert len(evidence) == 8


def test_purl_taken_from_package(raw: dict[str, Any]) -> None:
    findings, _ = parse_osv(raw, "raw/osv.json", SHA, "2.7.1")
    f = next(x for x in findings if x.advisory_id == "GHSA-33qg-7wpp-89cq")
    assert f.purl == "pkg:gem/rack-session@2.1.1"
    assert f.component_id == f.purl
    assert f.match_basis == MatchBasis.PURL
    assert f.confirmed_by == ["osv"]
    assert f.kind == FindingKind.VULNERABILITY


def test_severity_from_group_max_severity(raw: dict[str, Any]) -> None:
    findings, _ = parse_osv(raw, "raw/osv.json", SHA, "2.7.1")
    by_id = {f.advisory_id: f for f in findings}
    assert by_id["GHSA-33qg-7wpp-89cq"].source_severity == "CRITICAL"
    assert by_id["GHSA-h8w8-99g7-qmvj"].source_severity == "HIGH"
    assert by_id["GHSA-wv3x-4vxv-whpp"].source_severity == "MEDIUM"
    assert by_id["GHSA-5957-c7qm-m469"].severities == {"osv": "LOW"}


def test_severity_falls_back_to_database_specific() -> None:
    vuln = {"id": "GHSA-x", "database_specific": {"severity": "MODERATE"}, "affected": []}
    findings, _ = parse_osv(_synthetic(vuln, []), "r", SHA, "v")
    assert findings[0].source_severity == "MEDIUM"


def test_severity_unknown_when_absent() -> None:
    findings, _ = parse_osv(_synthetic({"id": "GHSA-x", "affected": []}, []), "r", SHA, "v")
    assert findings[0].source_severity == "UNKNOWN"


def test_aliases_sorted_unique_excluding_id() -> None:
    vuln = {"id": "GHSA-x", "aliases": ["CVE-2", "CVE-1", "CVE-2", "GHSA-x"], "affected": []}
    findings, _ = parse_osv(_synthetic(vuln, []), "r", SHA, "v")
    assert findings[0].aliases == ["CVE-1", "CVE-2"]


def test_fixed_versions_deduped_in_order(raw: dict[str, Any]) -> None:
    findings, _ = parse_osv(raw, "raw/osv.json", SHA, "2.7.1")
    f = next(x for x in findings if x.advisory_id == "GHSA-2vqw-3mp8-cgmx")
    assert f.fixed_versions == ["8.0.2", "7.2.1"]


def test_fixed_versions_ignore_other_packages() -> None:
    vuln = {
        "id": "GHSA-x",
        "affected": [
            {"package": {"name": "other"}, "ranges": [{"events": [{"fixed": "9"}]}]},
            {
                "package": {"name": "evil-pkg"},
                "ranges": [{"events": [{"fixed": "2"}, {"fixed": "2"}]}],
            },
        ],
    }
    findings, _ = parse_osv(_synthetic(vuln, []), "r", SHA, "v")
    assert findings[0].fixed_versions == ["2"]


def test_synthetic_mal_entry_is_malicious() -> None:
    vuln = {"id": "MAL-2099-0001", "summary": "SYNTHETIC malicious package", "affected": []}
    findings, _ = parse_osv(_synthetic(vuln, []), "r", SHA, "v")
    assert findings[0].kind == FindingKind.MALICIOUS


@pytest.mark.parametrize(
    ("eco", "expected"),
    [
        ("RubyGems", "pkg:gem/evil-pkg@1.0.0"),
        ("npm", "pkg:npm/evil-pkg@1.0.0"),
        ("PyPI", "pkg:pypi/evil-pkg@1.0.0"),
        ("crates.io", "pkg:cargo/evil-pkg@1.0.0"),
        ("Packagist", "pkg:composer/evil-pkg@1.0.0"),
        ("Hex", "pkg:hex/evil-pkg@1.0.0"),
    ],
)
def test_purl_built_when_missing(eco: str, expected: str) -> None:
    findings, _ = parse_osv(
        _synthetic({"id": "GHSA-x", "affected": []}, [], eco=eco), "r", SHA, "v"
    )
    assert findings[0].purl == expected


def test_evidence_pointer_and_ids(raw: dict[str, Any]) -> None:
    findings, evidence = parse_osv(raw, "raw/osv.json", SHA, "2.7.1")
    ev = evidence[0]
    assert ev.tool == "osv-scanner"
    assert ev.tool_version == "2.7.1"
    assert ev.file == "raw/osv.json"
    assert ev.sha256 == SHA
    assert ev.pointer == "/results/0/packages/0/vulnerabilities/0"
    assert ev.evidence_id == "ev-osv-0-0-0-abcdef01"
    assert ev.url == "https://osv.dev/vulnerability/GHSA-5957-c7qm-m469"
    assert findings[0].evidence_ids == [ev.evidence_id]


def test_finding_id_deterministic(raw: dict[str, Any]) -> None:
    a, _ = parse_osv(raw, "raw/osv.json", SHA, "2.7.1")
    b, _ = parse_osv(raw, "raw/osv.json", SHA, "2.7.1")
    assert [f.finding_id for f in a] == [f.finding_id for f in b]
    assert a[0].finding_id == finding_id("osv", a[0].purl, "GHSA-5957-c7qm-m469", [])


def test_zero_packages_raises() -> None:
    with pytest.raises(OsvError, match="no packages scanned"):
        parse_osv({"results": []}, "r", SHA, "v")


def _completed(rc: int, out: str = "{}", err: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=out, stderr=err)


def test_run_osv_argv_and_output(tmp_path: Path) -> None:
    sbom = tmp_path / "in" / "sbom.cdx.json"
    sbom.parent.mkdir()
    sbom.write_text("{}")
    with patch(
        "guardian.scanners.osv.subprocess.run", return_value=_completed(1, '{"results": []}')
    ) as run:
        out = run_osv(sbom, tmp_path / "out")
    argv = run.call_args.args[0]
    assert argv[:5] == ["docker", "run", "--rm", "--network", "host"]
    assert f"{sbom.parent}:/in:ro" in argv
    assert OSV_IMAGE in argv
    assert argv[-6:] == ["scan", "source", "--format", "json", "-L", "/in/sbom.cdx.json"]
    assert out == tmp_path / "out" / "raw" / "osv.json"
    assert out.read_text() == '{"results": []}'


def test_run_osv_exit_zero_ok(tmp_path: Path) -> None:
    with patch("guardian.scanners.osv.subprocess.run", return_value=_completed(0)):
        assert run_osv(tmp_path / "s.cdx.json", tmp_path / "o").exists()


def test_run_osv_exit_two_raises(tmp_path: Path) -> None:
    with patch("guardian.scanners.osv.subprocess.run", return_value=_completed(2, err="boom")):
        with pytest.raises(OsvError, match="boom"):
            run_osv(tmp_path / "s.cdx.json", tmp_path / "o")
