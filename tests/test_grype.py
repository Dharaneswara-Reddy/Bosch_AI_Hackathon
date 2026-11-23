import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from guardian.models import UNKNOWN, FindingKind, MatchBasis, finding_id
from guardian.scanners import grype
from guardian.scanners.grype import GrypeError, parse_grype, run_grype

FIXTURE = Path(__file__).parent / "fixtures" / "grype.sample.json"
SHA = "abcdef0123456789" * 4


@pytest.fixture
def raw() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text())
    return data


def test_one_finding_and_evidence_per_match(raw: dict[str, Any]) -> None:
    findings, evidence = parse_grype(raw, "raw/grype.json", SHA)
    assert len(findings) == len(evidence) == len(raw["matches"]) == 6


def test_fixed_match_maps_core_fields(raw: dict[str, Any]) -> None:
    f = parse_grype(raw, "raw/grype.json", SHA)[0][0]
    assert f.kind == FindingKind.VULNERABILITY
    assert f.advisory_id == "GHSA-xr9x-r78c-5hrm"
    assert f.purl == f.component_id == "pkg:gem/activestorage@8.0.4"
    assert f.fixed_versions == ["8.0.5.1"]
    assert f.source_severity == "Critical"
    assert f.severities == {"grype": "Critical"}
    assert f.confirmed_by == ["grype"]
    assert f.aliases == ["CVE-2026-66066"]
    assert f.match_basis == MatchBasis.PURL
    assert f.finding_id == finding_id("grype", f.purl, "GHSA-xr9x-r78c-5hrm", [])


def test_no_fix_match_has_empty_fixed_versions(raw: dict[str, Any]) -> None:
    f = parse_grype(raw, "raw/grype.json", SHA)[0][4]
    assert f.fixed_versions == []


def test_aliases_exclude_own_id_and_are_sorted(raw: dict[str, Any]) -> None:
    f = parse_grype(raw, "raw/grype.json", SHA)[0][5]
    assert f.advisory_id == "CVE-2099-0001"
    assert f.aliases == ["GHSA-cpe0-0000-0002"]


def test_cpe_match_basis(raw: dict[str, Any]) -> None:
    assert parse_grype(raw, "raw/grype.json", SHA)[0][5].match_basis == MatchBasis.CPE


def test_unrecognised_match_type_is_unknown(raw: dict[str, Any]) -> None:
    raw["matches"][0]["matchDetails"][0]["type"] = "fuzzy"
    assert parse_grype(raw, "raw/grype.json", SHA)[0][0].match_basis == MatchBasis.UNKNOWN


def test_evidence_points_into_raw_file(raw: dict[str, Any]) -> None:
    findings, evidence = parse_grype(raw, "raw/grype.json", SHA)
    e = evidence[2]
    assert e.evidence_id == f"ev-grype-2-{SHA[:8]}"
    assert (e.tool, e.tool_version) == ("grype", "0.122.1")
    assert (e.file, e.pointer, e.sha256) == ("raw/grype.json", "/matches/2", SHA)
    assert e.url == "https://github.com/advisories/GHSA-2j26-frm8-cmj9"
    assert findings[2].evidence_ids == [e.evidence_id]


def test_parse_is_deterministic(raw: dict[str, Any]) -> None:
    assert parse_grype(raw, "r", SHA) == parse_grype(raw, "r", SHA)


def test_missing_purl_falls_back_without_inventing_version(raw: dict[str, Any]) -> None:
    del raw["matches"][0]["artifact"]["purl"]
    del raw["matches"][0]["artifact"]["version"]
    f = parse_grype(raw, "r", SHA)[0][0]
    assert f.purl == f"pkg:gem/activestorage@{UNKNOWN}"


def test_missing_descriptor_version_is_unknown(raw: dict[str, Any]) -> None:
    del raw["descriptor"]
    assert parse_grype(raw, "r", SHA)[1][0].tool_version == UNKNOWN


def test_empty_matches_yield_empty_lists() -> None:
    assert parse_grype({"matches": []}, "r", SHA) == ([], [])


def test_run_grype_builds_docker_command_and_writes_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sbom = tmp_path / "in" / "sbom.cdx.json"
    sbom.parent.mkdir()
    sbom.write_text("{}")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        assert kwargs["timeout"] == 600
        return subprocess.CompletedProcess(argv, 0, stdout='{"matches": []}', stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = run_grype(sbom, tmp_path / "out")
    assert out == tmp_path / "out" / "raw" / "grype.json"
    assert out.read_text() == '{"matches": []}'
    argv = calls[0]
    assert argv[:3] == ["docker", "run", "--rm"]
    assert argv[argv.index("--network") + 1] == "host"
    assert argv[argv.index("--entrypoint") + 1] == "/grype"
    assert f"{sbom.parent}:/in:ro" in argv
    assert "guardian-grype-db:/root/.cache/grype" in argv
    assert "GRYPE_DB_CACHE_DIR=/root/.cache/grype" in argv
    assert "GRYPE_DB_AUTO_UPDATE=false" in argv
    assert argv[-4:] == [grype.GRYPE_IMAGE, "sbom:/in/sbom.cdx.json", "-o", "json"]


def test_grype_image_is_pinned_by_digest() -> None:
    assert grype.GRYPE_IMAGE.startswith("anchore/grype@sha256:")


def test_run_grype_raises_with_stderr_tail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}")

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="x" * 5000 + "boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(GrypeError, match="boom"):
        run_grype(sbom, tmp_path / "out")
    assert not (tmp_path / "out" / "raw" / "grype.json").exists()
