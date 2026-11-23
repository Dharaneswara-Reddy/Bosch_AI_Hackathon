from __future__ import annotations

import pytest

from guardian.ai.validator import validate
from tests.ai.factories import GRYPE_URL, claim, make_context


def _check(text: str, ids: list[str], kind: str = "evidence") -> tuple[bool, str]:
    result = validate(claim(text, ids, kind), make_context())
    return result.validated, result.rejected_reason or ""


def test_real_citation_is_accepted() -> None:
    ok, reason = _check(
        "jsonwebtoken 0.4.0 reaches the app via express-jwt 0.1.3 and is affected by CVE-2015-9235 "
        "(GHSA-c7hr-j4mj-j2w6); version 4.2.2 fixes it. Critical risk under rule R-CVE-1.",
        ["ev-grype-0001"],
    )
    assert ok, reason


def test_fabricated_cve_is_rejected() -> None:
    ok, reason = _check("jsonwebtoken 0.4.0 is also affected by CVE-2026-31337.", ["ev-grype-0001"])
    assert not ok
    assert "CVE-2026-31337 is not in the cited findings" in reason


def test_unknown_evidence_id_is_rejected() -> None:
    ok, reason = _check("jsonwebtoken 0.4.0 is affected by CVE-2015-9235.", ["ev-does-not-exist"])
    assert not ok
    assert "evidence ID not found" in reason


def test_wrong_version_is_rejected() -> None:
    ok, reason = _check("jsonwebtoken 0.5.0 is affected by CVE-2015-9235.", ["ev-grype-0001"])
    assert not ok
    assert "0.5.0" in reason


def test_wrong_version_in_at_form_is_rejected() -> None:
    ok, reason = _check("jsonwebtoken@0.9.1 is affected.", ["ev-grype-0001"])
    assert not ok
    assert "jsonwebtoken@0.9.1" in reason


def test_uncited_package_is_rejected() -> None:
    ok, reason = _check("left-pad was added in this commit.", ["ev-grype-0001"])
    assert not ok
    assert "left-pad is not in the cited findings" in reason


def test_file_path_not_in_evidence_is_rejected() -> None:
    ok, reason = _check("The flaw is triggered in routes/login.ts.", ["ev-grype-0001"])
    assert not ok
    assert "routes/login.ts" in reason


def test_file_path_in_evidence_is_accepted() -> None:
    ok, reason = _check("left-pad 1.3.0 was added in package.json.", ["ev-diff-0001"])
    assert ok, reason


def test_url_must_come_from_evidence() -> None:
    ok, _ = _check(f"Advisory: {GRYPE_URL}", ["ev-grype-0001"])
    assert ok
    ok, reason = _check("Advisory: https://evil.example/cve", ["ev-grype-0001"])
    assert not ok
    assert "https://evil.example/cve" in reason


def test_evidence_claim_without_citation_is_rejected() -> None:
    ok, reason = _check("Several packages are outdated.", [])
    assert not ok
    assert "cites no evidence" in reason


def test_inference_without_identifiers_is_accepted() -> None:
    ok, reason = _check(
        "Old JWT libraries are a common way to bypass authentication.",
        ["ev-grype-0001"],
        kind="inference",
    )
    assert ok, reason


@pytest.mark.parametrize(
    "text",
    [
        "jsonwebtoken is safe to ignore.",
        "This dependency is not vulnerable in practice.",
        "The project has no known vulnerabilities.",
        "Everything looks secure.",
    ],
)
def test_safety_verdicts_are_rejected(text: str) -> None:
    ok, reason = _check(text, ["ev-grype-0001"])
    assert not ok
    assert "never reports safe" in reason


def test_downgraded_severity_is_rejected() -> None:
    ok, reason = _check("jsonwebtoken 0.4.0 is a low risk issue.", ["ev-grype-0001"])
    assert not ok
    assert "severity/risk 'low'" in reason


def test_npm_names_with_dots_are_not_treated_as_paths() -> None:
    ok, reason = _check("unsafe install script detected for left-pad 1.3.0.", ["ev-diff-0001"])
    assert ok, reason


def test_four_part_versions_are_checked() -> None:
    ok, reason = _check("jsonwebtoken 4.2.2.9 fixes it.", ["ev-grype-0001"])
    assert not ok
    assert "4.2.2.9" in reason


def test_package_known_only_from_finding_purl_is_checked() -> None:
    ok, reason = _check("left-pad 9.9.9 was added.", ["ev-diff-0001"])
    assert not ok
    assert "9.9.9" in reason
