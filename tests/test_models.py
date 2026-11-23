import pytest
from pydantic import ValidationError

from guardian.models import (
    UNKNOWN,
    Evidence,
    Finding,
    FindingKind,
    MatchBasis,
    finding_id,
)


def test_finding_id_is_stable_for_same_identity() -> None:
    a = finding_id("grype", "pkg:npm/jsonwebtoken@0.4.0", "CVE-2015-9235", ["app", "express-jwt"])
    b = finding_id("grype", "pkg:npm/jsonwebtoken@0.4.0", "CVE-2015-9235", ["app", "express-jwt"])
    assert a == b


def test_finding_id_changes_when_path_changes() -> None:
    a = finding_id("grype", "pkg:npm/x@1", "CVE-1", ["app"])
    b = finding_id("grype", "pkg:npm/x@1", "CVE-1", ["app", "y"])
    assert a != b


def test_vulnerability_finding_defaults_unknown_and_empty() -> None:
    f = Finding(
        finding_id="f1",
        kind=FindingKind.VULNERABILITY,
        component_id="pkg:npm/x@1",
        purl="pkg:npm/x@1",
        advisory_id="CVE-1",
    )
    assert f.source_severity == UNKNOWN
    assert f.confirmed_by == []
    assert f.match_basis == MatchBasis.UNKNOWN


def test_finding_rejects_unknown_kind() -> None:
    with pytest.raises(ValidationError):
        Finding(finding_id="f1", kind="banana", component_id="c", purl="p")  # type: ignore[arg-type]


def test_evidence_requires_sha256() -> None:
    with pytest.raises(ValidationError):
        Evidence(evidence_id="e1", tool="grype", tool_version="0.122.1", file="raw/grype.json")  # type: ignore[call-arg]
