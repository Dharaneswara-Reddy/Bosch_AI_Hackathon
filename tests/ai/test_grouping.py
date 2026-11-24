from __future__ import annotations

import pytest

from guardian.ai.context import ReviewContext
from guardian.ai.triage import package_key, triage
from guardian.models import Finding, FindingKind, RiskLevel
from tests.ai.factories import make_context


def _finding(fid: str, purl: str, level: RiskLevel, kind: FindingKind = FindingKind.VULNERABILITY):
    return Finding(
        finding_id=fid,
        kind=kind,
        component_id=purl,
        purl=purl,
        evidence_ids=["ev-grype-0001"],
        risk_level=level,
    )


def _ctx(*findings: Finding) -> ReviewContext:
    base = make_context()
    return ReviewContext.build(findings, base.evidence.values(), base.components.values())


@pytest.mark.parametrize(
    ("purl", "key"),
    [
        ("pkg:gem/nokogiri@1.19.0", "gem:nokogiri"),
        ("pkg:gem/nokogiri@1.19.0-aarch64-linux-gnu?platform=aarch64-linux-gnu", "gem:nokogiri"),
        ("pkg:npm/%40scope/name@2.0.0", "npm:@scope/name"),
        ("pkg:npm/name@2.0.0", "npm:name"),
        ("pkg:pypi/name@2.0.0", "pypi:name"),
    ],
)
def test_package_key_ignores_version_and_qualifiers(purl: str, key: str) -> None:
    assert package_key(purl) == key


def test_platform_builds_share_one_group() -> None:
    ctx = _ctx(
        _finding("f1", "pkg:gem/nokogiri@1.19.0", RiskLevel.HIGH),
        _finding("f2", "pkg:gem/nokogiri@1.19.0-aarch64-linux-gnu", RiskLevel.MEDIUM),
    )
    groups, packs = triage(ctx, "medium", 200)
    assert [(g.group_id, g.finding_ids, g.top_risk) for g in groups] == [
        ("gem:nokogiri", ["f1", "f2"], "high")
    ]
    assert {p.finding_id for p in packs} == {"f1", "f2"}


def test_groups_below_the_policy_minimum_are_left_out() -> None:
    ctx = _ctx(
        _finding("f1", "pkg:npm/a@1.0.0", RiskLevel.LOW),
        _finding("f2", "pkg:npm/b@1.0.0", RiskLevel.MEDIUM),
        _finding("f3", "pkg:npm/b@2.0.0", RiskLevel.LOW),
    )
    groups, _ = triage(ctx, "medium", 200)
    assert [g.group_id for g in groups] == ["npm:b"]
    assert groups[0].finding_ids == ["f2", "f3"]
    assert [g.group_id for g in triage(ctx, "low", 200)[0]] == ["npm:b", "npm:a"]


def test_groups_are_ordered_by_highest_risk_and_capped() -> None:
    ctx = _ctx(
        _finding("f1", "pkg:npm/a@1.0.0", RiskLevel.MEDIUM),
        _finding("f2", "pkg:npm/b@1.0.0", RiskLevel.CRITICAL),
        _finding("f3", "pkg:npm/c@1.0.0", RiskLevel.HIGH),
    )
    assert [g.group_id for g in triage(ctx, "medium", 200)[0]] == ["npm:b", "npm:c", "npm:a"]
    capped, packs = triage(ctx, "medium", 2)
    assert [g.group_id for g in capped] == ["npm:b", "npm:c"]
    assert {p.finding_id for p in packs} == {"f2", "f3"}


def test_anomalies_join_the_group_of_their_package() -> None:
    ctx = _ctx(
        _finding("f1", "pkg:npm/a@1.0.0", RiskLevel.HIGH),
        _finding("f2", "pkg:npm/a@1.0.0", RiskLevel.MEDIUM, FindingKind.ANOMALY),
    )
    groups, packs = triage(ctx, "medium", 200)
    assert len(groups) == 1 and {p.kind for p in packs} == {"vulnerability", "anomaly"}


def test_unknown_policy_minimum_is_rejected() -> None:
    with pytest.raises(ValueError, match="GUARDIAN_AI_MIN_RISK"):
        triage(_ctx(), "severe", 10)
