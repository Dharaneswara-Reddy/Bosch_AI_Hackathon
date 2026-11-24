"""Triage agent (deterministic, no LLM).

Groups findings by package (version and platform qualifiers ignored), keeps every
group whose highest risk level reaches the policy minimum, and turns each finding into
an ``EvidencePack``: the finding, its component, its dependency path and its evidence
records, copied from tool output. Later agents see only these packs.
"""

from __future__ import annotations

from typing import Any

from guardian.ai.context import RISK_ORDER, ReviewContext, as_text
from guardian.ai.state import EvidencePack, PackageGroup
from guardian.ai.validator import purl_name_version
from guardian.models import Finding
from guardian.relevance import rank as relevance_rank


def _evidence_view(ctx: ReviewContext, evidence_id: str) -> dict[str, Any]:
    record = ctx.evidence.get(evidence_id)
    if record is None:
        return {"evidence_id": evidence_id, "status": "UNKNOWN"}
    return {
        "evidence_id": evidence_id,
        "tool": record.tool,
        "file": record.file,
        "pointer": record.pointer,
        "url": record.url,
    }


def _path_names(ctx: ReviewContext, finding: Finding) -> list[str]:
    names = []
    for component_id in finding.dependency_path:
        component = ctx.component(component_id)
        names.append(f"{component.name}@{component.version}" if component else component_id)
    return names


def _direct_dependency(ctx: ReviewContext, finding: Finding) -> str | None:
    """The app's direct dependency that pulls the finding in (path: app -> direct -> ...)."""
    if len(finding.dependency_path) < 2:
        return None
    component = ctx.component(finding.dependency_path[1])
    return component.name if component else purl_name_version(finding.dependency_path[1])[0]


def build_pack(ctx: ReviewContext, finding: Finding) -> EvidencePack:
    component = ctx.component(finding.component_id)
    name, version = purl_name_version(finding.purl)
    return EvidencePack(
        pack_id=f"pack-{finding.finding_id}",
        finding_id=finding.finding_id,
        kind=as_text(finding.kind),
        package=component.name if component else name,
        version=component.version if component else (version or "UNKNOWN"),
        purl=finding.purl,
        advisory_id=finding.advisory_id,
        aliases=list(finding.aliases),
        anomaly_type=finding.anomaly_type,
        source_severity=as_text(finding.source_severity),
        fixed_versions=list(finding.fixed_versions),
        dependency_path=_path_names(ctx, finding),
        direct_dependency=_direct_dependency(ctx, finding),
        path_count=finding.path_count,
        risk_level=as_text(finding.risk_level),
        risk_rule_id=finding.risk_rule_id,
        state=as_text(finding.state),
        evidence=[_evidence_view(ctx, e) for e in finding.evidence_ids],
        evidence_ids=list(finding.evidence_ids),
    )


LEVELS = tuple(RISK_ORDER)


def package_key(purl: str) -> str:
    """'pkg:gem/nokogiri@1.19.0-aarch64-linux-gnu?platform=x' -> 'gem:nokogiri'."""
    ecosystem = purl.removeprefix("pkg:").split("/", 1)[0].lower()
    return f"{ecosystem}:{purl_name_version(purl)[0]}"


def _risk_rank(finding: Finding) -> int:
    return RISK_ORDER.get(as_text(finding.risk_level).lower(), len(RISK_ORDER))


def _finding_order(finding: Finding) -> tuple[int, int, str]:
    return relevance_rank(finding), _risk_rank(finding), finding.finding_id


def triage(
    ctx: ReviewContext, min_risk: str, max_groups: int
) -> tuple[list[PackageGroup], list[EvidencePack]]:
    """Package groups at or above ``min_risk`` (highest risk first, capped) and their packs."""
    if min_risk not in RISK_ORDER:
        raise ValueError(
            f"GUARDIAN_AI_MIN_RISK must be one of {', '.join(RISK_ORDER)}, not '{min_risk}'."
        )
    members: dict[str, list[Finding]] = {}
    for finding in sorted(ctx.findings.values(), key=_finding_order):
        members.setdefault(package_key(finding.purl), []).append(finding)
    ranked = sorted((min(_risk_rank(f) for f in found), key) for key, found in members.items())
    groups = [
        PackageGroup(
            group_id=key,
            package=key.split(":", 1)[1],
            top_risk=LEVELS[best],
            finding_ids=[f.finding_id for f in members[key]],
        )
        for best, key in ranked
        if best <= RISK_ORDER[min_risk]
    ][:max_groups]
    packs = [build_pack(ctx, ctx.findings[fid]) for g in groups for fid in g.finding_ids]
    return groups, packs
