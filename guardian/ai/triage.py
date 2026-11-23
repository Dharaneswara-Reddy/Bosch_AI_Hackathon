"""Triage agent (deterministic, no LLM).

Selects the top-N findings by risk and turns each into an ``EvidencePack``:
the finding, its component, its dependency path and its evidence records,
copied from tool output. Later agents see only these packs.
"""

from __future__ import annotations

from typing import Any

from guardian.ai.context import ReviewContext, as_text
from guardian.ai.state import EvidencePack
from guardian.ai.validator import purl_name_version
from guardian.models import Finding


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


def triage(ctx: ReviewContext, top_n: int) -> list[EvidencePack]:
    return [build_pack(ctx, finding) for finding in ctx.top_findings(top_n)]
