"""Rule-based upgrade proposals: code only, so fixes work with the AI agents off."""

import re

from guardian.models import (
    Component,
    Finding,
    FindingKind,
    FixAction,
    RemediationProposal,
    RiskLevel,
    RunResult,
    Scope,
)

RISK_ORDER = {
    RiskLevel.CRITICAL: 4, RiskLevel.HIGH: 3, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 1,
    RiskLevel.UNKNOWN: 0,
}


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def _major(version: str) -> int | None:
    key = version_key(version)
    return key[0] if key else None


def _lowest_fix(current: str, fixed: list[str]) -> str:
    newer = [v for v in fixed if version_key(v) > version_key(current)] or fixed
    same_major = [v for v in newer if _major(v) == _major(current)]
    return min(same_major or newer, key=version_key)


def _fixable(node: Component) -> bool:
    return node.scope is Scope.DIRECT or (
        node.scope is Scope.TRANSITIVE and node.ecosystem == "npm")


def _upgradable(run: RunResult) -> dict[str, list[Finding]]:
    nodes = {node.component_id: node for node in run.graph.nodes}
    groups: dict[str, list[Finding]] = {}
    for finding in run.findings:
        node = nodes.get(finding.component_id)
        if (
            finding.kind is FindingKind.VULNERABILITY and finding.fixed_versions
            and node is not None and _fixable(node)
        ):
            groups.setdefault(node.component_id, []).append(finding)
    return groups


def _wording(
    component: Component, target: str, advisories: list[str]
) -> tuple[str, str, FixAction]:
    fixes = ", ".join(advisories) or "the finding"
    if component.scope is Scope.TRANSITIVE:
        return (
            f"Force {component.name} from {component.version} to {target}, the lowest "
            f"scanner-reported version that fixes {fixes}, with an npm override. If a newer "
            f"direct parent already depends on a fixed {component.name}, that parent is "
            "upgraded instead.",
            f"Remove the {component.name} override, or revert it to {component.version}.",
            FixAction.PIN_VERSION,
        )
    return (
        f"Upgrade {component.name} from {component.version} to {target}, the lowest "
        f"scanner-reported version that fixes {fixes}.",
        f"Revert {component.name} to {component.version}.",
        FixAction.UPGRADE,
    )


def _proposal(component: Component, findings: list[Finding]) -> RemediationProposal:
    target = max(
        (_lowest_fix(component.version, f.fixed_versions) for f in findings), key=version_key
    )
    top = max(findings, key=lambda f: RISK_ORDER[f.risk_level])
    advisories = sorted({f.advisory_id for f in findings if f.advisory_id})
    rationale, rollback, action = _wording(component, target, advisories)
    jump = _major(target) != _major(component.version)
    return RemediationProposal(
        proposal_id=f"rule-{top.finding_id}",
        finding_id=top.finding_id,
        action=action,
        target_version=target,
        rationale=rationale,
        rollback=rollback,
        breaking_change_risk="medium" if jump else "low",
        evidence_ids=list(dict.fromkeys(e for f in findings for e in f.evidence_ids)),
        validated=True,
    )


def rule_based_proposals(run: RunResult) -> list[RemediationProposal]:
    nodes = {node.component_id: node for node in run.graph.nodes}
    return [_proposal(nodes[cid], findings) for cid, findings in _upgradable(run).items()]


def merge_proposals(
    ai: list[RemediationProposal], rules: list[RemediationProposal]
) -> list[RemediationProposal]:
    usable = [p for p in ai if p.validated]
    covered = {p.finding_id for p in usable}
    return [*usable, *(p for p in rules if p.finding_id not in covered)]
