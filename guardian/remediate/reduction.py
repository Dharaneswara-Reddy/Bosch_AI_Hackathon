"""What a fix is expected to remove, computed from the scan before anything is applied."""

from pydantic import BaseModel

from guardian.models import Finding, FindingKind, RemediationProposal, RunResult
from guardian.remediate.candidates import version_key


class ExpectedReduction(BaseModel):
    fixes: dict[str, int]
    finding_ids: list[str]
    advisories: list[str]
    remaining_on_package: int


def _fixed_by(finding: Finding, target: str) -> bool:
    target_key = version_key(target)
    same_line = [v for v in finding.fixed_versions if version_key(v)[:1] == target_key[:1]]
    return any(version_key(v) <= target_key for v in same_line or finding.fixed_versions)


def expected_reduction(proposal: RemediationProposal, run: RunResult) -> ExpectedReduction | None:
    anchor = next((f for f in run.findings if f.finding_id == proposal.finding_id), None)
    target = proposal.target_version
    if anchor is None or not target or anchor.kind is not FindingKind.VULNERABILITY:
        return None
    on_package = [
        f for f in run.findings
        if f.kind is FindingKind.VULNERABILITY and f.component_id == anchor.component_id
    ]
    fixed = [f for f in on_package if _fixed_by(f, target)]
    levels = [f.risk_level.value for f in fixed]
    return ExpectedReduction(
        fixes={level: levels.count(level) for level in dict.fromkeys(levels)},
        finding_ids=[f.finding_id for f in fixed],
        advisories=sorted({f.advisory_id for f in fixed if f.advisory_id}),
        remaining_on_package=len(on_package) - len(fixed),
    )
