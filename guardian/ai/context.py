"""Read-only view of one run, used by the AI steps and the validator.

The context is the only source of facts: findings, evidence records and
components produced by tools. Nothing the model says is ever added to it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from guardian.models import Component, Evidence, Finding

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def as_text(value: object) -> str:
    """Enum-safe string conversion (P5's models may use str enums)."""
    if isinstance(value, Enum):
        return str(value.value)
    return "" if value is None else str(value)


@dataclass(frozen=True)
class ReviewContext:
    findings: dict[str, Finding]
    evidence: dict[str, Evidence]
    components: dict[str, Component]
    project_text: str = ""
    _by_evidence: dict[str, list[Finding]] = field(default_factory=dict, repr=False)

    @classmethod
    def build(
        cls,
        findings: Iterable[Finding],
        evidence: Iterable[Evidence],
        components: Iterable[Component],
        project_text: str = "",
    ) -> ReviewContext:
        finding_map = {f.finding_id: f for f in findings}
        by_evidence: dict[str, list[Finding]] = {}
        for finding in finding_map.values():
            for evidence_id in finding.evidence_ids:
                by_evidence.setdefault(evidence_id, []).append(finding)
        return cls(
            findings=finding_map,
            evidence={e.evidence_id: e for e in evidence},
            components={c.component_id: c for c in components},
            project_text=project_text,
            _by_evidence=by_evidence,
        )

    def findings_citing(self, evidence_ids: Iterable[str]) -> list[Finding]:
        """Findings backed by any of the given evidence IDs (finding IDs are accepted too)."""
        seen: dict[str, Finding] = {}
        for evidence_id in evidence_ids:
            for finding in self._by_evidence.get(evidence_id, []):
                seen[finding.finding_id] = finding
            if evidence_id in self.findings:
                seen[evidence_id] = self.findings[evidence_id]
        return list(seen.values())

    def component(self, component_id: str) -> Component | None:
        return self.components.get(component_id)

    def top_findings(self, n: int) -> list[Finding]:
        """Deterministic top-N by risk level, then finding ID."""

        def key(f: Finding) -> tuple[int, str]:
            return RISK_ORDER.get(as_text(f.risk_level).lower(), 4), f.finding_id

        return sorted(self.findings.values(), key=key)[:n]
