"""Relevance analysis (code only): does this vulnerability actually matter for this app?

For each vulnerability or malicious-package finding, record evidence-backed signals
and derive a verdict. The verdict never says "safe" or "not affected": without
positive proof, missing data makes the verdict ``unknown``.

Verdict rules, first match wins:
  1. malicious package                                   -> relevant
  2. installed version not confirmed inside the range    -> unknown
  3. listed as known exploited (CISA KEV)                -> relevant
  4. dev-only dependency                                 -> low_relevance
  5. application imports it (or the dependency that pulls it in) -> relevant
  6. production dependency                               -> likely_relevant
  7. otherwise                                           -> unknown
"""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from guardian.models import (
    Component,
    Evidence,
    Finding,
    FindingKind,
    MatchBasis,
    Reachability,
    Relevance,
    RelevanceSignal,
    RelevanceVerdict,
)
from guardian.reachability import ReachabilityScan

VERDICT_ORDER = {
    RelevanceVerdict.RELEVANT: 0,
    RelevanceVerdict.LIKELY_RELEVANT: 1,
    RelevanceVerdict.UNKNOWN: 2,
    RelevanceVerdict.LOW_RELEVANCE: 3,
}


class AdvisoryDetails(BaseModel):
    """Facts read from the scanner's raw output for one finding."""

    affected_range: str | None = None
    known_exploited: bool | None = None
    epss: float | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class PathFacts(BaseModel):
    component: Component | None = None
    labels: list[str] = Field(default_factory=list)
    introduced_by: str | None = None


def _pointer(document: Any, pointer: str) -> Any:
    for part in pointer.strip("/").split("/"):
        if isinstance(document, list) and part.isdigit() and int(part) < len(document):
            document = document[int(part)]
        elif isinstance(document, dict) and part in document:
            document = document[part]
        else:
            return None
    return document


def _from_grype_match(match: dict[str, Any], details: AdvisoryDetails) -> None:
    for item in match.get("matchDetails", []):
        found = item.get("found", {}) if isinstance(item, dict) else {}
        if found.get("versionConstraint") and details.affected_range is None:
            details.affected_range = str(found["versionConstraint"])
    vuln = match.get("vulnerability", {})
    if isinstance(vuln.get("knownExploited"), list):
        details.known_exploited = bool(vuln["knownExploited"])
    scores = [e.get("epss") for e in vuln.get("epss", []) if isinstance(e, dict)]
    if scores and isinstance(scores[0], int | float):
        details.epss = float(scores[0])


def advisory_details(
    finding: Finding, evidence: dict[str, Evidence], run_dir: Path, cache: dict[str, Any]
) -> AdvisoryDetails:
    details = AdvisoryDetails()
    for evidence_id in finding.evidence_ids:
        record = evidence.get(evidence_id)
        if record is None or record.tool != "grype":
            continue
        if record.file not in cache:
            path = run_dir / record.file
            cache[record.file] = json.loads(path.read_text("utf-8")) if path.is_file() else {}
        match = _pointer(cache[record.file], record.pointer)
        if isinstance(match, dict):
            _from_grype_match(match, details)
            details.evidence_ids.append(evidence_id)
    return details


def _version_signal(finding: Finding, facts: PathFacts, adv: AdvisoryDetails) -> RelevanceSignal:
    version = facts.component.version if facts.component else finding.purl.rsplit("@", 1)[-1]
    scanners = ", ".join(finding.confirmed_by) or "scanner"
    range_text = f" affected range {adv.affected_range}" if adv.affected_range else ""
    if finding.match_basis == MatchBasis.PURL:
        value, detail = "confirmed", f"installed {version} matched by package URL ({scanners});"
    elif finding.match_basis == MatchBasis.CPE:
        value, detail = "uncertain", f"installed {version} matched only by CPE ({scanners});"
    else:
        value, detail = "unknown", f"installed {version}; match basis not reported;"
    return RelevanceSignal(
        name="version_in_affected_range",
        value=value,
        detail=f"{detail}{range_text}".rstrip(";"),
        evidence_ids=list(adv.evidence_ids or finding.evidence_ids),
    )


def _scope_signals(finding: Finding, facts: PathFacts) -> list[RelevanceSignal]:
    dev = facts.component.dev if facts.component else None
    scope = "unknown" if dev is None else ("development" if dev else "production")
    depth = len(finding.dependency_path) - 1 if finding.dependency_path else 0
    position = "unknown" if depth <= 0 else ("direct" if depth == 1 else "transitive")
    chain = " -> ".join(facts.labels) if facts.labels else "path not resolved"
    return [
        RelevanceSignal(
            name="dependency_scope",
            value=scope,
            detail="from the lockfile's dev flag"
            if dev is not None
            else "lockfile does not record dev/production scope",
        ),
        RelevanceSignal(
            name="position", value=position, detail=f"depth {depth}: {chain}" if depth else chain
        ),
        RelevanceSignal(
            name="paths_into_app",
            value=str(finding.path_count or 0),
            detail="number of dependency paths from the application",
        ),
    ]


def _fix_signal(finding: Finding, facts: PathFacts) -> RelevanceSignal:
    if not finding.fixed_versions:
        return RelevanceSignal(
            name="fix_available",
            value="no",
            detail="no fixed version reported",
            evidence_ids=finding.evidence_ids,
        )
    current = facts.component.version.split(".")[0] if facts.component else ""
    majors = {v.lstrip("v").split(".")[0] for v in finding.fixed_versions}
    jump = "major version change" if current and current not in majors else "same major version"
    return RelevanceSignal(
        name="fix_available",
        value="yes",
        detail=f"fixed in {', '.join(finding.fixed_versions)} ({jump})",
        evidence_ids=finding.evidence_ids,
    )


def _reach_signal(
    facts: PathFacts, scan: ReachabilityScan | None, reach_evidence: dict[str, str]
) -> tuple[Reachability, RelevanceSignal]:
    names = [
        n for n in (facts.component.name if facts.component else None, facts.introduced_by) if n
    ]
    if scan is None or not scan.source_available:
        return Reachability.UNKNOWN, RelevanceSignal(
            name="reachability",
            value="unknown",
            detail="application source code was not available to check imports",
        )
    for name in names:
        hits = scan.hits.get(name, [])
        if hits:
            where = ", ".join(f"{h.file}:{h.line}" for h in hits[:3])
            via = "" if facts.component and name == facts.component.name else f" (via {name})"
            return Reachability.CONFIRMED, RelevanceSignal(
                name="reachability",
                value="confirmed",
                detail=f"imported at {where}{via}",
                evidence_ids=[reach_evidence[name]] if name in reach_evidence else [],
            )
    return Reachability.NOT_DETECTED, RelevanceSignal(
        name="reachability",
        value="not_detected",
        detail=f"no import of {' or '.join(names) or 'the package'} found in "
        f"{scan.source_files} source files (not proof it is unused)",
    )


def _exploit_signal(adv: AdvisoryDetails) -> RelevanceSignal:
    known = adv.known_exploited
    value = "unknown" if known is None else ("yes" if known else "no")
    epss = f"; EPSS {adv.epss:.3f}" if adv.epss is not None else ""
    detail = (
        "CISA known exploited vulnerabilities list"
        if value != "unknown"
        else "scanner output has no exploitation data"
    )
    return RelevanceSignal(
        name="known_exploited",
        value=value,
        detail=detail + epss,
        evidence_ids=adv.evidence_ids if value != "unknown" else [],
    )


def _verdict(finding: Finding, signals: dict[str, str], reach: Reachability) -> RelevanceVerdict:
    if finding.kind == FindingKind.MALICIOUS:
        return RelevanceVerdict.RELEVANT
    if signals["version_in_affected_range"] != "confirmed":
        return RelevanceVerdict.UNKNOWN
    if signals["known_exploited"] == "yes":
        return RelevanceVerdict.RELEVANT
    if signals["dependency_scope"] == "development":
        return RelevanceVerdict.LOW_RELEVANCE
    if reach == Reachability.CONFIRMED:
        return RelevanceVerdict.RELEVANT
    if signals["dependency_scope"] == "production":
        return RelevanceVerdict.LIKELY_RELEVANT
    return RelevanceVerdict.UNKNOWN


def _summary(verdict: RelevanceVerdict, signals: list[RelevanceSignal]) -> str:
    facts = "; ".join(f"{s.name.replace('_', ' ')}: {s.value}" for s in signals)
    return f"{verdict.value.replace('_', ' ')} ({facts})"


def assess(
    finding: Finding,
    facts: PathFacts,
    adv: AdvisoryDetails,
    scan: ReachabilityScan | None,
    reach_evidence: dict[str, str],
) -> Relevance:
    """Relevance for one vulnerability or malicious finding."""
    reach, reach_signal = _reach_signal(facts, scan, reach_evidence)
    signals = [
        _version_signal(finding, facts, adv),
        *_scope_signals(finding, facts),
        _fix_signal(finding, facts),
        reach_signal,
        _exploit_signal(adv),
    ]
    values = {s.name: s.value for s in signals}
    verdict = _verdict(finding, values, reach)
    return Relevance(
        verdict=verdict,
        reachability=reach,
        introduced_by=facts.introduced_by,
        path_labels=facts.labels,
        signals=signals,
        summary=_summary(verdict, signals),
    )


def path_facts(finding: Finding, nodes: dict[str, Component]) -> PathFacts:
    path = finding.dependency_path
    labels = [f"{nodes[c].name}@{nodes[c].version}" if c in nodes else c for c in path]
    introduced = None
    if len(path) >= 2:
        first = nodes.get(path[1])
        introduced = first.name if first else path[1]
    return PathFacts(
        component=nodes.get(finding.component_id), labels=labels, introduced_by=introduced
    )


def rank(finding: Finding) -> int:
    if finding.relevance is None:
        return len(VERDICT_ORDER)
    return VERDICT_ORDER[finding.relevance.verdict]
