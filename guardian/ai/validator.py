"""Claim validator: plain code, no AI.

A claim is accepted only when every concrete identifier in its text is backed
by the findings and evidence it cites. Checks, in order:

1. every cited ID exists in this run (evidence ID or finding ID);
2. every CVE/GHSA/OSV/MAL/... ID in the text belongs to a cited finding;
3. every package name and version in the text matches a cited component
   (or a fixed version of a cited finding);
4. every file path and URL in the text appears in the cited evidence;
5. ``kind="evidence"`` claims cite at least one record.

Guardrails added on top of the design's five checks:
6. a claim may not declare anything safe / not affected;
7. a severity or risk level in the text must match a cited finding.

Rejected claims are kept with every failing reason.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from guardian.ai.context import ReviewContext, as_text
from guardian.models import AgentClaim, Finding

ADVISORY_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|MAL-\d{4}-\d+|PYSEC-\d{4}-\d+|"
    r"GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+|OSV-\d{4}-\d+|GSD-\d{4}-\d+)\b",
    re.IGNORECASE,
)
URL = re.compile(r"https?://[^\s<>\"')\]]+")
PURL = re.compile(r"\bpkg:[a-z0-9.+-]+/[^\s,;)\]]+", re.IGNORECASE)
NAME_AT_VERSION = re.compile(r"(?<![\w/.-])((?:@[\w.-]+/)?[\w][\w.-]*)@v?(\d[\w.+-]*)")
STRICT_VERSION = re.compile(r"(?<![\w.@-])v?(\d+(?:\.\d+){2,}(?:-[0-9A-Za-z.-]+)?)(?![\w.])")
FILE_PATH = re.compile(
    r"(?<![\w@/.:-])((?:\.?[\w-]+/)*(?:Dockerfile[\w.-]*|[\w.-]+\.(?:json|ya?ml|lock|js|mjs|cjs|ts|py|toml|"
    r"xml|txt|cfg|ini|gradle|mod|sum|patch|sh|csproj|gemspec)))(?![\w/-])"
)
SAFETY_CLAIM = re.compile(
    r"(?i)\b(?:(?:is|are|be|being|looks?|appears?|seems?|considered|marked?|deemed|remains?)\s+"
    r"(?:completely\s+|totally\s+|now\s+|fully\s+)?(?:safe|secure|harmless|risk[- ]free|clean)\b|"
    r"no\s+(?:known\s+)?(?:risks?|vulnerabilit(?:y|ies)|issues?)\b|not\s+(?:vulnerable|affected|exploitable)\b|"
    r"safe\s+to\s+(?:ignore|use|deploy))"
)
LEVEL = r"(critical|high|medium|moderate|low)"
SEVERITY_MENTION = re.compile(
    rf"(?i)\b{LEVEL}[- ](?:risk|severity|priority)\b"
    rf"|\b(?:risk|severity|priority)(?:\s+level)?\s+(?:is\s+|of\s+|=\s*)?{LEVEL}\b"
)
SEVERITY_ALIASES = {"moderate": "medium"}
VERSION_AFTER_NAME = r"(?:v(?:ersion)?\s*)?(\d+\.\d+(?:\.\d+)*[\w.+-]*)"

NOT_REACHED = re.compile(
    r"(?i)\b(?:not|never)\s+(?:directly\s+)?(?:reachable|reached|imported)\b"
    r"|\b(?:does|do)\s+not\s+(?:import|require|call|load)\b"
)
REACHED = re.compile(
    r"(?i)\b(?:is|are)\s+(?:directly\s+)?(?:reachable|reached)\b"
    r"|\b(?:application|app|code|project)\s+(?:directly\s+)?(?:imports|requires|calls|loads)\b"
    r"|\bimported\s+(?:by|in|at|from)\b"
)
DEV_ONLY = re.compile(r"(?i)\bdev(?:elopment)?(?:-only|\s+only)?\s+dependenc(?:y|ies)\b")
PRODUCTION = re.compile(r"(?i)\bproduction\s+dependenc(?:y|ies)\b")
NOT_EXPLOITED = re.compile(r"(?i)\bnot\s+(?:known\s+to\s+be\s+|actively\s+)?exploited\b")
EXPLOITED = re.compile(r"(?i)\b(?:actively|known|being)\s+exploited\b|\bCISA\s+KEV\b")

Check = Callable[[AgentClaim, ReviewContext, list[Finding]], list[str]]


def purl_name_version(purl: str) -> tuple[str, str]:
    """'pkg:npm/%40scope/name@1.0?q' -> ('@scope/name', '1.0'); missing version -> ''."""
    body = purl.removeprefix("pkg:").split("?")[0].split("#")[0].replace("%40", "@")
    body = body.split("/", 1)[1] if "/" in body else body
    name, sep, version = body.rpartition("@")
    if not sep or not name:
        return body.rsplit("/", 1)[-1], ""
    return name.rsplit("/", 1)[-1] if not name.startswith("@") else name, version


def _allowed_versions(ctx: ReviewContext, cited: list[Finding]) -> dict[str, set[str]]:
    """Package name -> versions that the cited findings legitimately talk about."""
    allowed: dict[str, set[str]] = {}
    for finding in cited:
        name, version = purl_name_version(finding.purl)
        allowed.setdefault(name.lower(), set()).update({version, *finding.fixed_versions} - {""})
        for component_id in [finding.component_id, *finding.dependency_path]:
            component = ctx.component(component_id)
            if component is not None:
                allowed.setdefault(component.name.lower(), set()).add(component.version)
    return allowed


def check_ids_exist(claim: AgentClaim, ctx: ReviewContext, cited: list[Finding]) -> list[str]:
    missing = [i for i in claim.evidence_ids if i not in ctx.evidence and i not in ctx.findings]
    return [f"evidence ID not found in this run: {', '.join(missing)}"] if missing else []


def check_evidence_kind(claim: AgentClaim, ctx: ReviewContext, cited: list[Finding]) -> list[str]:
    if as_text(claim.kind) == "evidence" and not claim.evidence_ids:
        return ["evidence claim cites no evidence"]
    return []


def check_advisories(claim: AgentClaim, ctx: ReviewContext, cited: list[Finding]) -> list[str]:
    known = {a.lower() for f in cited for a in [f.advisory_id or "", *f.aliases] if a}
    unknown = sorted(
        {m.group(0).upper() for m in ADVISORY_ID.finditer(claim.text)} - {k.upper() for k in known}
    )
    return [f"advisory {a} is not in the cited findings" for a in unknown]


def check_packages(claim: AgentClaim, ctx: ReviewContext, cited: list[Finding]) -> list[str]:
    allowed = _allowed_versions(ctx, cited)
    every_version = {v for versions in allowed.values() for v in versions}
    text = PURL.sub(" ", URL.sub(" ", claim.text))
    reasons = [
        f"package {n}@{v} does not match a cited component"
        for n, v in NAME_AT_VERSION.findall(text)
        if v not in allowed.get(n.lower(), set())
    ]
    reasons += _check_name_then_version(text, allowed)
    reasons += [
        f"version {v} does not match a cited component"
        for v in sorted({m.group(1) for m in STRICT_VERSION.finditer(text)} - every_version)
    ]
    reasons += _check_uncited_names(text, ctx, allowed)
    return sorted(set(reasons))


def _check_name_then_version(text: str, allowed: dict[str, set[str]]) -> list[str]:
    reasons: list[str] = []
    for name, versions in allowed.items():
        pattern = rf"(?i)(?<![\w@/.-]){re.escape(name)}\s+{VERSION_AFTER_NAME}"
        for match in re.finditer(pattern, text):
            version = match.group(1).rstrip(".,;")
            if version not in versions:
                reasons.append(
                    f"package {name} version {version} does not match the cited component"
                )
    return reasons


def _check_uncited_names(text: str, ctx: ReviewContext, allowed: dict[str, set[str]]) -> list[str]:
    """Distinctive names of run components (e.g. 'express-jwt') may only appear if cited."""
    reasons: list[str] = []
    lowered = text.lower()
    for component in ctx.components.values():
        name = component.name.lower()
        distinctive = len(name) >= 4 and re.search(r"[-/@._0-9]", name) is not None
        mentioned = name in lowered and re.search(
            rf"(?<![\w@/.-]){re.escape(name)}(?![\w/-])", lowered
        )
        if distinctive and name not in allowed and mentioned:
            reasons.append(f"package {component.name} is not in the cited findings")
    return reasons


def check_paths_and_urls(
    claim: AgentClaim,
    ctx: ReviewContext,
    cited: list[Finding],
    allowed_paths: frozenset[str] = frozenset(),
) -> list[str]:
    records = [ctx.evidence[i] for i in claim.evidence_ids if i in ctx.evidence]
    records += [ctx.evidence[i] for f in cited for i in f.evidence_ids if i in ctx.evidence]
    urls = {(r.url or "").rstrip("/") for r in records}
    haystack = " ".join(f"{r.file} {r.pointer} {r.url or ''}" for r in records)
    names = {c.name.lower() for c in ctx.components.values()}
    reasons = [
        f"URL {u} is not in the cited evidence"
        for u in sorted(
            {m.group(0).rstrip(".,;:").rstrip("/") for m in URL.finditer(claim.text)} - urls
        )
    ]
    text = PURL.sub(" ", URL.sub(" ", claim.text))
    for path in sorted({m.group(1) for m in FILE_PATH.finditer(text)}):
        known = (
            path.lower() in names or path in haystack or path.rsplit("/", 1)[-1] in allowed_paths
        )
        if not known:
            reasons.append(f"file path {path} is not in the cited evidence")
    return reasons


def check_no_safety_verdict(
    claim: AgentClaim, ctx: ReviewContext, cited: list[Finding]
) -> list[str]:
    match = SAFETY_CLAIM.search(claim.text)
    return (
        [f"declares safety ('{match.group(0)}'); the Guardian never reports safe"] if match else []
    )


def _signal_values(cited: list[Finding], name: str) -> set[str]:
    return {s.value for f in cited if f.relevance for s in f.relevance.signals if s.name == name}


def _relevance_rules(text: str) -> list[tuple[str, str, set[str], str]]:
    """(signal, required values, matched phrase) for every relevance statement in the text."""
    rules: list[tuple[str, str, set[str], str]] = []
    if match := NOT_REACHED.search(text):
        rules.append(("reachability", "not reached", {"not_detected"}, match.group(0)))
    elif match := REACHED.search(text):
        rules.append(("reachability", "reached", {"confirmed"}, match.group(0)))
    if match := DEV_ONLY.search(text):
        rules.append(("dependency_scope", "dev-only", {"development"}, match.group(0)))
    if match := PRODUCTION.search(text):
        rules.append(("dependency_scope", "production", {"production"}, match.group(0)))
    if match := NOT_EXPLOITED.search(text):
        rules.append(("known_exploited", "not exploited", {"no"}, match.group(0)))
    elif match := EXPLOITED.search(text):
        rules.append(("known_exploited", "exploited", {"yes"}, match.group(0)))
    return rules


def check_relevance_claims(
    claim: AgentClaim, ctx: ReviewContext, cited: list[Finding]
) -> list[str]:
    """Statements about reachability, scope or exploitation must match the recorded signal."""
    reasons = []
    for signal, _meaning, allowed, phrase in _relevance_rules(claim.text):
        recorded = _signal_values(cited, signal)
        if not recorded & allowed:
            shown = ", ".join(sorted(recorded)) or "not recorded"
            reasons.append(f"says '{phrase}' but recorded {signal} is {shown}")
    return reasons


def check_severity(claim: AgentClaim, ctx: ReviewContext, cited: list[Finding]) -> list[str]:
    levels = {as_text(v).lower() for f in cited for v in (f.risk_level, f.source_severity)}
    reasons = []
    for match in SEVERITY_MENTION.finditer(claim.text):
        level = (match.group(1) or match.group(2)).lower()
        if SEVERITY_ALIASES.get(level, level) not in {SEVERITY_ALIASES.get(x, x) for x in levels}:
            reasons.append(f"severity/risk '{level}' does not match the cited findings")
    return reasons


CHECKS: tuple[Check, ...] = (
    check_ids_exist,
    check_advisories,
    check_packages,
    check_evidence_kind,
    check_no_safety_verdict,
    check_severity,
    check_relevance_claims,
)


def validate(
    claim: AgentClaim, ctx: ReviewContext, allowed_paths: frozenset[str] = frozenset()
) -> AgentClaim:
    """Return a copy of the claim with ``validated`` and ``rejected_reason`` set.

    ``allowed_paths`` names extra file names a claim may mention (used only for fix
    proposals, which legitimately refer to manifests and lockfiles).
    """
    cited = ctx.findings_citing(claim.evidence_ids)
    reasons = check_paths_and_urls(claim, ctx, cited, allowed_paths)
    for check in CHECKS:
        reasons.extend(check(claim, ctx, cited))
    if reasons:
        return claim.model_copy(update={"validated": False, "rejected_reason": "; ".join(reasons)})
    return claim.model_copy(update={"validated": True, "rejected_reason": None})
