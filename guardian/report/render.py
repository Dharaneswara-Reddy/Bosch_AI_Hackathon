"""Render local static reports from validated scan artifacts."""

import re
from collections import Counter
from html import escape
from itertools import islice
from pathlib import Path
from typing import TypeVar, cast
from urllib.parse import quote

from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel

from guardian.decisions import DecisionLog, HumanDecision, apply_decisions
from guardian.models import (
    AgentTrace,
    CoverageArtifact,
    Evidence,
    Finding,
    FindingKind,
    FindingsArtifact,
    GraphArtifact,
    LlmStatus,
    Scan,
)
from guardian.relevance import rank
from guardian.report.final import build_report, load_fixes

Artifact = TypeVar("Artifact", bound=BaseModel)
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
FIX_STEP = "remediation_planner"
LIMITATIONS = (
    "Reachability is a static import search of the application's own source; it does not "
    "prove that a vulnerable function is called, and no hit is not proof of safety.",
    "Exploitation data (CISA KEV, EPSS) is shown only when the scanner output includes it.",
    "Fix proposals are applied only after human approval, in a sandbox copy; a fix without a "
    "passing test run is verified by build and rescan only.",
)


def _load(root: Path, name: str, model: type[Artifact]) -> Artifact:
    return model.model_validate_json((root / name).read_bytes())


def _markdown(value: object) -> str:
    text = " ".join(str(value if value is not None else "UNKNOWN").splitlines())
    text = escape(text, quote=False)
    return re.sub(r"([\\\x60*_\[\]{}()#!|])", r"\\\1", text)


def _evidence_path(root: Path, item: Evidence) -> Path | None:
    path = Path(item.file)
    if path.is_absolute() or ".." in path.parts:
        return None
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root / "raw") or not resolved.is_file():
        return None
    return resolved


def _diff_excerpt(path: Path | None, pointer: str) -> str | None:
    if path is None or path.suffix not in {".diff", ".patch"}:
        return None
    match = re.fullmatch(r"(?:#?L|lines?[:= ]+)?(\d+)(?:\s*[-:]\s*L?(\d+))?", pointer)
    if match is None or path.stat().st_size > 1024 * 1024:
        return None
    start = max(1, int(match[1]))
    stop = min(int(match[2] or start), start + 29)
    if stop < start:
        return None
    with path.open(encoding="utf-8", errors="replace") as stream:
        return "".join(line[:500] for line in islice(stream, start - 1, stop)).strip()


def _evidence_details(root: Path, evidence: list[Evidence]) -> dict[str, dict[str, object]]:
    details: dict[str, dict[str, object]] = {}
    for item in evidence:
        path = _evidence_path(root, item)
        href = quote(path.relative_to(root).as_posix()) if path else None
        details[item.evidence_id] = {
            "item": item,
            "href": href,
            "diff": _diff_excerpt(path, item.pointer),
        }
    return details


def _ranked(findings: list[Finding]) -> list[Finding]:
    def key(finding: Finding) -> tuple[int, int, str]:
        return rank(finding), RISK_ORDER.get(str(finding.risk_level), 4), finding.finding_id

    return sorted((f for f in findings if f.kind != FindingKind.ANOMALY), key=key)


def _entry_paths(findings: list[Finding], graph: GraphArtifact) -> list[dict[str, object]]:
    """How each vulnerability enters the app: every hop, with the source of each edge."""
    nodes = {node.component_id: node for node in graph.nodes}
    sources = {(e.parent_id, e.child_id): str(e.edge_source) for e in graph.edges}
    rows: list[dict[str, object]] = []
    for finding in findings:
        path = finding.dependency_path
        hops = [
            {
                "label": f"{nodes[c].name}@{nodes[c].version}" if c in nodes else c,
                "edge": sources.get((c, path[i + 1]), "UNKNOWN") if i + 1 < len(path) else None,
            }
            for i, c in enumerate(path)
        ]
        introduced = finding.relevance.introduced_by if finding.relevance else None
        rows.append({"finding": finding, "hops": hops, "introduced_by": introduced})
    return rows


def _reviewed(trace: list[AgentTrace]) -> set[str]:
    """Finding IDs that triage handed to the AI (pack IDs are ``pack-<finding_id>``)."""
    return {
        pack.removeprefix("pack-")
        for step in trace
        if step.agent == "triage"
        for pack in step.produced
    }


def _groups(
    findings: list[Finding], graph: GraphArtifact, reviewed: set[str]
) -> list[dict[str, object]]:
    """One row per advisory and package name, so platform builds of one gem share a row."""
    nodes = {node.component_id: node for node in graph.nodes}
    groups: dict[tuple[str, str], dict[str, object]] = {}
    for finding in findings:
        node = nodes.get(finding.component_id)
        name = node.name if node else finding.purl
        group = groups.setdefault(
            (finding.advisory_id or finding.finding_id, name),
            {
                "finding": finding,
                "name": name,
                "versions": [],
                "count": 0,
                "ai": False,
            },
        )
        versions = group["versions"]
        if node and isinstance(versions, list) and node.version not in versions:
            versions.append(node.version)
        group["count"] = int(str(group["count"])) + 1
        group["ai"] = bool(group["ai"]) or finding.finding_id in reviewed
    return list(groups.values())


def _unknowns(scan: Scan, findings: list[Finding]) -> list[str]:
    items = [
        f"{f.advisory_id or f.purl}: relevance unknown ({f.relevance.summary})"
        for f in findings
        if f.relevance and f.relevance.verdict == "unknown"
    ]
    no_path = [f.advisory_id or f.purl for f in findings if not f.dependency_path]
    if no_path:
        items.append(f"Dependency path could not be resolved for: {', '.join(no_path)}")
    unknown_reach = sum(
        1 for f in findings if f.relevance and f.relevance.reachability == "unknown"
    )
    if unknown_reach:
        items.append(
            f"Reachability unknown for {unknown_reach} findings: application source "
            "code was not available."
        )
    if scan.llm_status != LlmStatus.OK:
        items.append(f"AI review status is {scan.llm_status}: AI explanations may be missing.")
    items += [f"Stage {stage} reported: {issue}" for stage, issue in scan.errors.items()]
    return items + list(LIMITATIONS)


def _environment() -> Environment:
    environment = Environment(
        loader=FileSystemLoader(Path(__file__).with_name("templates")),
        autoescape=lambda name: bool(name and name.endswith(".html.j2")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["md"] = _markdown
    return environment


def _template_data(
    root: Path,
    scan: Scan,
    graph: GraphArtifact,
    artifacts: FindingsArtifact,
    coverage: CoverageArtifact,
    decisions: list[HumanDecision],
) -> dict[str, object]:
    findings = apply_decisions(artifacts.findings, decisions)
    ranked = _ranked(findings)
    analysis = [item for item in artifacts.claims if item.step != FIX_STEP]
    reviewed = _reviewed(artifacts.agent_trace)
    groups = _groups(ranked, graph, reviewed)
    return {
        "scan": scan,
        "coverage": coverage,
        "components": {item.component_id: item for item in graph.nodes},
        "findings": ranked,
        "groups": groups,
        "advisory_count": len({f.advisory_id or f.finding_id for f in ranked}),
        "risk_counts": Counter(str(f.risk_level) for f in ranked),
        "reviewed_count": len(reviewed),
        "relevance_known": any(f.relevance and f.relevance.verdict != "unknown" for f in ranked),
        "suspicious": [
            item for item in findings if item.kind in (FindingKind.ANOMALY, FindingKind.MALICIOUS)
        ],
        "entries": _entry_paths([cast(Finding, group["finding"]) for group in groups], graph),
        "evidence": _evidence_details(root, artifacts.evidence),
        "accepted": [item for item in analysis if item.validated and item.kind == "evidence"],
        "inferences": [item for item in analysis if item.validated and item.kind == "inference"],
        "rejected": [item for item in analysis if not item.validated],
        "fixes": [item for item in artifacts.claims if item.step == FIX_STEP],
        "risk_adjustments": artifacts.risk_adjustments,
        "trace": artifacts.agent_trace,
        "unknowns": _unknowns(scan, ranked),
        "human_decisions": decisions,
        "has_sbom": (root / "sbom.cdx.json").is_file(),
    }


def render(run_dir: Path) -> None:
    """Write equivalent HTML and Markdown views from the four scan artifacts."""
    root = run_dir.resolve()
    scan = _load(root, "run.json", Scan)
    graph = _load(root, "graph.json", GraphArtifact)
    artifacts = _load(root, "findings.json", FindingsArtifact)
    coverage = _load(root, "coverage.json", CoverageArtifact)
    decisions = DecisionLog(root).history()
    data = _template_data(root, scan, graph, artifacts, coverage, decisions)
    ranked = cast(list[Finding], data["findings"])
    environment = _environment()
    final = build_report(scan, graph, artifacts, ranked, decisions, load_fixes(root.parent))
    (root / "report.json").write_text(final.model_dump_json(indent=2) + "\n", encoding="utf-8")
    data["final"] = final
    data["final_findings"] = {item.finding_id: item for item in final.findings}
    for name in ("report.html", "report.md"):
        text = environment.get_template(f"{name}.j2").render(**data)
        (root / name).write_text(text + "\n", encoding="utf-8")
