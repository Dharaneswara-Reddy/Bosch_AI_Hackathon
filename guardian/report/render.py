"""Render local static reports from validated scan artifacts."""

import re
from html import escape
from itertools import islice
from pathlib import Path
from typing import TypeVar
from urllib.parse import quote

from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel

from guardian.models import (
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

Artifact = TypeVar("Artifact", bound=BaseModel)
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
FIX_STEP = "remediation_planner"
LIMITATIONS = (
    "Reachability is a static import search of the application's own source; it does not "
    "prove that a vulnerable function is called, and no hit is not proof of safety.",
    "Exploitation data (CISA KEV, EPSS) is shown only when the scanner output includes it.",
    "Fix proposals are not applied or tested here; each needs human approval and a sandbox "
    "build, test and rescan.",
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
            "item": item, "href": href, "diff": _diff_excerpt(path, item.pointer),
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
        hops = [{"label": f"{nodes[c].name}@{nodes[c].version}" if c in nodes else c,
                 "edge": sources.get((c, path[i + 1]), "UNKNOWN") if i + 1 < len(path) else None}
                for i, c in enumerate(path)]
        introduced = finding.relevance.introduced_by if finding.relevance else None
        rows.append({"finding": finding, "hops": hops, "introduced_by": introduced})
    return rows


def _unknowns(scan: Scan, findings: list[Finding]) -> list[str]:
    items = [f"{f.advisory_id or f.purl}: relevance unknown ({f.relevance.summary})"
             for f in findings if f.relevance and f.relevance.verdict == "unknown"]
    no_path = [f.advisory_id or f.purl for f in findings if not f.dependency_path]
    if no_path:
        items.append(f"Dependency path could not be resolved for: {', '.join(no_path)}")
    unknown_reach = sum(
        1 for f in findings if f.relevance and f.relevance.reachability == "unknown"
    )
    if unknown_reach:
        items.append(f"Reachability unknown for {unknown_reach} findings: application source "
                     "code was not available.")
    if scan.llm_status != LlmStatus.OK:
        items.append(f"AI review status is {scan.llm_status}: AI explanations may be missing.")
    items += [f"Stage {stage} reported: {issue}" for stage, issue in scan.errors.items()]
    return items + list(LIMITATIONS)


def render(run_dir: Path) -> None:
    """Write equivalent HTML and Markdown views from the four scan artifacts."""
    root = run_dir.resolve()
    scan = _load(root, "run.json", Scan)
    graph = _load(root, "graph.json", GraphArtifact)
    artifacts = _load(root, "findings.json", FindingsArtifact)
    coverage = _load(root, "coverage.json", CoverageArtifact)
    environment = Environment(
        loader=FileSystemLoader(Path(__file__).with_name("templates")),
        autoescape=lambda name: bool(name and name.endswith(".html.j2")),
        trim_blocks=True, lstrip_blocks=True,
    )
    environment.filters["md"] = _markdown
    ranked = _ranked(artifacts.findings)
    analysis = [item for item in artifacts.claims if item.step != FIX_STEP]
    data = {
        "scan": scan,
        "coverage": coverage,
        "components": {item.component_id: item for item in graph.nodes},
        "findings": ranked,
        "suspicious": [item for item in artifacts.findings
                       if item.kind in (FindingKind.ANOMALY, FindingKind.MALICIOUS)],
        "entries": _entry_paths(ranked, graph),
        "evidence": _evidence_details(root, artifacts.evidence),
        "accepted": [item for item in analysis if item.validated and item.kind == "evidence"],
        "inferences": [item for item in analysis if item.validated and item.kind == "inference"],
        "rejected": [item for item in analysis if not item.validated],
        "fixes": [item for item in artifacts.claims if item.step == FIX_STEP],
        "trace": artifacts.agent_trace,
        "unknowns": _unknowns(scan, ranked),
        "has_sbom": (root / "sbom.cdx.json").is_file(),
    }
    for name in ("report.html", "report.md"):
        text = environment.get_template(f"{name}.j2").render(**data)
        (root / name).write_text(text + "\n", encoding="utf-8")
