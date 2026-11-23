"""Render local static reports from validated scan artifacts."""

import re
from html import escape
from itertools import islice
from pathlib import Path
from typing import TypeVar
from urllib.parse import quote

from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel

from guardian.models import CoverageArtifact, Evidence, FindingsArtifact, GraphArtifact, Scan

Artifact = TypeVar("Artifact", bound=BaseModel)


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
    data = {
        "scan": scan,
        "coverage": coverage,
        "components": {item.component_id: item for item in graph.nodes},
        "findings": [item for item in artifacts.findings if item.kind != "anomaly"],
        "anomalies": [item for item in artifacts.findings if item.kind == "anomaly"],
        "paths": [item for item in artifacts.findings if item.dependency_path],
        "evidence": _evidence_details(root, artifacts.evidence),
        "accepted": [item for item in artifacts.claims if item.validated and item.kind == "evidence"],
        "inferences": [item for item in artifacts.claims if item.validated and item.kind == "inference"],
        "rejected": [item for item in artifacts.claims if not item.validated],
        "has_sbom": (root / "sbom.cdx.json").is_file(),
    }
    for name in ("report.html", "report.md"):
        text = environment.get_template(f"{name}.j2").render(**data)
        (root / name).write_text(text + "\n", encoding="utf-8")
