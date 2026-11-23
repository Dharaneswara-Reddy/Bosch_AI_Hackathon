"""Runner stages that explain how vulnerabilities enter the application and whether they matter.

* ``apply_scope``: mark graph components direct/transitive and production/dev-only.
* ``apply_relevance``: scan the application's own source for imports, record the hits
  as evidence (``raw/relevance/reachability.json``), and attach a ``Relevance`` to every
  vulnerability and malicious-package finding.
"""

import json
from pathlib import Path
from typing import Any

from guardian.evidence import EvidenceStore
from guardian.models import Component, FindingKind, RunResult
from guardian.reachability import ReachabilityScan, scan_imports
from guardian.relevance import advisory_details, assess, path_facts
from guardian.scope import apply_scope as scope_graph
from guardian.scope import gemfile_groups, npm_dev_flags

REACHABILITY_FILE = "raw/relevance/reachability.json"
ASSESSED_KINDS = frozenset({FindingKind.VULNERABILITY, FindingKind.MALICIOUS})


def apply_scope(result: RunResult, target: Path | None, roots: list[str]) -> None:
    local = target is not None and target.is_dir()
    flags = npm_dev_flags(target) if local and target is not None else {}
    gems = gemfile_groups(target) if local and target is not None else None
    result.graph = scope_graph(result.graph, roots, flags, gems)


def _package_names(result: RunResult, nodes: dict[str, Component]) -> set[str]:
    names: set[str] = set()
    for finding in result.findings:
        if finding.kind not in ASSESSED_KINDS:
            continue
        facts = path_facts(finding, nodes)
        names.update(n for n in (facts.introduced_by,) if n)
        if facts.component is not None:
            names.add(facts.component.name)
    return names


def _record_hits(scan: ReachabilityScan, out: Path, store: EvidenceStore) -> dict[str, str]:
    """Write import hits to the raw folder and return package name -> evidence ID."""
    if not scan.hits:
        return {}
    path = out / REACHABILITY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "tool": "guardian-reachability",
        "source_files": scan.source_files,
        "hits": {name: [h.model_dump() for h in hits] for name, hits in scan.hits.items()},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        name: store.add("guardian-reachability", REACHABILITY_FILE, f"/hits/{name}")
        for name in scan.hits
    }


def apply_relevance(
    result: RunResult, target: Path | None, out: Path, store: EvidenceStore
) -> None:
    nodes = {node.component_id: node for node in result.graph.nodes}
    scan = None
    reach_evidence: dict[str, str] = {}
    if target is not None and target.is_dir():
        scan = scan_imports(target, _package_names(result, nodes))
        reach_evidence = _record_hits(scan, out, store)
    evidence = {record.evidence_id: record for record in store.records()}
    cache: dict[str, Any] = {}
    for index, finding in enumerate(result.findings):
        if finding.kind not in ASSESSED_KINDS:
            continue
        details = advisory_details(finding, evidence, out, cache)
        relevance = assess(finding, path_facts(finding, nodes), details, scan, reach_evidence)
        result.findings[index] = finding.model_copy(update={"relevance": relevance})
