"""Compute inventory counts and scanner and resolver coverage."""

from collections import defaultdict

from guardian.models import (
    CoverageArtifact, CoverageRow, EcosystemCoverage, Finding, GraphArtifact,
)


def build_coverage(
    graph: GraphArtifact, findings: list[Finding], rows: list[CoverageRow]
) -> CoverageArtifact:
    inventory: dict[str, set[str]] = defaultdict(set)
    for node in graph.nodes:
        inventory[node.ecosystem].add(node.component_id)
    resolved = {edge.child_id for edge in graph.edges if edge.edge_source == "resolver"}
    matched = {
        finding.component_id for finding in findings
        if finding.kind in {"vulnerability", "malicious"} and finding.confirmed_by
    }
    ecosystems = {
        ecosystem: EcosystemCoverage(
            components=len(ids),
            resolver_percent=100 * len(ids & resolved) / len(ids),
            scanner_percent=100 * len(ids & matched) / len(ids),
        )
        for ecosystem, ids in sorted(inventory.items())
    }
    return CoverageArtifact(
        rows=rows, ecosystems=ecosystems,
        warnings=[] if ecosystems else ["Zero components found. Inventory coverage is unknown."],
    )
