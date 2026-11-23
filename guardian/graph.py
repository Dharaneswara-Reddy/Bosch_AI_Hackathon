"""Load a CycloneDX SBOM into a dependency graph and answer path questions about it."""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import networkx as nx

LOCATION_PROPERTY = "syft:location:0:path"
DEFAULT_PATH_CAP = 10_000
COUNTS_KEY = "_path_counts"
RESOLVER_EDGE_PREFIX = "guardian:resolver-edge:"


def load_graph(sbom: Path) -> nx.DiGraph:
    bom = json.loads(sbom.read_text(encoding="utf-8"))
    graph: nx.DiGraph = nx.DiGraph()
    locations: dict[str, str] = {}
    for component in bom.get("components", []):
        ref = component.get("bom-ref") or component.get("purl")
        if not ref:
            continue
        name, version = component.get("name", ""), component.get("version", "")
        graph.add_node(
            ref, purl=component.get("purl", ""), name=name, version=version,
            label=f"{name}@{version}" if version else name,
        )
        locations[ref] = _location(component)
    resolver_edges = _resolver_edges(bom)
    for entry in bom.get("dependencies", []):
        for child in entry.get("dependsOn", []):
            if entry["ref"] in graph and child in graph:
                source = "resolver" if (entry["ref"], child) in resolver_edges else "sbom"
                graph.add_edge(entry["ref"], child, edge_source=source)
    graph.graph["roots"] = _roots(graph, locations)
    return graph


def _resolver_edges(bom: dict[str, Any]) -> set[tuple[str, str]]:
    edges: set[tuple[str, str]] = set()
    for prop in bom.get("properties", []):
        if str(prop.get("name", "")).startswith(RESOLVER_EDGE_PREFIX):
            parent, child = str(prop["value"]).split(" ", 1)
            edges.add((parent, child))
    return edges


def _location(component: dict[str, Any]) -> str:
    for prop in component.get("properties", []):
        if prop.get("name") == LOCATION_PROPERTY:
            return str(prop.get("value", ""))
    return ""


def _roots(graph: nx.DiGraph, locations: dict[str, str]) -> list[str]:
    best: dict[str, tuple[int, str]] = {}
    for node in graph:
        if graph.in_degree(node) or not graph.out_degree(node):
            continue
        size = len(nx.descendants(graph, node))
        site = locations.get(node, "")
        if site not in best or size > best[site][0]:
            best[site] = (size, node)
    return sorted(node for _, node in best.values())


def shortest_path(g: nx.DiGraph, component_id: str) -> list[str]:
    if component_id not in g:
        return []
    best: list[str] = []
    for root in g.graph.get("roots", []):
        try:
            path: list[str] = nx.shortest_path(g, root, component_id)
        except nx.NetworkXNoPath:
            continue
        if not best or len(path) < len(best):
            best = path
    return best


def path_count(g: nx.DiGraph, component_id: str, cap: int = DEFAULT_PATH_CAP) -> int:
    cache: dict[int, dict[str, int]] = g.graph.setdefault(COUNTS_KEY, {})
    if cap not in cache:
        cache[cap] = _count_all(g, cap)
    return cache[cap].get(component_id, 0)


def _count_all(g: nx.DiGraph, cap: int) -> dict[str, int]:
    roots: list[str] = g.graph.get("roots", [])
    order, kept = _acyclic_order(g, roots)
    counts: dict[str, int] = defaultdict(int)
    for root in roots:
        counts[root] = 1
    for node in order:
        for child in kept[node]:
            counts[child] = min(cap, counts[child] + counts[node])
    return dict(counts)


def _acyclic_order(
    g: nx.DiGraph, roots: list[str]
) -> tuple[list[str], dict[str, list[str]]]:
    state: dict[str, int] = {}
    kept: dict[str, list[str]] = defaultdict(list)
    post: list[str] = []
    for root in roots:
        if root in state:
            continue
        state[root] = 1
        stack = [(root, iter(sorted(g.successors(root))))]
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                state[node] = 2
                post.append(node)
                stack.pop()
            elif state.get(child) == 1:
                continue
            else:
                kept[node].append(child)
                if child not in state:
                    state[child] = 1
                    stack.append((child, iter(sorted(g.successors(child)))))
    return post[::-1], kept
