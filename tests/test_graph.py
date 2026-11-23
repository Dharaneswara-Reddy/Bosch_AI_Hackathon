import json
from pathlib import Path

import networkx as nx
import pytest

from guardian.graph import load_graph, path_count, shortest_path

EDGES = {
    "A": ["C", "D"], "B": ["D"], "C": ["E"], "D": ["E"], "E": ["F"], "F": ["E"],
    "P": ["Q"], "Q": ["P"],
}
NAMES = "ABCDEFPQZ"


def _write_sbom(tmp_path: Path, edges: dict[str, list[str]], names: str) -> Path:
    bom = {
        "metadata": {"component": {"bom-ref": "dir", "name": "/src", "type": "file"}},
        "components": [
            {"bom-ref": ref, "name": f"pkg-{ref}", "version": "1.0", "purl": f"pkg:npm/{ref}@1.0",
             "properties": [{"name": "syft:location:0:path", "value": "/package-lock.json"}]}
            for ref in names
        ],
        "dependencies": [{"ref": ref, "dependsOn": kids} for ref, kids in edges.items()]
        + [{"ref": "Z"}],
    }
    path = tmp_path / "sbom.cdx.json"
    path.write_text(json.dumps(bom), encoding="utf-8")
    return path


@pytest.fixture
def graph(tmp_path: Path) -> nx.DiGraph:
    return load_graph(_write_sbom(tmp_path, EDGES, NAMES))


def test_nodes_and_edges_come_only_from_dependencies(graph: nx.DiGraph) -> None:
    assert graph.number_of_edges() == 9
    assert graph.nodes["C"]["purl"] == "pkg:npm/C@1.0"
    assert graph.nodes["C"]["label"] == "pkg-C@1.0"
    assert graph.edges["A", "C"]["edge_source"] == "sbom"
    assert "dir" not in graph


def test_roots_exclude_cycles_and_isolated_nodes_in_same_lockfile(graph: nx.DiGraph) -> None:
    assert graph.graph["roots"] == ["A"]


def test_roots_are_chosen_per_lockfile(tmp_path: Path) -> None:
    sbom = _write_sbom(tmp_path, {"A": ["C"], "B": ["D"]}, "ABCD")
    bom = json.loads(sbom.read_text(encoding="utf-8"))
    for component in bom["components"]:
        if component["bom-ref"] in "BD":
            component["properties"][0]["value"] = "/frontend/package-lock.json"
    sbom.write_text(json.dumps(bom), encoding="utf-8")
    assert load_graph(sbom).graph["roots"] == ["A", "B"]


def test_shortest_path_from_nearest_root(graph: nx.DiGraph) -> None:
    assert shortest_path(graph, "E") in (["A", "C", "E"], ["A", "D", "E"])
    assert shortest_path(graph, "F")[-2:] == ["E", "F"]
    assert shortest_path(graph, "A") == ["A"]


def test_shortest_path_picks_shortest_over_all_roots(tmp_path: Path) -> None:
    edges = {"A": ["X"], "X": ["Y"], "Y": ["T"], "B": ["T"]}
    graph = load_graph(_write_sbom(tmp_path, edges, "AXYBT"))
    graph.graph["roots"] = ["A", "B"]
    assert shortest_path(graph, "T") == ["B", "T"]


def test_path_count_over_diamond_with_cycle(graph: nx.DiGraph) -> None:
    assert path_count(graph, "D") == 1
    assert path_count(graph, "E") == 2
    assert path_count(graph, "F") == 2


def test_unreachable_nodes_have_no_path(graph: nx.DiGraph) -> None:
    for node in ("Z", "P", "Q"):
        assert shortest_path(graph, node) == []
        assert path_count(graph, node) == 0
    assert shortest_path(graph, "missing") == []
    assert path_count(graph, "missing") == 0


def test_path_count_is_capped(tmp_path: Path) -> None:
    layers = {"R": ["a0", "b0"]}
    for i in range(12):
        layers[f"a{i}"] = [f"a{i + 1}", f"b{i + 1}"]
        layers[f"b{i}"] = [f"a{i + 1}", f"b{i + 1}"]
    names = ["R", *[f"{c}{i}" for i in range(13) for c in "ab"]]
    graph = load_graph(_write_sbom_refs(tmp_path, layers, names))
    assert path_count(graph, "a12") == 2**12
    assert path_count(graph, "a12", cap=100) == 100


def _write_sbom_refs(tmp_path: Path, edges: dict[str, list[str]], refs: list[str]) -> Path:
    path = _write_sbom(tmp_path, edges, "")
    bom = json.loads(path.read_text(encoding="utf-8"))
    bom["components"] = [
        {"bom-ref": ref, "name": ref, "version": "1", "purl": f"pkg:npm/{ref}@1"} for ref in refs
    ]
    path.write_text(json.dumps(bom), encoding="utf-8")
    return path


def test_resolver_edges_and_synthetic_roots_give_paths(tmp_path: Path) -> None:
    bom = {
        "components": [
            {"bom-ref": ref, "name": ref, "version": "1", "purl": f"pkg:gem/{ref}@1",
             "properties": [{"name": "syft:location:0:path", "value": "/Gemfile.lock"}]}
            for ref in ("a", "b", "c", "d")
        ] + [
            {"bom-ref": "guardian:root:Gemfile.lock", "type": "application",
             "name": "Gemfile.lock",
             "properties": [{"name": "syft:location:0:path", "value": "/Gemfile.lock"}]},
        ],
        "dependencies": [
            {"ref": "guardian:root:Gemfile.lock", "dependsOn": ["a", "d"]},
            {"ref": "a", "dependsOn": ["b"]}, {"ref": "b", "dependsOn": ["c"]},
        ],
        "properties": [{"name": "guardian:resolver-edge:0", "value": "b c"},
                       {"name": "guardian:resolver-edge:1",
                        "value": "guardian:root:Gemfile.lock a"}],
    }
    path = tmp_path / "sbom.cdx.json"
    path.write_text(json.dumps(bom), encoding="utf-8")
    graph = load_graph(path)
    assert graph.graph["roots"] == ["guardian:root:Gemfile.lock"]
    assert shortest_path(graph, "c") == ["guardian:root:Gemfile.lock", "a", "b", "c"]
    assert shortest_path(graph, "d") == ["guardian:root:Gemfile.lock", "d"]
    assert graph.edges["b", "c"]["edge_source"] == "resolver"
    assert graph.edges["a", "b"]["edge_source"] == "sbom"
    assert graph.edges["guardian:root:Gemfile.lock", "d"]["edge_source"] == "sbom"
