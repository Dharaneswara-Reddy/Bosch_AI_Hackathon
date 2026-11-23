"""Mark each component as direct or transitive and as a production or dev-only dependency.

* Direct vs transitive comes from the dependency graph: children of an application root
  are direct dependencies.
* Dev-only comes from npm lockfiles (``"dev": true`` on every installed copy of a
  package). Ecosystems whose lockfiles do not record it keep ``dev = None`` (unknown).
"""

import json
import os
from pathlib import Path
from typing import Any

from guardian.models import Component, GraphArtifact, Scope

NPM_LOCKFILES = frozenset({"package-lock.json", "npm-shrinkwrap.json"})
SKIPPED_DIRS = frozenset({"node_modules", ".git", "vendor"})


def _package_name(entry_path: str, entry: dict[str, Any]) -> str:
    name = entry.get("name")
    if isinstance(name, str) and name:
        return name
    return entry_path.rsplit("node_modules/", 1)[-1]


def _lockfile_dev_flags(path: Path) -> dict[tuple[str, str], bool]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    flags: dict[tuple[str, str], bool] = {}
    packages = data.get("packages", {}) if isinstance(data, dict) else {}
    for entry_path, entry in packages.items():
        if not entry_path or not isinstance(entry, dict) or "node_modules/" not in entry_path:
            continue
        key = (_package_name(entry_path, entry), str(entry.get("version", "")))
        is_dev = entry.get("dev") is True or entry.get("devOptional") is True
        flags[key] = flags.get(key, True) and is_dev
    return flags


def npm_dev_flags(target: Path) -> dict[tuple[str, str], bool]:
    """(name, version) -> True if every installed copy is dev-only, False if any is not."""
    flags: dict[tuple[str, str], bool] = {}
    for directory, folders, files in os.walk(target):
        folders[:] = sorted(name for name in folders if name not in SKIPPED_DIRS)
        for name in sorted(NPM_LOCKFILES & set(files)):
            for key, is_dev in _lockfile_dev_flags(Path(directory) / name).items():
                flags[key] = flags.get(key, True) and is_dev
    return flags


def _scope(component_id: str, roots: set[str], direct: set[str]) -> Scope:
    if component_id in roots:
        return Scope.UNKNOWN
    return Scope.DIRECT if component_id in direct else Scope.TRANSITIVE


def apply_scope(
    graph: GraphArtifact,
    roots: list[str],
    dev_flags: dict[tuple[str, str], bool],
) -> GraphArtifact:
    """Return a copy of the graph with ``scope`` and ``dev`` filled in where known."""
    root_set = set(roots)
    direct = {edge.child_id for edge in graph.edges if edge.parent_id in root_set}
    nodes: list[Component] = []
    for node in graph.nodes:
        dev = dev_flags.get((node.name, node.version), node.dev)
        scope = _scope(node.component_id, root_set, direct) if root_set else node.scope
        nodes.append(node.model_copy(update={"scope": scope, "dev": dev}))
    return graph.model_copy(update={"nodes": nodes})
