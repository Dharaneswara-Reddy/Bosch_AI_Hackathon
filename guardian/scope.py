"""Mark each component as direct or transitive and as a production or dev-only dependency.

* Direct vs transitive comes from the dependency graph: children of an application root
  are direct dependencies.
* Ruby dev-only comes from the Gemfile's ``group :development, :test`` blocks: a gem is dev
  when it is listed only in dev/test groups and every dependency path to it goes through such
  gems.
* Dev-only for npm comes from npm lockfiles (``"dev": true`` on every installed copy of a
  package). Ecosystems whose lockfiles do not record it keep ``dev = None`` (unknown).
"""

import json
import os
import re
from collections import deque
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

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


DEV_GROUPS = frozenset({"development", "test"})
_GROUP_BLOCK = re.compile(r"^\s*group\s*\(?\s*([^\n]*?)\s*\)?\s+do\b")
_BLOCK_OPEN = re.compile(r"(\bdo(\s*\|[^|]*\|)?\s*$)|^\s*(if|unless|case|begin)\b")
_GEM_LINE = re.compile(r"^\s*gem\s*\(?\s*['\"]([^'\"]+)['\"](.*)")
_INLINE_GROUP = re.compile(r"\bgroups?:\s*(\[[^\]]*\]|%i\[[^\]]*\]|:\w+)|:groups?\s*=>\s*(\[[^\]]*\]|:\w+)")


class GemfileGroups(BaseModel):
    """Gem names listed only in dev/test groups (dev) or at least once elsewhere (prod)."""

    dev: set[str] = Field(default_factory=set)
    prod: set[str] = Field(default_factory=set)


def _symbols(text: str) -> set[str]:
    return set(re.findall(r"(?::|\b)([a-z_]+)\b", text.replace("%i", " "))) - {"i"}


def _gemfile_entries(text: str) -> list[tuple[str, set[str]]]:
    """(gem name, groups) for each gem line; empty groups means the default (production) group."""
    entries: list[tuple[str, set[str]]] = []
    stack: list[set[str]] = []
    for line in text.splitlines():
        code = line.split("#", 1)[0]
        if (block := _GROUP_BLOCK.match(code)) is not None:
            stack.append(_symbols(block.group(1)))
        elif re.match(r"^\s*end\b", code):
            if stack:
                stack.pop()
        elif (gem := _GEM_LINE.match(code)) is not None:
            inline = _INLINE_GROUP.search(gem.group(2))
            groups = _symbols(next(g for g in inline.groups() if g)) if inline else set()
            entries.append((gem.group(1), groups.union(*stack)))
        elif _BLOCK_OPEN.search(code):
            stack.append(set())
    return entries


def gemfile_groups(target: Path) -> GemfileGroups:
    groups = GemfileGroups()
    for directory, folders, files in os.walk(target):
        folders[:] = sorted(name for name in folders if name not in SKIPPED_DIRS)
        if "Gemfile" not in files:
            continue
        try:
            text = (Path(directory) / "Gemfile").read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for name, found in _gemfile_entries(text):
            (groups.dev if found and found <= DEV_GROUPS else groups.prod).add(name)
    groups.dev -= groups.prod
    return groups


def _production_gems(graph: GraphArtifact, roots: set[str], dev_direct: set[str]) -> set[str]:
    """Component IDs reachable from the app through at least one non-dev direct gem."""
    names = {node.component_id: node.name for node in graph.nodes}
    children: dict[str, list[str]] = {}
    for edge in graph.edges:
        children.setdefault(edge.parent_id, []).append(edge.child_id)
    queue = deque(
        child for root in roots for child in children.get(root, [])
        if names.get(child) not in dev_direct
    )
    seen: set[str] = set()
    while queue:
        current = queue.popleft()
        if current not in seen:
            seen.add(current)
            queue.extend(children.get(current, []))
    return seen


def _apply_gemfile(graph: GraphArtifact, roots: set[str], gems: GemfileGroups) -> dict[str, bool]:
    """Component ID -> dev flag for gems the Gemfile groups settle; others stay unknown."""
    if not roots or not (gems.dev or gems.prod):
        return {}
    production = _production_gems(graph, roots, gems.dev)
    reachable = {edge.child_id for edge in graph.edges}
    return {
        node.component_id: node.component_id not in production
        for node in graph.nodes
        if node.ecosystem == "gem" and node.component_id in reachable
    }


def _scope(component_id: str, roots: set[str], direct: set[str]) -> Scope:
    if component_id in roots:
        return Scope.UNKNOWN
    return Scope.DIRECT if component_id in direct else Scope.TRANSITIVE


def apply_scope(
    graph: GraphArtifact,
    roots: list[str],
    dev_flags: dict[tuple[str, str], bool],
    gems: GemfileGroups | None = None,
) -> GraphArtifact:
    """Return a copy of the graph with ``scope`` and ``dev`` filled in where known."""
    root_set = set(roots)
    gem_dev = _apply_gemfile(graph, root_set, gems or GemfileGroups())
    direct = {edge.child_id for edge in graph.edges if edge.parent_id in root_set}
    nodes: list[Component] = []
    for node in graph.nodes:
        dev = dev_flags.get((node.name, node.version), gem_dev.get(node.component_id, node.dev))
        scope = _scope(node.component_id, root_set, direct) if root_set else node.scope
        nodes.append(node.model_copy(update={"scope": scope, "dev": dev}))
    return graph.model_copy(update={"nodes": nodes})
