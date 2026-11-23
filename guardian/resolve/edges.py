"""Dependency edges read straight from lockfiles, for ecosystems where Syft emits none."""

import re
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, Field


class LockfileEdges(BaseModel):
    lockfile: Path
    edges: list[tuple[str, str]] = Field(default_factory=list)
    direct: list[str] = Field(default_factory=list)


GEM_SECTIONS = frozenset({"GEM", "GIT", "PATH", "PLUGIN SOURCE"})
GEM_LINE = re.compile(r"^ {4}(\S+) \(([^)]+)\)$")
CHILD_LINE = re.compile(r"^ {6}(\S+)(?: \(.*\))?$")
DIRECT_LINE = re.compile(r"^ {2}(\S+?)!?(?: \(.*\))?$")


def _gem_purl(name: str, version: str) -> str:
    return f"pkg:gem/{name}@{version}"


def parse_gemfile_lock(path: Path) -> LockfileEdges:
    children: dict[str, list[str]] = defaultdict(list)
    versions: dict[str, list[str]] = defaultdict(list)
    direct_names: list[str] = []
    section, current = "", ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith(" "):
            section, current = line.strip(), ""
        elif section in GEM_SECTIONS and (gem := GEM_LINE.match(line)):
            current = _gem_purl(gem[1], gem[2])
            versions[gem[1]].append(current)
            children.setdefault(current, [])
        elif section in GEM_SECTIONS and current and (child := CHILD_LINE.match(line)):
            children[current].append(child[1])
        elif section == "DEPENDENCIES" and (name := DIRECT_LINE.match(line)):
            direct_names.append(name[1])
    edges = [
        (parent, target)
        for parent, names in children.items()
        for name in names
        for target in versions.get(name, [])
    ]
    direct = [purl for name in direct_names for purl in versions.get(name, [])]
    return LockfileEdges(lockfile=path, edges=edges, direct=direct)


EDGE_PARSERS: dict[str, Callable[[Path], LockfileEdges]] = {
    "Gemfile.lock": parse_gemfile_lock,
}
