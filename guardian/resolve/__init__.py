"""Classify how fully a target's dependencies are pinned, without running package managers."""

import os
from pathlib import Path

from pydantic import BaseModel, Field

from guardian.models import Resolution
from guardian.resolve.edges import EDGE_PARSERS, LockfileEdges

LOCKFILE_NAMES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "Gemfile.lock",
    "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock", "go.sum", "composer.lock",
    "packages.lock.json", "gradle.lockfile",
})
SKIPPED_DIRS = frozenset({"node_modules", ".git", "vendor"})


class ResolveResult(BaseModel):
    resolution: Resolution
    lockfiles: list[Path] = Field(default_factory=list)
    lockfile_edges: list[LockfileEdges] = Field(default_factory=list)


def resolve_target(target_path: Path, work_dir: Path) -> ResolveResult:
    lockfiles: list[Path] = []
    for directory, folders, files in os.walk(target_path):
        folders[:] = sorted(name for name in folders if name not in SKIPPED_DIRS)
        lockfiles.extend(Path(directory) / name for name in sorted(files) if name in LOCKFILE_NAMES)
    resolution = Resolution.LOCKFILE if lockfiles else Resolution.MANIFEST_ONLY
    edges = [EDGE_PARSERS[path.name](path) for path in lockfiles if path.name in EDGE_PARSERS]
    return ResolveResult(resolution=resolution, lockfiles=lockfiles, lockfile_edges=edges)
