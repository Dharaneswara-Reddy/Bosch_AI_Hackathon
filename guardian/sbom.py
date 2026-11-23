"""Produce a CycloneDX SBOM for a directory or image reference with a pinned Syft."""

import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory, mkstemp
from typing import Any

from guardian.resolve.edges import LockfileEdges
from guardian.tools import run_tool

SYFT_IMAGE = "anchore/syft@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a"
SYFT_TIMEOUT_S = 600
MOUNT_POINT = "/input"
ROOT_PREFIX = "guardian:root:"
LOCATION_PROPERTY = "syft:location:0:path"
EDGE_PROPERTY = "guardian:resolver-edge"
SKIPPED_PROPERTY = "guardian:resolver-edges-skipped"


def build_sbom(target: Path | str, resolved: object | None) -> Path:
    mounts: dict[Path, str] = {}
    if isinstance(target, Path):
        mounts[target] = MOUNT_POINT
        source = f"dir:{MOUNT_POINT}"
    else:
        source = target
    with TemporaryDirectory(prefix="guardian-syft-") as run_dir:
        run = run_tool(
            "syft", [source, "-o", "cyclonedx-json", "-q"], mounts, SYFT_TIMEOUT_S,
            run_dir=Path(run_dir), image=SYFT_IMAGE,
        )
        handle, name = mkstemp(prefix="guardian-", suffix=".cdx.json")
        sbom = Path(name)
        with open(handle, "wb") as destination, (Path(run_dir) / run.file).open("rb") as raw:
            shutil.copyfileobj(raw, destination)
    lockfile_edges: list[LockfileEdges] = getattr(resolved, "lockfile_edges", [])
    if lockfile_edges and isinstance(target, Path):
        bom = json.loads(sbom.read_text(encoding="utf-8"))
        merged = merge_resolver_edges(bom, lockfile_edges, target)
        sbom.write_text(json.dumps(merged), encoding="utf-8")
    return sbom


def merge_resolver_edges(
    bom: dict[str, Any], lockfiles: list[LockfileEdges], target: Path
) -> dict[str, Any]:
    if not lockfiles:
        return bom
    refs: dict[str, list[str]] = {}
    for component in bom.get("components", []):
        if component.get("purl") and component.get("bom-ref"):
            refs.setdefault(component["purl"].split("?")[0], []).append(component["bom-ref"])
    dependencies: dict[str, list[str]] = {
        entry["ref"]: list(entry.get("dependsOn", [])) for entry in bom.get("dependencies", [])
    }
    added: list[tuple[str, str]] = []
    skipped = 0
    for lockfile in lockfiles:
        root = _add_root(bom, lockfile.lockfile, target)
        refs[root] = [root]
        pairs = [(root, child) for child in lockfile.direct] + lockfile.edges
        skipped += _merge_pairs(pairs, refs, dependencies, added)
    bom["dependencies"] = [{"ref": ref, "dependsOn": kids} for ref, kids in dependencies.items()]
    properties: list[dict[str, str]] = bom.setdefault("properties", [])
    properties.extend(
        {"name": f"{EDGE_PROPERTY}:{index}", "value": f"{parent} {child}"}
        for index, (parent, child) in enumerate(added)
    )
    properties.append({"name": SKIPPED_PROPERTY, "value": str(skipped)})
    return bom


def _merge_pairs(
    pairs: list[tuple[str, str]],
    refs: dict[str, list[str]],
    dependencies: dict[str, list[str]],
    added: list[tuple[str, str]],
) -> int:
    skipped = 0
    for parent, child in pairs:
        parent_refs, child_refs = refs.get(parent, []), refs.get(child, [])
        if not parent_refs or not child_refs:
            skipped += 1
            continue
        for parent_ref in parent_refs:
            known = dependencies.setdefault(parent_ref, [])
            for child_ref in child_refs:
                if child_ref not in known:
                    known.append(child_ref)
                    added.append((parent_ref, child_ref))
    return skipped


def _add_root(bom: dict[str, Any], lockfile: Path, target: Path) -> str:
    relative = lockfile.relative_to(target).as_posix()
    root = f"{ROOT_PREFIX}{relative}"
    bom.setdefault("components", []).append({
        "bom-ref": root, "type": "application", "name": relative,
        "properties": [
            {"name": "guardian:synthetic", "value": "true"},
            {"name": LOCATION_PROPERTY, "value": f"/{relative}"},
        ],
    })
    return root
