"""Produce a CycloneDX SBOM for a directory or image reference with a pinned Syft."""

import shutil
from pathlib import Path
from tempfile import TemporaryDirectory, mkstemp

from guardian.tools import run_tool

SYFT_IMAGE = "anchore/syft@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a"
SYFT_TIMEOUT_S = 600
MOUNT_POINT = "/input"


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
    return sbom
