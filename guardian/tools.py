"""Run a configured, digest-pinned scanner against local artifacts."""

import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from time import monotonic
from uuid import uuid4

from guardian.config import IMAGE_DIGEST, TOOL_TIMEOUT_S
from guardian.evidence import file_sha256
from guardian.models import ToolRun


class ToolError(RuntimeError):
    def __init__(self, message: str, run: ToolRun | None = None) -> None:
        super().__init__(message)
        self.run = run


def run_tool(
    name: str, argv: Sequence[str], mounts: Mapping[Path, str], timeout: int = TOOL_TIMEOUT_S,
    *, run_dir: Path, image: str,
) -> ToolRun:
    if name not in {"syft", "grype", "osv"}:
        raise ValueError("Unknown scanner name.")
    if IMAGE_DIGEST.fullmatch(image) is None:
        raise ValueError(f"Configure a SHA-256 image digest for {name}.")
    cmd = [
        "docker", "run", "--rm", "--pull=never", "--network=host",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
    ]
    if name == "grype":
        cmd.extend(["--entrypoint", "/grype"])
    for source, destination in mounts.items():
        host = source.resolve(strict=True)
        valid_mount = re.fullmatch(r"/(?:input|cache)(?:/[\w.-]+)*", destination)
        if "," in str(host) or not valid_mount or {".", ".."} & set(destination.split("/")):
            raise ValueError("Use a read-only mount under /input or /cache.")
        cmd.extend(["--mount", f"type=bind,source={host},target={destination},readonly"])
    cmd.extend([image, *argv])
    raw = run_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    path = raw / f"{name}-{uuid4().hex}.json"
    start = monotonic()
    try:
        with path.open("xb") as stdout:
            process = subprocess.run(cmd, stdout=stdout, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        run = _tool_record(name, cmd, 124, start, path, image)
        raise ToolError(f"{name} timed out after {timeout}s.", run) from error
    except OSError as error:
        raise ToolError(f"{name} could not start: {error}") from error
    run = _tool_record(name, cmd, process.returncode, start, path, image)
    if process.returncode:
        detail = process.stderr[-1000:].decode("utf-8", errors="replace")
        raise ToolError(f"{name} exited with {process.returncode}: {detail}", run)
    return run


def _tool_record(
    name: str, cmd: list[str], status: int, start: float, path: Path, image: str,
) -> ToolRun:
    return ToolRun(
        tool=name, command=cmd, exit_code=status, duration_s=monotonic() - start,
        file=f"raw/{path.name}", sha256=file_sha256(path), tool_version=image,
    )
