"""Collect evidence for manifest, lockfile, Dockerfile and workflow changes."""

from __future__ import annotations

import hashlib
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guardian.detectors._common import DetectionResult, coverage_rows, sha256_bytes
from guardian.models import CoverageStatus, Evidence

_LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "cargo.lock",
    "go.sum",
    "composer.lock",
    "gemfile.lock",
}
_MANIFESTS = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "pipfile",
    "cargo.toml",
    "go.mod",
    "composer.json",
    "gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def _git(root: Path, *arguments: str, binary: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=not binary,
    )


def _relevant(path: str) -> bool:
    normalized = path.replace("\\", "/")
    name = normalized.rsplit("/", 1)[-1].casefold()
    return (
        name in _LOCKFILES
        or name in _MANIFESTS
        or name.startswith("dockerfile")
        or normalized.startswith(".github/workflows/")
    )


def _line_pointer(diff: str) -> str:
    ranges = []
    for match in _HUNK.finditer(diff):
        start = int(match.group(3))
        count = int(match.group(4) or "1")
        end = max(start, start + count - 1)
        ranges.append((start, end))
    if not ranges:
        return "lines:UNKNOWN"
    return "lines:" + ",".join(f"{start}-{end}" for start, end in ranges)


def _baseline_bytes(root: Path, baseline_commit: str, path: str) -> bytes | None:
    result = _git(root, "show", f"{baseline_commit}:{path}", binary=True)
    return result.stdout if result.returncode == 0 else None


def detect(
    target_path: Path,
    baseline_commit: str | None,
    *,
    ecosystems: list[str] | None = None,
) -> DetectionResult:
    root = Path(target_path)
    known_ecosystems = sorted(set(ecosystems or [])) or ["any"]
    counts = {ecosystem: 0 for ecosystem in known_ecosystems}
    if not baseline_commit:
        return DetectionResult(
            coverage=coverage_rows(
                "git_diff",
                known_ecosystems,
                CoverageStatus.NOT_APPLICABLE,
                "No baseline commit",
                counts,
            )
        )
    name_result = _git(
        root, "diff", "--name-only", "--diff-filter=ACDMRTUXB", baseline_commit, "--"
    )
    if name_result.returncode != 0:
        return DetectionResult(
            coverage=coverage_rows(
                "git_diff",
                known_ecosystems,
                CoverageStatus.ERROR,
                name_result.stderr.strip(),
                counts,
            )
        )
    evidence: list[Evidence] = []
    artifacts: dict[str, bytes] = {}
    for path in sorted(set(name_result.stdout.splitlines())):
        if not _relevant(path):
            continue
        patch_result = _git(
            root, "diff", "--no-ext-diff", "--unified=0", baseline_commit, "--", path
        )
        if patch_result.returncode != 0:
            continue
        patch = patch_result.stdout
        old_content = _baseline_bytes(root, baseline_commit, path)
        current_path = root / Path(path)
        new_content = current_path.read_bytes() if current_path.is_file() else None
        old_hash = sha256_bytes(old_content) if old_content is not None else "UNKNOWN"
        new_hash = sha256_bytes(new_content) if new_content is not None else "UNKNOWN"
        patch_bytes = patch.encode("utf-8")
        artifact_file = f"raw/git-diff/{path}.patch"
        pointer = (
            f"target_file={path};{_line_pointer(patch)};old_sha256={old_hash};new_sha256={new_hash}"
        )
        evidence_id = hashlib.sha256(
            f"git_diff\0{artifact_file}\0{pointer}\0{sha256_bytes(patch_bytes)}".encode()
        ).hexdigest()[:24]
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                tool="guardian:git_diff",
                tool_version="1",
                file=artifact_file,
                pointer=pointer,
                sha256=sha256_bytes(patch_bytes),
                collected_at=datetime.now(UTC),
            )
        )
        artifacts[artifact_file] = patch_bytes
    status = CoverageStatus.FINDING if evidence else CoverageStatus.PASS
    return DetectionResult(
        evidence=evidence,
        coverage=coverage_rows("git_diff", known_ecosystems, status, "", counts),
        artifacts=artifacts,
    )
