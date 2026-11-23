"""Bring the full source of a GitHub scan into the fix sandbox.

Scans of GitHub repositories fetch only manifests, so the project's build and tests would have
nothing to run. The scanned commit is cloned shallowly into a scratch folder, and the files the
sandbox does not already have are copied over it, so the edited manifests always win. Nothing
from the repository is executed: hooks are disabled and the clone is only read.
"""

import shutil
from pathlib import Path

from guardian.fetch import MANIFEST_NAME, FetchError, FetchResult, parse_github_url
from guardian.remediate.sandbox import IGNORED_DIRS, Runner, StepResult

MAX_SOURCE_BYTES = 150 * 1024 * 1024
GIT_TIMEOUT_S = 180
LOCAL_COMMIT = "local-demo"
SAFE_GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
            "-c", "core.symlinks=false"]


def _tree_size(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*")
               if path.is_file() and ".git" not in path.relative_to(root).parts)


def _copy_missing(source: str, destination: str) -> str:
    if not Path(destination).exists():
        shutil.copy2(source, destination, follow_symlinks=False)
    return destination


def _clone(url: str, sha: str, clone: Path, git: Runner) -> str | None:
    steps = (
        ("git clone", [*SAFE_GIT, "clone", "--depth", "1", "--no-checkout", url, str(clone)]),
        ("git fetch", [*SAFE_GIT, "-C", str(clone), "fetch", "--depth", "1", "origin", sha]),
        ("git checkout", [*SAFE_GIT, "-C", str(clone), "checkout", "--detach", "FETCH_HEAD"]),
    )
    for label, command in steps:
        done = git(command, clone.parent, GIT_TIMEOUT_S)
        if done.returncode != 0:
            return f"{label} failed: {done.output[-300:]}"
    return None


def overlay_source(work_dir: Path, sandbox: Path, git: Runner) -> StepResult:
    manifest = work_dir / MANIFEST_NAME
    if not manifest.is_file():
        return StepResult(status="unsupported", detail="no fetch manifest; using local files")
    fetched = FetchResult.model_validate_json(manifest.read_text(encoding="utf-8"))
    if fetched.commit_sha == LOCAL_COMMIT:
        return StepResult(status="unsupported", detail="local scan already has its source")
    try:
        parse_github_url(fetched.url)
    except FetchError as error:
        return StepResult(status="failed", detail=f"source not cloned: {error}")
    clone = sandbox.parent / "source-clone"
    shutil.rmtree(clone, ignore_errors=True)
    clone.parent.mkdir(parents=True, exist_ok=True)
    try:
        problem = _clone(fetched.url, fetched.commit_sha, clone, git)
        if problem is None and _tree_size(clone) > MAX_SOURCE_BYTES:
            problem = f"repository exceeds the {MAX_SOURCE_BYTES // 2**20} MB size limit"
        if problem is not None:
            return StepResult(status="failed", detail=f"source not cloned: {problem}")
        shutil.copytree(clone, sandbox, symlinks=True, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(*IGNORED_DIRS),
                        copy_function=_copy_missing)
    finally:
        shutil.rmtree(clone, ignore_errors=True)
    return StepResult(status="passed",
                      detail=f"cloned {fetched.commit_sha[:12]} for build and tests")
