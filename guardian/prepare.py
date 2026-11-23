"""Generate missing npm lockfiles without running any install scripts."""

import hashlib
import os
import subprocess
from pathlib import Path, PurePosixPath

from guardian.fetch import FetchedFile, FetchResult, write_manifest

NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
BASE_CMD = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--package-lock=true",
            "--no-audit", "--no-fund"]
NPM_TIMEOUT_S = 300


def _folders_missing_lock(files: list[FetchedFile]) -> list[PurePosixPath]:
    names: dict[PurePosixPath, set[str]] = {}
    for item in files:
        pure = PurePosixPath(item.path)
        names.setdefault(pure.parent, set()).add(pure.name)
    return sorted(
        folder for folder, present in names.items()
        if "package.json" in present and not NPM_LOCKS & present
    )


def _run_npm(folder: Path, flag: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "npm_config_ignore_scripts": "true"}
    return subprocess.run(
        [*BASE_CMD, *([flag] if flag else [])], cwd=folder, env=env, capture_output=True,
        text=True, timeout=NPM_TIMEOUT_S, check=False,
    )


def _generate(folder: Path) -> tuple[str | None, str]:
    detail = ""
    for flag in ("", "--legacy-peer-deps"):
        try:
            done = _run_npm(folder, flag)
        except (OSError, subprocess.SubprocessError) as error:
            detail = f"{type(error).__name__}: {error}"
            continue
        if done.returncode == 0 and (folder / "package-lock.json").is_file():
            return flag, ""
        detail = (done.stderr or done.stdout)[-500:].strip() or f"npm exited {done.returncode}"
    return None, detail


def generate_npm_lockfiles(result: FetchResult) -> FetchResult:
    for folder in _folders_missing_lock(result.files):
        relative = (folder / "package-lock.json").as_posix().removeprefix("./")
        flag, detail = _generate(result.dest / folder)
        if flag is None:
            result.errors[f"npm:{(folder / 'package.json').as_posix().removeprefix('./')}"] = detail
            continue
        data = (result.dest / relative).read_bytes()
        result.files.append(FetchedFile(
            path=relative, size=len(data), sha256=hashlib.sha256(data).hexdigest(),
            source="generated", npm_flags=flag,
        ))
    write_manifest(result)
    return result
