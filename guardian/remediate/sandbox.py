"""Apply an approved upgrade to a throwaway copy of the repo and check it resolves.

Nothing here executes repository code on the host: npm runs with ``--ignore-scripts``, pip
resolves wheels only, a Gemfile is evaluated only when it is purely declarative, and project
tests run only inside a network-less, read-only container.
"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from guardian.prepare import BASE_CMD, NPM_TIMEOUT_S
from guardian.remediate.candidates import version_key

IGNORED_DIRS = frozenset({"node_modules", ".git"})
SOURCE_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"})
NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
TOOL_TIMEOUT_S = 300
TEST_TIMEOUT_S = 600
CONTAINER_IMAGE = "node:20-slim"
TEST_LIMITS = ("--cpus", "1", "--memory", "512m", "--pids-limit", "256")
DEFAULT_TEST_SCRIPT = "no test specified"
MAX_OUTPUT = 200_000
FAILURE_TAIL = 800
PLAIN_VERSION_SPEC = re.compile(r"^(\^|~|>=|=)?\s*\d+(?:\.\d+){2}(?:[-+][\w.+-]*)?$")
PIP_REQUIREMENT = re.compile(
    r"^([A-Za-z0-9._-]+)(\[[^\]]*\])?\s*"
    r"([<>=!~]+\s*[^\s;#,]+(?:\s*,\s*[<>=!~]+\s*[^\s;#,]+)*)(.*)$"
)
GEMFILE_DSL = re.compile(
    r"^\s*(?:#.*|source\b.*|gem\s.*|group\b.*|platforms?\b.*|ruby\b.*|end|git_source\b.*|)$"
)


class CommandResult(BaseModel):
    returncode: int
    output: str

    def __init__(self, returncode: int, output: str) -> None:
        super().__init__(returncode=returncode, output=output)


Runner = Callable[[Sequence[str], Path, int], CommandResult]
ParentLookup = Callable[[str, str, str, str], str | None]


class FixTarget(BaseModel):
    ecosystem: str
    package: str
    from_version: str
    to_version: str
    transitive: bool = False
    parent: str | None = None
    parent_version: str | None = None


class StepResult(BaseModel):
    status: Literal["passed", "failed", "unsupported"]
    detail: str = ""
    files: list[str] = []


class TestRun(BaseModel):
    __test__ = False

    status: Literal["passed", "failed", "not_run"]
    reason: str = ""


def run_command(command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
    env = {**os.environ, "npm_config_ignore_scripts": "true"}
    try:
        done = subprocess.run(
            list(command), cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(124, f"timed out after {timeout}s: {command[0]}")
    except OSError as error:
        return CommandResult(127, f"cannot run {command[0]}: {error}")
    if done.returncode == 0:
        return CommandResult(0, done.stdout[-MAX_OUTPUT:].strip())
    return CommandResult(done.returncode, (done.stderr or done.stdout)[-FAILURE_TAIL:].strip())


def create_sandbox(repo: Path, dest: Path) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(repo, dest, ignore=shutil.ignore_patterns(*IGNORED_DIRS))
    return dest


def _files(root: Path, pattern: str) -> Iterator[Path]:
    for path in sorted(root.rglob(pattern)):
        if path.is_file() and not IGNORED_DIRS & set(path.relative_to(root).parts):
            yield path


def _normal(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _rewrite_spec(spec: object, version: str) -> str | None:
    if not isinstance(spec, str) or ":" in spec or "/" in spec:
        return None
    plain = PLAIN_VERSION_SPEC.match(spec)
    return f"{plain[1] or ''}{version}" if plain else f"^{version}"


def _write_manifest(manifest: Path, data: dict[str, Any]) -> None:
    manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _npm_edit(root: Path, target: FixTarget) -> list[Path]:
    changed = []
    for manifest in _files(root, "package.json"):
        data = json.loads(manifest.read_text(encoding="utf-8"))
        for section in NPM_SECTIONS:
            rewritten = _rewrite_spec(data.get(section, {}).get(target.package), target.to_version)
            if rewritten is not None:
                data[section][target.package] = rewritten
                _write_manifest(manifest, data)
                changed.append(manifest)
                break
    return changed


def _npm_override(root: Path, target: FixTarget) -> list[Path]:
    manifests = list(_files(root, "package.json"))
    locked = [m for m in manifests if (m.parent / "package-lock.json").is_file()]
    shallowest = sorted(manifests, key=lambda m: len(m.relative_to(root).parts))[:1]
    changed = []
    for manifest in locked or shallowest:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data.setdefault("overrides", {})[target.package] = target.to_version
        _write_manifest(manifest, data)
        changed.append(manifest)
    return changed


def _pin_line(line: str, target: FixTarget) -> str:
    match = PIP_REQUIREMENT.match(line)
    if match and _normal(match[1]) == _normal(target.package):
        return f"{match[1]}{match[2] or ''}=={target.to_version}{match[4]}"
    return line


def _pip_edit(root: Path, target: FixTarget) -> list[Path]:
    changed = []
    for path in _files(root, "requirements*.txt"):
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        edited = [
            _pin_line(line.rstrip("\n"), target) + ("\n" if line.endswith("\n") else "")
            for line in lines
        ]
        if edited != lines:
            path.write_text("".join(edited), encoding="utf-8")
            changed.append(path)
    return changed


def _gem_line(line: str, target: FixTarget) -> str:
    match = re.match(rf"^(\s*gem\s+['\"]{re.escape(target.package)}['\"])(.*)$", line)
    if not match:
        return line
    rest = re.sub(r",\s*['\"][~<>=!\d][^'\"]*['\"]", "", match[2])
    return f'{match[1]}, "= {target.to_version}"{rest}'


def _gem_edit(root: Path, target: FixTarget) -> list[Path]:
    changed = []
    for path in _files(root, "Gemfile"):
        lines = path.read_text(encoding="utf-8").splitlines()
        edited = [_gem_line(line, target) for line in lines]
        if edited != lines:
            path.write_text("\n".join(edited) + "\n", encoding="utf-8")
            changed.append(path)
    return changed


EDITORS: dict[str, Callable[[Path, FixTarget], list[Path]]] = {
    "npm": _npm_edit, "pypi": _pip_edit, "gem": _gem_edit,
}
MANIFEST_NAMES = {"npm": "package.json", "pypi": "requirements.txt", "gem": "Gemfile"}


def _passed(root: Path, changed: list[Path], detail: str) -> StepResult:
    return StepResult(status="passed", files=[p.relative_to(root).as_posix() for p in changed],
                      detail=detail)


def _apply_transitive(root: Path, target: FixTarget, lookup: ParentLookup | None) -> StepResult:
    parent = target.parent
    newer = lookup(parent, target.parent_version or "", target.package,
                   target.to_version) if lookup and parent else None
    if newer and parent:
        upgrade = FixTarget(ecosystem="npm", package=parent,
                            from_version=target.parent_version or "", to_version=newer)
        changed = _npm_edit(root, upgrade)
        if changed:
            return _passed(root, changed, (
                f"upgraded {parent} to {newer}, which depends on "
                f"{target.package} {target.to_version} or newer"))
    changed = _npm_override(root, target)
    if not changed:
        return StepResult(status="failed", detail="no package.json found to hold an override")
    return _passed(root, changed, (
        f"pinned {target.package} to {target.to_version} with an npm override "
        "(no newer direct parent was found that pulls a fixed version)"))


def apply_upgrade(
    root: Path, target: FixTarget, parent_lookup: ParentLookup | None = None
) -> StepResult:
    editor = EDITORS.get(target.ecosystem)
    if editor is None:
        return StepResult(
            status="unsupported",
            detail=f"unsupported ecosystem '{target.ecosystem}': fixes are applied only to "
            f"{', '.join(sorted(EDITORS))}; make this change manually",
        )
    if target.ecosystem == "npm" and target.transitive:
        return _apply_transitive(root, target, parent_lookup)
    changed = editor(root, target)
    if not changed:
        return StepResult(
            status="failed",
            detail=f"{target.package} {target.from_version} is not declared in a "
            f"{MANIFEST_NAMES[target.ecosystem]} with an editable registry version, so it is "
            "pulled in indirectly; upgrade the package that depends on it",
        )
    return _passed(root, changed, f"set {target.package} to {target.to_version}")


def npm_parent_lookup(run: Runner) -> ParentLookup:
    def lookup(parent: str, version: str, child: str, fixed: str) -> str | None:
        field = f"dependencies.{child}"
        done = run(["npm", "view", f"{parent}@>{version}", "version", field, "--json"],
                   Path.cwd(), NPM_TIMEOUT_S)
        if done.returncode != 0:
            return None
        try:
            rows = json.loads(done.output)
        except json.JSONDecodeError:
            return None
        found = [
            row["version"] for row in (rows if isinstance(rows, list) else [rows])
            if "-" not in row["version"]
            and version_key(str(row.get(field, "0"))) >= version_key(fixed)
        ]
        return min(found, key=version_key) if found else None

    return lookup


def _npm_lock(folder: Path, run: Runner) -> StepResult:
    detail = ""
    for flag in ("", "--legacy-peer-deps"):
        done = run([*BASE_CMD, *([flag] if flag else [])], folder, NPM_TIMEOUT_S)
        if done.returncode == 0 and (folder / "package-lock.json").is_file():
            return StepResult(status="passed", detail="npm resolved the upgraded dependency tree")
        detail = done.output or f"npm exited {done.returncode}"
    return StepResult(status="failed", detail=f"npm could not resolve the upgrade: {detail}")


def _gem_lock(folder: Path, target: FixTarget, run: Runner) -> StepResult:
    lines = (folder / "Gemfile").read_text(encoding="utf-8").splitlines()
    if not all(GEMFILE_DSL.match(line) for line in lines):
        return StepResult(status="failed", detail=(
            "Gemfile contains arbitrary Ruby; it is not evaluated on the host. "
            "Update the gem manually"))
    done = run(["bundle", "lock", "--update", target.package], folder, TOOL_TIMEOUT_S)
    if done.returncode != 0:
        return StepResult(status="failed", detail=f"bundler could not resolve: {done.output}")
    return StepResult(status="passed", detail="bundler resolved the upgraded gem")


def _pip_command() -> list[str] | None:
    if importlib.util.find_spec("pip"):
        return [sys.executable, "-m", "pip"]
    found = shutil.which("pip3") or shutil.which("pip")
    return [found] if found else None


def _pip_resolve(path: Path, run: Runner) -> StepResult:
    pip = _pip_command()
    if pip is None:
        return StepResult(status="failed", detail="pip is not installed on this host")
    command = [*pip, "install", "--dry-run", "--ignore-installed", "--only-binary=:all:",
               "-r", path.name]
    done = run(command, path.parent, TOOL_TIMEOUT_S)
    if done.returncode != 0:
        return StepResult(status="failed", detail=f"pip could not resolve: {done.output}")
    return StepResult(status="passed", detail="pip resolved the pins using wheels only")


def build_check(
    root: Path, target: FixTarget, run: Runner, files: Sequence[str]
) -> StepResult:
    checks: dict[str, Callable[[Path], StepResult]] = {
        "npm": lambda path: _npm_lock(path.parent, run),
        "gem": lambda path: _gem_lock(path.parent, target, run),
        "pypi": lambda path: _pip_resolve(path, run),
    }
    for name in files:
        result = checks[target.ecosystem](root / name)
        if result.status != "passed":
            return result
    return StepResult(status="passed", detail="dependency resolution succeeded")


def _has_source(root: Path) -> bool:
    return any(path.suffix in SOURCE_SUFFIXES for path in _files(root, "*"))


def _test_script(root: Path) -> str | None:
    manifest = root / "package.json"
    if not manifest.is_file():
        return None
    script = json.loads(manifest.read_text(encoding="utf-8")).get("scripts", {}).get("test")
    return None if not script or DEFAULT_TEST_SCRIPT in script else str(script)


def _container(engine: str, root: Path, *, offline: bool) -> list[str]:
    mount = f"{root}:/work" + (":ro" if offline else "")
    isolation = ["--network", "none", "--read-only", "--cap-drop", "ALL"] if offline else []
    user = f"{os.getuid()}:{os.getgid()}"
    return [engine, "run", "--rm", *isolation, *TEST_LIMITS, "--user", user,
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp", "-e", "HOME=/tmp",
            "-v", mount, "-w", "/work", CONTAINER_IMAGE]


def _skipped(reason: str) -> TestRun:
    return TestRun(status="not_run", reason=reason)


def run_tests(root: Path, run: Runner = run_command, engine: str | None = None) -> TestRun:
    if not _has_source(root):
        return _skipped("only manifests were fetched; no source to test")
    if _test_script(root) is None:
        return _skipped("the project defines no test script (scripts.test)")
    if engine is None:
        return _skipped("no container engine (docker/podman); tests never run on the host")
    install = run([*_container(engine, root, offline=False), "npm", "ci", "--ignore-scripts",
                   "--no-audit", "--no-fund"], root, TEST_TIMEOUT_S)
    if install.returncode != 0:
        return _skipped(f"container dependency install failed: {install.output}")
    done = run([*_container(engine, root, offline=True), "npm", "test"], root, TEST_TIMEOUT_S)
    if done.returncode == 0:
        return TestRun(status="passed", reason="npm test passed in an isolated container")
    return TestRun(status="failed", reason=f"npm test failed ({done.returncode}): {done.output}")
