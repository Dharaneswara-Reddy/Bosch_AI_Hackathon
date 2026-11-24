"""Run a project's own build and test scripts, only ever inside a locked-down container.

Dependencies are installed in a container with ``--ignore-scripts`` (the only step with network
access). The ``build`` and ``test`` scripts then run with no network, a read-only source mount,
dropped capabilities and CPU, memory and process limits. Repository code never runs on the host.
"""

import json
import os
import re
import subprocess
import uuid
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from guardian.remediate.sandbox import IGNORED_DIRS, SOURCE_SUFFIXES, CommandResult, Runner, TestRun

CONTAINER_IMAGE = "node:20-slim"
LIMITS = ("--cpus", "1", "--memory", "512m", "--pids-limit", "256")
INSTALL_TIMEOUT_S = 600
BUILD_TIMEOUT_S = 300
TEST_TIMEOUT_S = 600
KILL_TIMEOUT_S = 30
TAIL_LINES = 40
CAPTURE_CHARS = 200_000
DEFAULT_TEST_SCRIPT = "no test specified"
TIMED_OUT = 124
COUNT_LINE = re.compile(r"^\s*(?:#|ℹ)\s+(tests|pass|fail)\s+(\d+)\s*$", re.MULTILINE)
FAILED_TEST = re.compile(
    r"^\s*(?:not ok \d+ - |✖ )(.+?)(?:\s+#.*|\s+\(\d[\d.]*ms\))?$", re.MULTILINE
)


class Validation(BaseModel):
    build: TestRun
    tests: TestRun


def run_captured(command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        done = subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(TIMED_OUT, f"timed out after {timeout}s: {command[0]}")
    except OSError as error:
        return CommandResult(127, f"cannot run {command[0]}: {error}")
    return CommandResult(done.returncode, (done.stdout + done.stderr)[-CAPTURE_CHARS:].strip())


def _has_source(root: Path) -> bool:
    return any(
        path.suffix in SOURCE_SUFFIXES and not IGNORED_DIRS & set(path.relative_to(root).parts)
        for path in root.rglob("*")
        if path.is_file()
    )


def _script(root: Path, name: str) -> str | None:
    manifest = root / "package.json"
    if not manifest.is_file():
        return None
    script = json.loads(manifest.read_text(encoding="utf-8")).get("scripts", {}).get(name)
    return None if not script or DEFAULT_TEST_SCRIPT in script else str(script)


def _container(engine: str, name: str, root: Path, *, offline: bool) -> list[str]:
    mount = f"{root}:/work" + (":ro" if offline else "")
    dns = os.environ.get("GUARDIAN_SANDBOX_DNS", "").strip()
    networked = ["--dns", dns] if dns else []
    isolation = ["--network", "none", "--read-only", "--cap-drop", "ALL"] if offline else networked
    user = f"{os.getuid()}:{os.getgid()}"
    return [
        engine,
        "run",
        "--rm",
        "--name",
        name,
        *isolation,
        *LIMITS,
        "--user",
        user,
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp",
        "-e",
        "HOME=/tmp",
        "-v",
        mount,
        "-w",
        "/work",
        CONTAINER_IMAGE,
    ]


def _run_container(
    capture: Runner, engine: str, root: Path, command: list[str], *, offline: bool, timeout: int
) -> CommandResult:
    name = f"guardian-{uuid.uuid4().hex[:12]}"
    done = capture([*_container(engine, name, root, offline=offline), *command], root, timeout)
    if done.returncode == TIMED_OUT:
        capture([engine, "rm", "-f", name], root, KILL_TIMEOUT_S)
    return done


def _tail(output: str) -> list[str]:
    return output.splitlines()[-TAIL_LINES:]


def _counts(output: str) -> dict[str, int]:
    return {key: int(value) for key, value in COUNT_LINE.findall(output)}


def _failed_names(output: str) -> list[str]:
    names = (name.strip() for name in FAILED_TEST.findall(output))
    return list(dict.fromkeys(name for name in names if name != "failing tests:"))


def _step(label: str, done: CommandResult) -> TestRun:
    counts = _counts(done.output)
    passed, failed, total = counts.get("pass"), counts.get("fail"), counts.get("tests")
    tail = _tail(done.output)
    if done.returncode == 0:
        return TestRun(
            status="passed",
            reason=f"{label} passed in an isolated container",
            passed=passed,
            failed=failed,
            total=total,
            output_tail=tail,
        )
    timed_out = done.output if done.returncode == TIMED_OUT else ""
    return TestRun(
        status="failed",
        passed=passed,
        failed=failed,
        total=total,
        output_tail=tail,
        failed_tests=_failed_names(done.output),
        reason=timed_out or f"{label} failed (exit {done.returncode})",
    )


def _not_run(reason: str) -> TestRun:
    return TestRun(status="not_run", reason=reason)


def _both(reason: str) -> Validation:
    return Validation(build=_not_run(reason), tests=_not_run(reason))


NO_BUILD_SCRIPT = "the project defines no build script (scripts.build)"
NO_TEST_SCRIPT = "the project defines no test script (scripts.test)"


def _offline_step(
    capture: Runner, engine: str, root: Path, command: list[str], timeout: int
) -> TestRun:
    done = _run_container(capture, engine, root, command, offline=True, timeout=timeout)
    return _step(" ".join(command), done)


def _build_then_test(
    capture: Runner, engine: str, root: Path, build_script: str | None, test_script: str | None
) -> Validation:
    build = _not_run(NO_BUILD_SCRIPT)
    if build_script is not None:
        build = _offline_step(capture, engine, root, ["npm", "run", "build"], BUILD_TIMEOUT_S)
    if build.status == "failed":
        return Validation(build=build, tests=_not_run("not run because the build failed"))
    tests = _not_run(NO_TEST_SCRIPT)
    if test_script is not None:
        tests = _offline_step(capture, engine, root, ["npm", "test"], TEST_TIMEOUT_S)
    return Validation(build=build, tests=tests)


def validate_project(
    root: Path, capture: Runner, engine: str | None, source_note: str = ""
) -> Validation:
    if not _has_source(root):
        note = f" ({source_note})" if source_note else ""
        return _both(f"only manifests were fetched; no source to test{note}")
    build_script, test_script = _script(root, "build"), _script(root, "test")
    if build_script is None and test_script is None:
        return Validation(build=_not_run(NO_BUILD_SCRIPT), tests=_not_run(NO_TEST_SCRIPT))
    if engine is None:
        return _both("no container engine (docker/podman); project code never runs on the host")
    install = _run_container(
        capture,
        engine,
        root,
        ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        offline=False,
        timeout=INSTALL_TIMEOUT_S,
    )
    if install.returncode != 0:
        return _both(f"container dependency install failed: {install.output[-300:]}")
    return _build_then_test(capture, engine, root, build_script, test_script)
