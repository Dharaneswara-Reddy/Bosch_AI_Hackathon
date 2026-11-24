import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from guardian.remediate.sandbox import CommandResult
from guardian.remediate.validate import validate_project

TAP_PASS = "ok 1 - a\nok 2 - b\n1..2\n# tests 2\n# suites 0\n# pass 2\n# fail 0\n"
TAP_FAIL = (
    "not ok 1 - auth rejects a missing token\n  ---\n  error: boom\n"
    "ok 2 - lodash groups\nnot ok 3 - server answers\n"
    "# tests 3\n# pass 1\n# fail 2\n"
)
OK = CommandResult(0, "ok")


class FakeCapture:
    def __init__(self, *results: CommandResult) -> None:
        self.calls: list[list[str]] = []
        self._results = list(results)

    def __call__(self, command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
        self.calls.append(list(command))
        return self._results.pop(0) if self._results else OK


def _project(root: Path, scripts: dict[str, str], source: bool = True) -> Path:
    (root / "package.json").write_text(json.dumps({"scripts": scripts}), encoding="utf-8")
    if source:
        (root / "src").mkdir()
        (root / "src" / "a.js").write_text("1", encoding="utf-8")
    return root


def test_not_run_without_source(tmp_path: Path) -> None:
    result = validate_project(
        _project(tmp_path, {"test": "jest"}, source=False), FakeCapture(), "docker"
    )
    assert result.tests.status == "not_run"
    assert result.tests.reason == "only manifests were fetched; no source to test"
    assert result.build.status == "not_run"


def test_source_note_explains_why_source_is_missing(tmp_path: Path) -> None:
    result = validate_project(
        _project(tmp_path, {"test": "jest"}, source=False),
        FakeCapture(),
        "docker",
        source_note="git clone failed: 404",
    )
    assert result.tests.reason == (
        "only manifests were fetched; no source to test (git clone failed: 404)"
    )


def test_not_run_without_a_test_script(tmp_path: Path) -> None:
    root = _project(tmp_path, {"start": "node a.js", "test": 'echo "Error: no test specified"'})
    capture = FakeCapture()
    result = validate_project(root, capture, "docker")
    assert result.tests.status == "not_run" and "no test script" in result.tests.reason
    assert result.build.status == "not_run" and "no build script" in result.build.reason
    assert capture.calls == []


def test_configured_dns_is_given_only_to_the_networked_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDIAN_SANDBOX_DNS", "1.1.1.1")
    capture = FakeCapture(OK, OK, CommandResult(0, TAP_PASS))
    validate_project(_project(tmp_path, {"build": "tsc", "test": "node --test"}), capture, "docker")
    install, build, test = capture.calls
    assert install[install.index("--dns") + 1] == "1.1.1.1"
    assert "--dns" not in build and "--dns" not in test


def test_not_run_without_a_container_engine(tmp_path: Path) -> None:
    capture = FakeCapture()
    result = validate_project(_project(tmp_path, {"test": "jest"}), capture, None)
    assert result.tests.status == "not_run" and "container engine" in result.tests.reason
    assert capture.calls == []


def test_install_then_isolated_build_and_test(tmp_path: Path) -> None:
    capture = FakeCapture(OK, OK, CommandResult(0, TAP_PASS))
    result = validate_project(
        _project(tmp_path, {"build": "tsc", "test": "node --test"}), capture, "docker"
    )
    install, build, test = capture.calls
    assert install[:2] == ["docker", "run"] and "--ignore-scripts" in install
    assert "--network" not in install
    for command, script in ((build, "build"), (test, "test")):
        assert command[command.index("--network") + 1] == "none"
        assert "--read-only" in command and f"{tmp_path}:/work:ro" in command
        assert {"--memory", "--cpus", "--pids-limit", "--name"} <= set(command)
        assert command[-3:] == ["npm", "run", script] or command[-2:] == ["npm", "test"]
    assert result.build.status == "passed"
    assert (result.tests.status, result.tests.passed, result.tests.total) == ("passed", 2, 2)


def test_failing_tests_report_counts_names_and_output_tail(tmp_path: Path) -> None:
    capture = FakeCapture(OK, CommandResult(1, TAP_FAIL))
    result = validate_project(_project(tmp_path, {"test": "node --test"}), capture, "docker")
    tests = result.tests
    assert tests.status == "failed"
    assert (tests.passed, tests.failed, tests.total) == (1, 2, 3)
    assert tests.failed_tests == ["auth rejects a missing token", "server answers"]
    assert "# fail 2" in tests.output_tail[-1]
    assert result.build.status == "not_run"


def test_output_tail_keeps_only_the_last_forty_lines(tmp_path: Path) -> None:
    noisy = "\n".join(f"line {n}" for n in range(100))
    result = validate_project(
        _project(tmp_path, {"test": "x"}), FakeCapture(OK, CommandResult(1, noisy)), "docker"
    )
    assert result.tests.output_tail[0] == "line 60" and len(result.tests.output_tail) == 40


def test_failed_build_skips_the_tests(tmp_path: Path) -> None:
    capture = FakeCapture(OK, CommandResult(2, "SyntaxError: bad"))
    result = validate_project(_project(tmp_path, {"build": "b", "test": "t"}), capture, "docker")
    assert result.build.status == "failed" and "SyntaxError" in result.build.output_tail[-1]
    assert result.tests.status == "not_run" and "build failed" in result.tests.reason
    assert len(capture.calls) == 2


def test_failed_install_is_reported_not_silently_ignored(tmp_path: Path) -> None:
    capture = FakeCapture(CommandResult(1, "E404 not found"))
    result = validate_project(_project(tmp_path, {"test": "t"}), capture, "docker")
    assert result.tests.status == "not_run"
    assert "install failed" in result.tests.reason and "E404" in result.tests.reason


def test_a_timed_out_container_is_killed_by_name(tmp_path: Path) -> None:
    capture = FakeCapture(OK, CommandResult(124, "timed out after 600s: docker"), OK)
    result = validate_project(_project(tmp_path, {"test": "t"}), capture, "docker")
    run_command = capture.calls[1]
    name = run_command[run_command.index("--name") + 1]
    assert capture.calls[2] == ["docker", "rm", "-f", name]
    assert result.tests.status == "failed" and "timed out" in result.tests.reason
