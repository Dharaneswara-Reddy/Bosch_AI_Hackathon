import json
from collections.abc import Sequence
from pathlib import Path

from guardian.remediate.sandbox import (
    CommandResult,
    FixTarget,
    apply_upgrade,
    build_check,
    create_sandbox,
    run_tests,
)


class FakeRunner:
    def __init__(self, *results: CommandResult) -> None:
        self.calls: list[tuple[list[str], Path]] = []
        self._results = list(results)

    def __call__(self, command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
        self.calls.append((list(command), cwd))
        return self._results.pop(0) if self._results else CommandResult(0, "")


OK = CommandResult(0, "ok")


def _target(ecosystem: str, package: str, old: str, new: str) -> FixTarget:
    return FixTarget(ecosystem=ecosystem, package=package, from_version=old, to_version=new)


def _write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_create_sandbox_copies_the_repo_without_dependencies_or_git(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo, "package.json", "{}")
    _write(repo, "node_modules/x/index.js", "x")
    _write(repo, ".git/HEAD", "ref")
    sandbox = create_sandbox(repo, tmp_path / "sandbox")
    assert (sandbox / "package.json").is_file()
    assert not (sandbox / "node_modules").exists() and not (sandbox / ".git").exists()
    _write(repo, "later.txt", "y")
    assert create_sandbox(repo, tmp_path / "sandbox").joinpath("later.txt").is_file()


def test_npm_upgrade_edits_the_declaring_manifest_and_keeps_the_range_prefix(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "package.json", json.dumps({
        "dependencies": {"lodash": "^4.17.4"}, "devDependencies": {"minimist": "0.0.8"}}))
    done = apply_upgrade(tmp_path, _target("npm", "lodash", "4.17.4", "4.17.21"))
    assert done.status == "passed" and done.files == ["package.json"]
    done = apply_upgrade(tmp_path, _target("npm", "minimist", "0.0.8", "1.2.6"))
    data = json.loads((tmp_path / "package.json").read_text(encoding="utf-8"))
    assert data["dependencies"]["lodash"] == "^4.17.21"
    assert data["devDependencies"]["minimist"] == "1.2.6"


def test_npm_transitive_package_is_reported_not_raised(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"a": "1.0.0"}}))
    done = apply_upgrade(tmp_path, _target("npm", "jws", "0.2.6", "3.2.3"))
    assert done.status == "failed"
    assert "jws" in done.detail and "not declared" in done.detail


def test_python_pin_is_edited_with_normalised_names(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "Django_Rest==3.0.0  # api\nflask>=1\n")
    done = apply_upgrade(tmp_path, _target("pypi", "django-rest", "3.0.0", "3.1.0"))
    assert done.status == "passed"
    assert (tmp_path / "requirements.txt").read_text(encoding="utf-8") == (
        "Django_Rest==3.1.0  # api\nflask>=1\n")
    assert apply_upgrade(tmp_path, _target("pypi", "flask", "1.0", "2.0")).status == "failed"


def test_gem_constraint_is_added_to_a_declarative_gemfile(tmp_path: Path) -> None:
    _write(tmp_path, "Gemfile", 'source "https://rubygems.org"\ngem "rails", "~> 4.0"\n')
    done = apply_upgrade(tmp_path, _target("gem", "rails", "4.0.0", "4.2.11"))
    assert done.status == "passed"
    assert 'gem "rails", "= 4.2.11"' in (tmp_path / "Gemfile").read_text(encoding="utf-8")


def test_gemfile_with_arbitrary_ruby_is_never_evaluated(tmp_path: Path) -> None:
    _write(tmp_path, "Gemfile", 'system("curl evil")\ngem "rails"\n')
    runner = FakeRunner()
    target = _target("gem", "rails", "4.0.0", "4.2.11")
    done = build_check(tmp_path, target, runner)
    assert done.status == "failed" and "arbitrary Ruby" in done.detail
    assert runner.calls == []


def test_unsupported_ecosystem_is_a_structured_result(tmp_path: Path) -> None:
    done = apply_upgrade(tmp_path, _target("cargo", "serde", "1.0.0", "1.0.1"))
    assert done.status == "unsupported" and "cargo" in done.detail


def test_npm_build_check_regenerates_the_lockfile_without_install_scripts(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"lodash": "1.0.0"}}))
    runner = FakeRunner(OK)
    _write(tmp_path, "package-lock.json", "{}")
    done = build_check(tmp_path, _target("npm", "lodash", "1", "2"), runner)
    assert done.status == "passed"
    [(command, cwd)] = runner.calls
    assert {"--package-lock-only", "--ignore-scripts"} <= set(command) and cwd == tmp_path


def test_npm_build_check_reports_resolution_failure_with_npm_output(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"lodash": "1.0.0"}}))
    runner = FakeRunner(CommandResult(1, "ETARGET no matching version"),
                        CommandResult(1, "ETARGET no matching version"))
    done = build_check(tmp_path, _target("npm", "lodash", "1", "2"), runner)
    assert done.status == "failed" and "ETARGET" in done.detail


def test_gem_build_check_updates_only_the_target_gem(tmp_path: Path) -> None:
    _write(tmp_path, "Gemfile", 'gem "rails"\n')
    runner = FakeRunner(OK)
    done = build_check(tmp_path, _target("gem", "rails", "1", "2"), runner)
    assert done.status == "passed"
    assert runner.calls[0][0] == ["bundle", "lock", "--update", "rails"]


def test_python_build_check_resolves_with_wheels_only(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "flask==2.0.0\n")
    runner = FakeRunner(OK)
    assert build_check(tmp_path, _target("pypi", "flask", "1", "2"), runner).status == "passed"
    command = runner.calls[0][0]
    assert "--only-binary=:all:" in command and "--dry-run" in command


def test_tests_not_run_without_source(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"scripts": {"test": "jest"}}))
    result = run_tests(tmp_path, FakeRunner(), engine="docker")
    assert result.status == "not_run"
    assert result.reason == "only manifests were fetched; no source to test"


def test_tests_not_run_without_a_test_script(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"scripts": {"start": "node a.js"}}))
    _write(tmp_path, "src/a.js", "1")
    result = run_tests(tmp_path, FakeRunner(), engine="docker")
    assert result.status == "not_run" and "no test script" in result.reason


def test_tests_not_run_without_a_container_engine(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"scripts": {"test": "jest"}}))
    _write(tmp_path, "src/a.js", "1")
    runner = FakeRunner()
    result = run_tests(tmp_path, runner, engine=None)
    assert result.status == "not_run" and "container engine" in result.reason
    assert runner.calls == []


def test_tests_run_only_in_an_isolated_container(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"scripts": {"test": "jest"}}))
    _write(tmp_path, "src/a.js", "1")
    runner = FakeRunner(OK, OK)
    result = run_tests(tmp_path, runner, engine="docker")
    assert result.status == "passed"
    install, test = (call[0] for call in runner.calls)
    assert install[0] == "docker" and "--ignore-scripts" in install
    assert "--network" in test and test[test.index("--network") + 1] == "none"
    assert "--read-only" in test and f"{tmp_path}:/work:ro" in test
    assert {"--memory", "--cpus", "--pids-limit"} <= set(test)
    assert test[-2:] == ["npm", "test"]


def test_failing_tests_report_the_output_tail(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"scripts": {"test": "jest"}}))
    _write(tmp_path, "src/a.js", "1")
    runner = FakeRunner(OK, CommandResult(1, "1 test failed"))
    result = run_tests(tmp_path, runner, engine="docker")
    assert result.status == "failed" and "1 test failed" in result.reason
