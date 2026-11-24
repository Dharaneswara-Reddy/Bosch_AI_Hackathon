import json
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from guardian.remediate import sandbox
from guardian.remediate.sandbox import (
    CommandResult,
    FixTarget,
    apply_upgrade,
    build_check,
    create_sandbox,
    npm_parent_lookup,
    run_command,
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
    assert apply_upgrade(tmp_path, _target("pypi", "flask", "1.0", "2.0")).status == "passed"


def test_gem_constraint_is_added_to_a_declarative_gemfile(tmp_path: Path) -> None:
    _write(tmp_path, "Gemfile", 'source "https://rubygems.org"\ngem "rails", "~> 4.0"\n')
    done = apply_upgrade(tmp_path, _target("gem", "rails", "4.0.0", "4.2.11"))
    assert done.status == "passed"
    assert 'gem "rails", "= 4.2.11"' in (tmp_path / "Gemfile").read_text(encoding="utf-8")


def test_gemfile_with_arbitrary_ruby_is_never_evaluated(tmp_path: Path) -> None:
    _write(tmp_path, "Gemfile", 'system("curl evil")\ngem "rails"\n')
    runner = FakeRunner()
    target = _target("gem", "rails", "4.0.0", "4.2.11")
    done = build_check(tmp_path, target, runner, ["Gemfile"])
    assert done.status == "failed" and "arbitrary Ruby" in done.detail
    assert runner.calls == []


def test_unsupported_ecosystem_is_a_structured_result(tmp_path: Path) -> None:
    done = apply_upgrade(tmp_path, _target("cargo", "serde", "1.0.0", "1.0.1"))
    assert done.status == "unsupported" and "cargo" in done.detail


def test_npm_build_check_regenerates_the_lockfile_without_install_scripts(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"lodash": "1.0.0"}}))
    runner = FakeRunner(OK)
    _write(tmp_path, "package-lock.json", "{}")
    done = build_check(tmp_path, _target("npm", "lodash", "1", "2"), runner, ["package.json"])
    assert done.status == "passed"
    [(command, cwd)] = runner.calls
    assert {"--package-lock-only", "--ignore-scripts"} <= set(command) and cwd == tmp_path


def test_npm_build_check_reports_resolution_failure_with_npm_output(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"lodash": "1.0.0"}}))
    runner = FakeRunner(CommandResult(1, "ETARGET no matching version"),
                        CommandResult(1, "ETARGET no matching version"))
    done = build_check(tmp_path, _target("npm", "lodash", "1", "2"), runner, ["package.json"])
    assert done.status == "failed" and "ETARGET" in done.detail


def test_gem_build_check_updates_only_the_target_gem(tmp_path: Path) -> None:
    _write(tmp_path, "Gemfile", 'gem "rails"\n')
    runner = FakeRunner(OK)
    done = build_check(tmp_path, _target("gem", "rails", "1", "2"), runner, ["Gemfile"])
    assert done.status == "passed"
    assert runner.calls[0][0] == ["bundle", "lock", "--update", "rails"]


def test_python_build_check_resolves_with_wheels_only(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "flask==2.0.0\n")
    runner = FakeRunner(OK)
    done = build_check(tmp_path, _target("pypi", "flask", "1", "2"), runner, ["requirements.txt"])
    assert done.status == "passed"
    command = runner.calls[0][0]
    assert "--only-binary=:all:" in command and "--dry-run" in command



def _transitive(package: str = "jws", old: str = "0.2.6", new: str = "3.2.3") -> FixTarget:
    return FixTarget(ecosystem="npm", package=package, from_version=old, to_version=new,
                     transitive=True, parent="express-jwt", parent_version="0.1.3")


def _spec(root: Path, section: str, package: str) -> str:
    data = json.loads((root / "package.json").read_text(encoding="utf-8"))
    return str(data[section][package])


@pytest.mark.parametrize(("before", "after"), [
    ("^4.17.4", "^4.17.21"), ("~4.17.4", "~4.17.21"), ("4.17.4", "4.17.21"),
    (">=4.0.0", ">=4.17.21"), (">=4.0.0 <5", "^4.17.21"), ("4.x", "^4.17.21"), ("*", "^4.17.21"),
])
def test_npm_declared_ranges_are_rewritten_to_admit_the_fix(
    tmp_path: Path, before: str, after: str
) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"lodash": before}}))
    done = apply_upgrade(tmp_path, _target("npm", "lodash", "4.17.4", "4.17.21"))
    assert done.status == "passed"
    assert _spec(tmp_path, "dependencies", "lodash") == after


def test_npm_non_registry_specs_are_left_alone(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"x": "file:vendor/x"}}))
    assert apply_upgrade(tmp_path, _target("npm", "x", "1", "2")).status == "failed"


def test_transitive_npm_package_is_pinned_with_an_override_in_the_locked_manifest(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"express-jwt": "0.1.3"}}))
    _write(tmp_path, "package-lock.json", "{}")
    _write(tmp_path, "docs/package.json", "{}")
    done = apply_upgrade(tmp_path, _transitive())
    assert done.status == "passed" and done.files == ["package.json"]
    assert "override" in done.detail
    assert _spec(tmp_path, "overrides", "jws") == "3.2.3"
    assert _spec(tmp_path, "dependencies", "express-jwt") == "0.1.3"


def test_transitive_override_keeps_existing_overrides(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"overrides": {"other": "1.0.0"}}))
    apply_upgrade(tmp_path, _transitive())
    data = json.loads((tmp_path / "package.json").read_text(encoding="utf-8"))
    assert data["overrides"] == {"other": "1.0.0", "jws": "3.2.3"}


def test_transitive_fix_upgrades_the_parent_when_a_newer_one_pulls_the_fix(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"express-jwt": "0.1.3"}}))
    asked: list[tuple[str, str, str, str]] = []

    def lookup(parent: str, version: str, child: str, fixed: str) -> str | None:
        asked.append((parent, version, child, fixed))
        return "7.7.8"

    done = apply_upgrade(tmp_path, _transitive(), lookup)
    assert done.status == "passed" and "express-jwt" in done.detail and "7.7.8" in done.detail
    assert asked == [("express-jwt", "0.1.3", "jws", "3.2.3")]
    assert _spec(tmp_path, "dependencies", "express-jwt") == "7.7.8"
    assert "overrides" not in json.loads((tmp_path / "package.json").read_text(encoding="utf-8"))


def test_transitive_fix_falls_back_to_an_override_when_no_parent_helps(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"express-jwt": "0.1.3"}}))
    done = apply_upgrade(tmp_path, _transitive(), lambda *_: None)
    assert done.status == "passed" and "override" in done.detail
    assert _spec(tmp_path, "overrides", "jws") == "3.2.3"


def _view(*entries: dict[str, str]) -> FakeRunner:
    return FakeRunner(CommandResult(0, json.dumps(list(entries))))


def test_parent_lookup_picks_the_lowest_newer_parent_whose_dependency_admits_the_fix() -> None:
    runner = _view(
        {"version": "1.0.0", "dependencies.jws": "~0.2.6"},
        {"version": "9.0.0", "dependencies.jws": "^4.0.0"},
        {"version": "7.7.8", "dependencies.jws": "^3.2.3"},
        {"version": "8.0.0-beta.1", "dependencies.jws": "^3.2.3"},
        {"version": "6.0.0"},
    )
    found = npm_parent_lookup(runner)("express-jwt", "0.1.3", "jws", "3.2.3")
    assert found == "7.7.8"
    [(command, _)] = runner.calls
    assert command[:3] == ["npm", "view", "express-jwt@>0.1.3"] and "--json" in command


def test_parent_lookup_handles_a_single_match_and_unusable_output() -> None:
    single = FakeRunner(CommandResult(0, json.dumps(
        {"version": "2.0.0", "dependencies.jws": "^3.2.3"})))
    assert npm_parent_lookup(single)("p", "1.0.0", "jws", "3.2.3") == "2.0.0"
    plain_versions = CommandResult(0, '["0.2.0", "0.2.1"]')
    error_object = CommandResult(0, '{"error": {"code": "E404"}}')
    unusable = (CommandResult(1, "E404"), CommandResult(0, "not json"), CommandResult(0, "[]"),
                plain_versions, error_object)
    for result in unusable:
        assert npm_parent_lookup(FakeRunner(result))("p", "1.0.0", "jws", "3.2.3") is None


def test_run_command_keeps_the_whole_stdout_of_a_successful_command(tmp_path: Path) -> None:
    done = run_command([sys.executable, "-c", "print('x' * 5000)"], tmp_path, 30)
    assert done.returncode == 0 and len(done.output) == 5000


def test_python_specifiers_are_replaced_with_the_fixed_pin(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt",
           "requests>=2.0,<3  # http\nurllib3[socks] ~= 1.20 ; python_version>'3'\nDjango==1.0\n")
    for package, old, new in (("requests", "2.19.0", "2.32.4"), ("urllib3", "1.20", "1.26.19")):
        assert apply_upgrade(tmp_path, _target("pypi", package, old, new)).status == "passed"
    assert (tmp_path / "requirements.txt").read_text(encoding="utf-8") == (
        "requests==2.32.4  # http\nurllib3[socks]==1.26.19 ; python_version>'3'\nDjango==1.0\n")


def test_unpinned_python_requirement_is_not_edited(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "requests\n")
    assert apply_upgrade(tmp_path, _target("pypi", "requests", "2", "3")).status == "failed"


def test_build_check_resolves_every_edited_manifest_folder(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"overrides": {"jws": "3.2.3"}}))
    _write(tmp_path, "package-lock.json", "{}")
    runner = FakeRunner(OK)
    done = build_check(tmp_path, _transitive(), runner, ["package.json"])
    assert done.status == "passed" and len(runner.calls) == 1


def test_transitive_override_needs_no_known_parent(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", "{}")
    target = FixTarget(ecosystem="npm", package="jws", from_version="0.2.6", to_version="3.2.3",
                       transitive=True)
    assert apply_upgrade(tmp_path, target, lambda *_: "9.9.9").status == "passed"
    assert _spec(tmp_path, "overrides", "jws") == "3.2.3"


def test_pip_falls_back_to_the_pip_on_path_when_the_interpreter_has_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(
        sandbox.shutil, "which", lambda name: "/usr/bin/pip3" if name == "pip3" else None)
    _write(tmp_path, "requirements.txt", "flask==2.0.0\n")
    runner = FakeRunner(OK)
    build_check(tmp_path, _target("pypi", "flask", "1", "2"), runner, ["requirements.txt"])
    assert runner.calls[0][0][:3] == ["/usr/bin/pip3", "install", "--dry-run"]


def test_missing_pip_is_a_structured_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    _write(tmp_path, "requirements.txt", "flask==2.0.0\n")
    runner = FakeRunner()
    done = build_check(tmp_path, _target("pypi", "flask", "1", "2"), runner, ["requirements.txt"])
    assert done.status == "failed" and "pip is not installed" in done.detail
    assert runner.calls == []
