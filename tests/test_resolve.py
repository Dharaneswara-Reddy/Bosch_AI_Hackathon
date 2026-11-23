from pathlib import Path

import pytest

from guardian.models import Resolution
from guardian.resolve import resolve_target


def _touch(root: Path, *names: str) -> None:
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")


def test_nested_lockfiles_give_lockfile_resolution(tmp_path: Path) -> None:
    _touch(tmp_path, "package.json", "frontend/package-lock.json", "Gemfile.lock")
    result = resolve_target(tmp_path, tmp_path / "work")
    assert Resolution(result.resolution) is Resolution.LOCKFILE
    assert sorted(path.name for path in result.lockfiles) == ["Gemfile.lock", "package-lock.json"]


def test_manifest_only_target(tmp_path: Path) -> None:
    _touch(tmp_path, "package.json", "requirements.txt")
    result = resolve_target(tmp_path, tmp_path / "work")
    assert Resolution(result.resolution) is Resolution.MANIFEST_ONLY
    assert result.lockfiles == []


@pytest.mark.parametrize("skipped", ["node_modules/x/package-lock.json", ".git/yarn.lock",
                                     "vendor/Gemfile.lock"])
def test_vendored_lockfiles_are_ignored(tmp_path: Path, skipped: str) -> None:
    _touch(tmp_path, skipped)
    assert resolve_target(tmp_path, tmp_path / "work").lockfiles == []


@pytest.mark.parametrize("name", ["yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
                                  "Pipfile.lock", "Cargo.lock", "go.sum", "composer.lock",
                                  "packages.lock.json", "gradle.lockfile",
                                  "npm-shrinkwrap.json"])
def test_each_known_lockfile_is_recognised(tmp_path: Path, name: str) -> None:
    _touch(tmp_path, name)
    assert [path.name for path in resolve_target(tmp_path, tmp_path / "w").lockfiles] == [name]
