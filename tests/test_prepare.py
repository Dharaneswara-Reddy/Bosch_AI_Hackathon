import json
import subprocess
from pathlib import Path

import pytest

from guardian.fetch import FetchedFile, FetchResult
from guardian.prepare import generate_npm_lockfiles


def _result(tmp_path: Path, names: list[str]) -> FetchResult:
    dest = tmp_path / "repo"
    files = []
    for name in names:
        path = dest / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
        files.append(FetchedFile(path=name, size=2, sha256="x"))
    return FetchResult(url="u", ref="main", commit_sha="a" * 40, dest=dest, files=files)


class FakeNpm:
    def __init__(self, fail_first: bool = False, always_fail: bool = False) -> None:
        self.calls: list[tuple[list[str], Path]] = []
        self.fail_first, self.always_fail = fail_first, always_fail

    def __call__(self, cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        cwd = Path(str(kwargs["cwd"]))
        self.calls.append((cmd, cwd))
        failing = self.always_fail or (self.fail_first and len(self.calls) == 1)
        if failing:
            return subprocess.CompletedProcess(cmd, 1, "", "ERESOLVE boom")
        (cwd / "package-lock.json").write_text('{"lockfileVersion": 3}')
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_generates_missing_lockfiles_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeNpm()
    monkeypatch.setattr("guardian.prepare.subprocess.run", fake)
    result = _result(tmp_path, ["package.json", "frontend/package.json", "app/package.json",
                                "app/yarn.lock"])
    out = generate_npm_lockfiles(result)
    assert sorted(c[1].name for c in fake.calls) == ["frontend", "repo"]
    for cmd, _ in fake.calls:
        assert "--ignore-scripts" in cmd and "--package-lock-only" in cmd
    generated = {f.path: f for f in out.files if f.source == "generated"}
    assert set(generated) == {"package-lock.json", "frontend/package-lock.json"}
    assert generated["package-lock.json"].npm_flags == ""
    manifest = json.loads((tmp_path / "fetch-manifest.json").read_text())
    assert {f["source"] for f in manifest["files"]} == {"repo", "generated"}


def test_retries_with_legacy_peer_deps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeNpm(fail_first=True)
    monkeypatch.setattr("guardian.prepare.subprocess.run", fake)
    out = generate_npm_lockfiles(_result(tmp_path, ["package.json"]))
    assert "--legacy-peer-deps" in fake.calls[1][0]
    assert out.files[-1].npm_flags == "--legacy-peer-deps"
    assert out.errors == {}


def test_failure_is_recorded_not_raised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("guardian.prepare.subprocess.run", FakeNpm(always_fail=True))
    out = generate_npm_lockfiles(_result(tmp_path, ["package.json"]))
    assert "ERESOLVE" in out.errors["npm:package.json"]
    assert all(f.source == "repo" for f in out.files)
