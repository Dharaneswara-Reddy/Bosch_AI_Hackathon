from collections.abc import Sequence
from pathlib import Path

from guardian.fetch import MANIFEST_NAME, FetchResult
from guardian.remediate.sandbox import CommandResult
from guardian.remediate.source import MAX_SOURCE_BYTES, overlay_source

SHA = "a" * 40


class FakeGit:
    def __init__(self, fail_on: str | None = None, big: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.fail_on = fail_on
        self.big = big

    def __call__(self, command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
        self.calls.append(list(command))
        verb = next(part for part in command if part in {"clone", "fetch", "checkout"})
        if verb == self.fail_on:
            return CommandResult(128, "fatal: repository not found")
        if verb == "clone":
            clone = Path(command[-1])
            (clone / "src").mkdir(parents=True)
            (clone / "src" / "app.js").write_text("module.exports = 1\n", encoding="utf-8")
            (clone / "package.json").write_text('{"name": "original"}', encoding="utf-8")
            (clone / ".git").mkdir()
            (clone / ".git" / "HEAD").write_text("ref", encoding="utf-8")
            if self.big:
                (clone / "blob.bin").write_bytes(b"0" * (MAX_SOURCE_BYTES + 1))
        return CommandResult(0, "")


def _scan(tmp_path: Path, url: str = "https://github.com/acme/shop", sha: str = SHA) -> Path:
    work = tmp_path / "scan"
    (work / "repo").mkdir(parents=True)
    manifest = FetchResult(url=url, ref="main", commit_sha=sha, dest=work / "repo")
    (work / MANIFEST_NAME).write_text(manifest.model_dump_json(), encoding="utf-8")
    return work


def _sandbox(tmp_path: Path) -> Path:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "package.json").write_text('{"name": "edited"}', encoding="utf-8")
    return sandbox


def test_clones_the_scanned_commit_and_keeps_the_edited_manifest(tmp_path: Path) -> None:
    git = FakeGit()
    sandbox = _sandbox(tmp_path)
    result = overlay_source(_scan(tmp_path), sandbox, git)
    assert result.status == "passed" and SHA[:12] in result.detail
    assert (sandbox / "src" / "app.js").is_file()
    assert (sandbox / "package.json").read_text() == '{"name": "edited"}'
    assert not (sandbox / ".git").exists()
    clone, fetch, checkout = git.calls
    assert "--depth" in clone and "https://github.com/acme/shop" in clone
    assert fetch[-4:] == ["--depth", "1", "origin", SHA]
    assert checkout[-1] == "FETCH_HEAD"


def test_demo_scans_already_have_their_source(tmp_path: Path) -> None:
    git = FakeGit()
    result = overlay_source(_scan(tmp_path, url="Built-in demo", sha="local-demo"),
                            _sandbox(tmp_path), git)
    assert result.status == "unsupported" and git.calls == []


def test_clone_failure_falls_back_to_manifests_with_the_exact_reason(tmp_path: Path) -> None:
    sandbox = _sandbox(tmp_path)
    result = overlay_source(_scan(tmp_path), sandbox, FakeGit(fail_on="fetch"))
    assert result.status == "failed"
    assert "git fetch" in result.detail and "repository not found" in result.detail
    assert not (sandbox / "src").exists()


def test_oversized_repositories_are_refused(tmp_path: Path) -> None:
    result = overlay_source(_scan(tmp_path), _sandbox(tmp_path), FakeGit(big=True))
    assert result.status == "failed" and "size limit" in result.detail


def test_non_github_urls_are_never_cloned(tmp_path: Path) -> None:
    git = FakeGit()
    result = overlay_source(_scan(tmp_path, url="https://evil.example/x/y"),
                            _sandbox(tmp_path), git)
    assert result.status == "failed" and git.calls == []
