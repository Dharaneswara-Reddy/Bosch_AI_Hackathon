import hashlib
import json
from pathlib import Path

import httpx
import pytest

from guardian.fetch import FetchError, fetch_repo_files

SHA = "a" * 40
LOCK = b'{"lockfileVersion": 3}'
FILES: dict[str, bytes] = {
    "package.json": b"{}",
    "package-lock.json": LOCK,
    "Dockerfile": b"FROM scratch",
    "Dockerfile.dev": b"FROM scratch",
    ".github/workflows/ci.yml": b"on: push",
    "frontend/package.json": b"{}",
    "requirements-dev.txt": b"flask==2.0",
    "src/app.py": b"print(1)",
    "node_modules/x/package.json": b"{}",
    "README.md": b"hi",
}


def _handler(
    tree: list[dict[str, object]] | None = None,
    truncated: bool = False,
    status: int = 200,
    headers: dict[str, str] | None = None,
    calls: list[str] | None = None,
) -> httpx.MockTransport:
    entries = (
        tree
        if tree is not None
        else [{"path": path, "type": "blob", "size": len(body)} for path, body in FILES.items()]
    )

    def handle(request: httpx.Request) -> httpx.Response:
        url = request.url
        if calls is not None:
            calls.append(f"{url.host}{url.path}|{request.headers.get('authorization', '')}")
        if status != 200:
            return httpx.Response(status, headers=headers or {}, json={"message": "nope"})
        if url.host == "raw.githubusercontent.com":
            relative = url.path.removeprefix(f"/o/r/{SHA}/")
            return httpx.Response(200, content=FILES[relative])
        if url.path == "/repos/o/r":
            return httpx.Response(200, json={"private": False, "default_branch": "main"})
        if url.path.startswith("/repos/o/r/commits/"):
            return httpx.Response(200, json={"sha": SHA})
        if url.path == f"/repos/o/r/git/trees/{SHA}":
            return httpx.Response(200, json={"tree": entries, "truncated": truncated})
        return httpx.Response(404, json={})

    return httpx.MockTransport(handle)


def test_downloads_only_manifests_and_records_manifest(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    result = fetch_repo_files(
        "https://github.com/o/r",
        "main",
        dest,
        None,
        transport=_handler(),
    )
    assert result.commit_sha == SHA
    paths = sorted(f.path for f in result.files)
    assert paths == [
        ".github/workflows/ci.yml",
        "Dockerfile",
        "Dockerfile.dev",
        "frontend/package.json",
        "package-lock.json",
        "package.json",
        "requirements-dev.txt",
    ]
    assert not (dest / "src").exists()
    assert not (dest / "node_modules").exists()
    lock = next(f for f in result.files if f.path == "package-lock.json")
    assert lock.sha256 == hashlib.sha256(LOCK).hexdigest()
    assert lock.source == "repo"
    manifest = json.loads((tmp_path / "fetch-manifest.json").read_text())
    assert manifest["commit_sha"] == SHA
    assert len(manifest["files"]) == 7


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/o/r",
        "https://evil.com/o/r",
        "https://github.com/o",
        "https://github.com/o/r/tree/main",
        "https://github.com/o/r?x=1",
        "https://user@github.com/o/r",
    ],
)
def test_rejects_non_repository_urls(tmp_path: Path, url: str) -> None:
    with pytest.raises(FetchError):
        fetch_repo_files(url, "main", tmp_path / "d", None, transport=_handler())


def test_rejects_bad_ref(tmp_path: Path) -> None:
    with pytest.raises(FetchError, match="ref"):
        fetch_repo_files(
            "https://github.com/o/r", "../x", tmp_path / "d", None, transport=_handler()
        )


def test_truncated_tree_fails(tmp_path: Path) -> None:
    with pytest.raises(FetchError, match="truncated"):
        fetch_repo_files(
            "https://github.com/o/r",
            "main",
            tmp_path / "d",
            None,
            transport=_handler(truncated=True),
        )


def test_rate_limit_is_explained(tmp_path: Path) -> None:
    transport = _handler(status=403, headers={"x-ratelimit-remaining": "0"})
    with pytest.raises(FetchError, match="rate limit.*GITHUB_TOKEN"):
        fetch_repo_files(
            "https://github.com/o/r", "main", tmp_path / "d", None, transport=transport
        )


def test_too_many_files_fails(tmp_path: Path) -> None:
    tree: list[dict[str, object]] = [
        {"path": f"d{i}/package.json", "type": "blob", "size": 2} for i in range(401)
    ]
    with pytest.raises(FetchError, match="Too many"):
        fetch_repo_files(
            "https://github.com/o/r", "main", tmp_path / "d", None, transport=_handler(tree=tree)
        )


def test_oversized_file_is_skipped_and_reported(tmp_path: Path) -> None:
    tree: list[dict[str, object]] = [
        {"path": "package.json", "type": "blob", "size": 10_000_000},
    ]
    result = fetch_repo_files(
        "https://github.com/o/r", "main", tmp_path / "d", None, transport=_handler(tree=tree)
    )
    assert result.files == []
    assert "package.json" in result.skipped[0]


def test_token_goes_to_api_only(tmp_path: Path) -> None:
    calls: list[str] = []
    fetch_repo_files(
        "https://github.com/o/r", "main", tmp_path / "d", "tok", transport=_handler(calls=calls)
    )
    api = [c for c in calls if c.startswith("api.github.com")]
    raw = [c for c in calls if c.startswith("raw.githubusercontent.com")]
    assert api and all(c.endswith("Bearer tok") for c in api)
    assert raw and all(c.endswith("|") for c in raw)
