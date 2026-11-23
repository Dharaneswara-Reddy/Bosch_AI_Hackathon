"""Fetch only dependency manifests, lockfiles, Dockerfiles and workflows from a public repo."""

import fnmatch
import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import quote, urlparse

import httpx
from pydantic import BaseModel, Field

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
MAX_FILES = 400
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 25_000_000
MANIFEST_NAME = "fetch-manifest.json"
SKIPPED_DIRS = {"node_modules", "vendor", ".git"}
EXACT_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    ".npmrc",
    "Gemfile",
    "Gemfile.lock",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "gradle.lockfile",
    "packages.lock.json",
}
NAME_PATTERNS = ("requirements*.txt", "build.gradle*", "*.csproj", "Dockerfile*")
OWNER_REPO = re.compile(r"[A-Za-z0-9_.-]+")
REF = re.compile(r"[A-Za-z0-9_./-]+")


class FetchError(RuntimeError):
    """A fetch failure with a message safe to show to the user."""


class FetchedFile(BaseModel):
    path: str
    size: int = Field(ge=0)
    sha256: str
    source: Literal["repo", "generated"] = "repo"
    npm_flags: str | None = None


class FetchResult(BaseModel):
    url: str
    ref: str
    commit_sha: str
    dest: Path
    files: list[FetchedFile] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


def parse_github_url(url: str) -> tuple[str, str]:
    parsed = urlparse(url.strip())
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise FetchError("Enter a public https://github.com/owner/repository URL")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2 or not all(OWNER_REPO.fullmatch(part) for part in parts):
        raise FetchError("Use a repository URL without a subpath")
    return parts[0], parts[1].removesuffix(".git")


def is_wanted(path: str) -> bool:
    pure = PurePosixPath(path)
    if SKIPPED_DIRS & set(pure.parts[:-1]) or ".." in pure.parts or pure.is_absolute():
        return False
    name = pure.name
    if name in EXACT_NAMES or any(fnmatch.fnmatch(name, p) for p in NAME_PATTERNS):
        return True
    return pure.parent.as_posix() == ".github/workflows" and pure.suffix in {".yml", ".yaml"}


def _api_json(client: httpx.Client, path: str) -> dict[str, object]:
    try:
        response = client.get(f"{API}{path}")
    except httpx.HTTPError as error:
        raise FetchError(f"Could not reach GitHub: {type(error).__name__}") from error
    limited = response.status_code == 429 or (
        response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0"
    )
    if limited:
        raise FetchError("GitHub API rate limit reached; set GITHUB_TOKEN or try again later")
    if response.status_code == 404:
        raise FetchError("Repository or ref not found, or the repository is private")
    if response.status_code >= 400:
        raise FetchError(f"GitHub API returned HTTP {response.status_code}")
    body: dict[str, object] = response.json()
    return body


def _resolve_commit(client: httpx.Client, owner: str, repo: str, ref: str) -> tuple[str, str]:
    meta = _api_json(client, f"/repos/{owner}/{repo}")
    if meta.get("private"):
        raise FetchError("Private repositories are not supported")
    chosen = ref or str(meta.get("default_branch", ""))
    if not REF.fullmatch(chosen) or ".." in chosen or chosen.startswith(("/", "-")):
        raise FetchError("Invalid Git ref")
    commit = _api_json(client, f"/repos/{owner}/{repo}/commits/{quote(chosen, safe='/')}")
    sha = str(commit.get("sha", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise FetchError("GitHub did not return a commit SHA for the ref")
    return chosen, sha


def _select(client: httpx.Client, owner: str, repo: str, sha: str) -> tuple[list[str], list[str]]:
    tree = _api_json(client, f"/repos/{owner}/{repo}/git/trees/{sha}?recursive=1")
    if tree.get("truncated"):
        raise FetchError("Repository tree was truncated by GitHub; cannot build a complete scan")
    listing = tree.get("tree", [])
    entries = [e for e in listing if isinstance(e, dict)] if isinstance(listing, list) else []
    wanted = [e for e in entries if e.get("type") == "blob" and is_wanted(str(e.get("path")))]
    if len(wanted) > MAX_FILES:
        raise FetchError(f"Too many manifest files ({len(wanted)}); the limit is {MAX_FILES}")
    keep: list[str] = []
    skipped: list[str] = []
    for entry in wanted:
        size = int(entry.get("size", 0))
        if size > MAX_FILE_BYTES:
            skipped.append(f"{entry['path']}: {size} bytes exceeds {MAX_FILE_BYTES}")
        else:
            keep.append(str(entry["path"]))
    return keep, skipped


def _download(
    raw: httpx.Client,
    owner: str,
    repo: str,
    sha: str,
    paths: list[str],
    dest: Path,
) -> list[FetchedFile]:
    files: list[FetchedFile] = []
    total = 0
    for path in paths:
        try:
            response = raw.get(f"{RAW}/{owner}/{repo}/{sha}/{quote(path, safe='/')}")
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise FetchError(f"Could not download {path}: {type(error).__name__}") from error
        total += len(response.content)
        if total > MAX_TOTAL_BYTES:
            raise FetchError(f"Selected files exceed the {MAX_TOTAL_BYTES} byte total limit")
        target = dest / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(response.content)
        digest = hashlib.sha256(response.content).hexdigest()
        files.append(FetchedFile(path=path, size=len(response.content), sha256=digest))
    return files


def write_manifest(result: FetchResult) -> None:
    (result.dest.parent / MANIFEST_NAME).write_text(
        result.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )


def fetch_repo_files(
    url: str,
    ref: str,
    dest: Path,
    token: str | None,
    *,
    transport: httpx.BaseTransport | None = None,
) -> FetchResult:
    owner, repo = parse_github_url(url)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "guardian-fetch"}
    api_headers = {**headers, "Authorization": f"Bearer {token}"} if token else headers
    with (
        httpx.Client(headers=api_headers, timeout=25, transport=transport) as api,
        httpx.Client(headers=headers, timeout=25, transport=transport) as raw,
    ):
        chosen, sha = _resolve_commit(api, owner, repo, ref)
        paths, skipped = _select(api, owner, repo, sha)
        dest.mkdir(parents=True, exist_ok=True)
        files = _download(raw, owner, repo, sha, sorted(paths), dest)
    result = FetchResult(
        url=f"https://github.com/{owner}/{repo}",
        ref=chosen,
        commit_sha=sha,
        dest=dest,
        files=files,
        skipped=skipped,
    )
    write_manifest(result)
    return result
