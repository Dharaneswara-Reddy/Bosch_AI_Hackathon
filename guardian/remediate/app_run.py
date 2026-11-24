"""Build the fixed project's own image, run it, check it answers, and scan the built image.

The container is published only on 127.0.0.1 (ephemeral host port), read-only, with every
capability dropped and CPU, memory and process limits. It is always removed afterwards.
The built image is exported with ``docker save`` and scanned by the pinned Grype image against
its offline database, so OS packages of the base image show up as "image-only" findings.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from guardian.remediate.sandbox import Runner, TestRun
from guardian.remediate.validate import CONTAINER_IMAGE, KILL_TIMEOUT_S, LIMITS, TAIL_LINES
from guardian.scanners.grype import GRYPE_DB_DIR, GRYPE_DB_VOLUME, GRYPE_IMAGE

DEFAULT_PORT = 3000
DEFAULT_HEALTH_PATH = "/health"
HEALTH_TIMEOUT_S = 60
HEALTH_INTERVAL_S = 1.0
HEALTH_REQUEST_TIMEOUT_S = 5.0
BUILD_TIMEOUT_S = 900
SAVE_TIMEOUT_S = 300
SCAN_TIMEOUT_S = 600
SNIPPET_CHARS = 200
LOG_TAIL_CHARS = 400
IMAGE_ONLY_LIMIT = 10
SERIOUS = ("critical", "high")
SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")
EXPOSE = re.compile(r"^\s*EXPOSE\s+(\d+)", re.MULTILINE | re.IGNORECASE)
VULNS_FILE = "image-vulns.json"
TAR_FILE = "image.tar"

HttpGet = Callable[[str, float], tuple[int, str]]


class AppRun(BaseModel):
    status: Literal["passed", "failed", "not_run"]
    reason: str = ""
    health_url: str = ""
    http_status: int | None = None
    response_snippet: str = ""
    image_vulns: dict[str, int] | None = None
    image_only: list[str] = []
    image_only_serious: int = 0
    image_error: str = ""


def http_get(url: str, timeout: float) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - 127.0.0.1 only
            return int(response.status), response.read(SNIPPET_CHARS).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read(SNIPPET_CHARS).decode("utf-8", "replace")


def not_run_reason(root: Path, tests: TestRun | None, engine: str | None) -> str | None:
    if tests is None or tests.status != "passed":
        return "the tests did not pass, so the application was not started"
    if not (root / "Dockerfile").is_file():
        return "no Dockerfile in the project; there is no image to build and run"
    if engine is None:
        return "no container engine (docker/podman); the application was not started"
    return None


def _port(root: Path) -> int:
    found = EXPOSE.search((root / "Dockerfile").read_text(encoding="utf-8", errors="replace"))
    return int(found.group(1)) if found else DEFAULT_PORT


def _build_command(engine: str, tag: str) -> list[str]:
    dns = os.environ.get("GUARDIAN_SANDBOX_DNS", "").strip()
    host_network = ["--network", "host"] if dns else []
    return [engine, "build", "-t", tag, *host_network, "."]


def _start_command(engine: str, name: str, tag: str, port: int) -> list[str]:
    return [
        engine, "run", "-d", "--name", name, "-p", f"127.0.0.1::{port}",
        "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", *LIMITS, tag,
    ]  # fmt: skip


def _poll_health(url: str, get: HttpGet, timeout_s: float) -> tuple[int | None, str, str]:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status, body = get(url, HEALTH_REQUEST_TIMEOUT_S)
            error = f"HTTP {status}"
            if 200 <= status < 300:
                return status, body.strip()[:SNIPPET_CHARS], ""
            last: tuple[int | None, str] = (status, body.strip()[:SNIPPET_CHARS])
        except OSError as failure:
            error, last = str(failure), (None, "")
        if time.monotonic() >= deadline:
            return last[0], last[1], error
        time.sleep(HEALTH_INTERVAL_S)


def _health(
    capture: Runner, engine: str, root: Path, name: str, port: int, get: HttpGet, timeout_s: float
) -> AppRun:
    path = os.environ.get("GUARDIAN_APP_HEALTH_PATH", DEFAULT_HEALTH_PATH)
    mapped = capture([engine, "port", name, f"{port}/tcp"], root, KILL_TIMEOUT_S)
    host_port = mapped.output.splitlines()[0].rsplit(":", 1)[-1] if mapped.output else ""
    url = f"http://127.0.0.1:{host_port}{path}"
    polled = _poll_health(url, get, timeout_s) if host_port else (None, "", "no port published")
    status, snippet, error = polled
    if not error:
        return AppRun(status="passed", health_url=url, http_status=status, response_snippet=snippet)
    logs = capture([engine, "logs", "--tail", str(TAIL_LINES), name], root, KILL_TIMEOUT_S)
    tail = logs.output[-LOG_TAIL_CHARS:].strip()
    reason = f"the container did not answer {path} with 2xx within {int(timeout_s)}s ({error})"
    return AppRun(
        status="failed",
        health_url=url,
        http_status=status,
        response_snippet=snippet,
        reason=reason + (f"; logs: {tail}" if tail else ""),
    )


def _traced_start_command(
    engine: str, name: str, root: Path, trace: Path, hook: Path, loader: Path
) -> list[str]:
    command = [
        engine,
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        *LIMITS,
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp",
        "-e",
        "HOME=/tmp",
    ]
    get_uid = getattr(os, "getuid", None)
    get_gid = getattr(os, "getgid", None)
    if callable(get_uid) and callable(get_gid):
        command.extend(["--user", f"{get_uid()}:{get_gid()}"])
    command.extend(
        [
            "-e",
            "NODE_OPTIONS=--require=/guardian-trace.cjs --experimental-loader=file:///guardian-trace-loader.mjs",
            "-e",
            "GUARDIAN_TRACE_FILE=/trace.jsonl",
            "-e",
            "GUARDIAN_TRACE_MAX_BYTES=5242880",
            "-v",
            f"{root}:/work:ro",
            "-v",
            f"{trace}:/trace.jsonl:rw",
            "-v",
            f"{hook}:/guardian-trace.cjs:ro",
            "-v",
            f"{loader}:/guardian-trace-loader.mjs:ro",
            "-w",
            "/work",
            CONTAINER_IMAGE,
            "npm",
            "start",
        ]
    )
    return command


def _container_http_get(engine: str, name: str, root: Path, capture: Runner) -> HttpGet:
    script = (
        "fetch(process.argv[1]).then(async r=>console.log(JSON.stringify({status:r.status,"
        "body:(await r.text()).slice(0,200)}))).catch(e=>{console.error(e);process.exit(1)})"
    )

    def get(url: str, timeout: float) -> tuple[int, str]:
        done = capture([engine, "exec", name, "node", "-e", script, url], root, int(timeout) + 1)
        if done.returncode:
            raise OSError(done.output or "application health check did not answer")
        for line in reversed(done.output.splitlines()):
            try:
                result = json.loads(line)
            except ValueError:
                continue
            if isinstance(result, dict) and "status" in result:
                return int(result["status"]), str(result.get("body", ""))
        raise OSError("application health check returned no HTTP result")

    return get


def run_traced_application(
    root: Path,
    trace: Path,
    hook: Path,
    loader: Path,
    engine: str,
    capture: Runner,
    timeout_s: float = HEALTH_TIMEOUT_S,
) -> AppRun:
    """Start npm start offline with tracing enabled, then reuse the health poll logic."""
    name = f"guardian-reach-app-{uuid.uuid4().hex[:12]}"
    port = int(os.environ.get("GUARDIAN_APP_PORT", str(DEFAULT_PORT)))
    path = os.environ.get("GUARDIAN_APP_HEALTH_PATH", DEFAULT_HEALTH_PATH)
    try:
        started = capture(
            _traced_start_command(engine, name, root, trace, hook, loader), root, KILL_TIMEOUT_S
        )
        if started.returncode:
            return AppRun(
                status="failed",
                reason=f"application container did not start: {started.output[-300:]}",
            )
        url = f"http://127.0.0.1:{port}{path}"
        status, snippet, error = _poll_health(
            url, _container_http_get(engine, name, root, capture), timeout_s
        )
        if error:
            return AppRun(
                status="failed",
                health_url=url,
                http_status=status,
                response_snippet=snippet,
                reason=f"application did not answer {path}: {error}",
            )
        return AppRun(status="passed", health_url=url, http_status=status, response_snippet=snippet)
    finally:
        capture([engine, "rm", "-f", name], root, KILL_TIMEOUT_S)


def _severity(raw: object) -> str:
    level = str(raw or "unknown").lower()
    level = "low" if level == "negligible" else level
    return level if level in SEVERITY_ORDER else "unknown"


def _summarise_matches(matches: list[dict[str, Any]], source_ids: set[str]) -> dict[str, Any]:
    seen: dict[tuple[str, str], tuple[str, set[str]]] = {}
    for match in matches:
        vuln = match["vulnerability"]
        key = (str(vuln["id"]), str(match["artifact"].get("purl") or match["artifact"]["name"]))
        ids = {key[0], *(str(r["id"]) for r in match.get("relatedVulnerabilities", []))}
        seen[key] = (_severity(vuln.get("severity")), ids)
    counts = {level: 0 for level in SEVERITY_ORDER}
    foreign: dict[str, str] = {}
    for (vuln_id, _), (level, ids) in seen.items():
        counts[level] += 1
        if not ids & source_ids:
            foreign[vuln_id] = min(level, foreign.get(vuln_id, level), key=SEVERITY_ORDER.index)
    ordered = sorted(foreign, key=lambda i: (SEVERITY_ORDER.index(foreign[i]), i))
    return {
        "image_vulns": {level: n for level, n in counts.items() if n},
        "image_only": ordered[:IMAGE_ONLY_LIMIT],
        "image_only_serious": sum(1 for level in foreign.values() if level in SERIOUS),
    }


def _scan_image(
    capture: Runner, engine: str, tag: str, folder: Path, source_ids: set[str]
) -> dict[str, Any]:
    folder.mkdir(parents=True, exist_ok=True)
    tar = folder / TAR_FILE
    try:
        saved = capture([engine, "save", "-o", str(tar), tag], folder, SAVE_TIMEOUT_S)
        if saved.returncode != 0:
            return {"image_error": f"cannot export the image: {saved.output[-300:]}"}
        scan = capture([
            engine, "run", "--rm", "--network", "host", "--entrypoint", "/grype",
            "-v", f"{folder.resolve()}:/in", "-v", f"{GRYPE_DB_VOLUME}:{GRYPE_DB_DIR}",
            "-e", f"GRYPE_DB_CACHE_DIR={GRYPE_DB_DIR}", "-e", "GRYPE_DB_AUTO_UPDATE=false",
            GRYPE_IMAGE, f"docker-archive:/in/{TAR_FILE}", "-o", "json", "--file",
            f"/in/{VULNS_FILE}",
        ], folder, SCAN_TIMEOUT_S)  # fmt: skip
        if scan.returncode != 0:
            return {"image_error": f"image scan failed: {scan.output[-300:]}"}
        raw = json.loads((folder / VULNS_FILE).read_text(encoding="utf-8"))
        return _summarise_matches(raw.get("matches", []), source_ids)
    finally:
        tar.unlink(missing_ok=True)


def run_application(
    root: Path,
    folder: Path,
    proposal_id: str,
    source_ids: set[str],
    capture: Runner,
    engine: str,
    get: HttpGet = http_get,
    health_timeout_s: float = HEALTH_TIMEOUT_S,
) -> AppRun:
    tag = f"guardian-fix-{proposal_id}:latest"
    built = capture(_build_command(engine, tag), root, BUILD_TIMEOUT_S)
    if built.returncode != 0:
        return AppRun(status="failed", reason=f"image build failed: {built.output[-300:]}")
    name, port = f"guardian-app-{uuid.uuid4().hex[:12]}", _port(root)
    try:
        started = capture(_start_command(engine, name, tag, port), root, KILL_TIMEOUT_S)
        if started.returncode != 0:
            reason = f"container did not start: {started.output[-300:]}"
            return AppRun(status="failed", reason=reason)
        result = _health(capture, engine, root, name, port, get, health_timeout_s)
    finally:
        capture([engine, "rm", "-f", name], root, KILL_TIMEOUT_S)
    scan = _scan_image(capture, engine, tag, folder / "image", source_ids)
    return result.model_copy(update=scan)
