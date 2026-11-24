import json
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from guardian.remediate.app_run import AppRun, HttpGet, not_run_reason, run_application
from guardian.remediate.sandbox import CommandResult, TestRun

PASSED = TestRun(status="passed")


def _match(
    vuln_id: str, severity: str, package: str, related: tuple[str, ...] = ()
) -> dict[str, object]:
    return {
        "vulnerability": {"id": vuln_id, "severity": severity},
        "relatedVulnerabilities": [{"id": r} for r in related],
        "artifact": {"name": package, "version": "1", "purl": f"pkg:x/{package}@1"},
    }


MATCHES = [
    _match("CVE-LODASH", "High", "lodash"),
    _match("CVE-LODASH", "High", "lodash"),
    _match("CVE-LIBC-1", "Critical", "libc6"),
    _match("CVE-LIBC-2", "High", "libc6"),
    _match("CVE-ZLIB", "Negligible", "zlib"),
    _match("GHSA-JWT", "Medium", "jsonwebtoken", related=("CVE-JWT",)),
]


class FakeEngine:
    def __init__(self, *, build_ok: bool = True, scan_ok: bool = True) -> None:
        self.calls: list[list[str]] = []
        self.build_ok = build_ok
        self.scan_ok = scan_ok
        self.logs = "listening on 3000"

    def verbs(self) -> list[str]:
        return [call[1] for call in self.calls]

    def call(self, verb: str) -> list[str]:
        return next(c for c in self.calls if c[1] == verb)

    def __call__(self, command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
        self.calls.append(list(command))
        verb = command[1]
        if verb == "build":
            return CommandResult(0, "built") if self.build_ok else CommandResult(1, "npm ERR! boom")
        if verb == "run" and "-d" in command:
            return CommandResult(0, "cid123")
        if verb == "port":
            return CommandResult(0, "127.0.0.1:49153")
        if verb == "logs":
            return CommandResult(0, self.logs)
        if verb == "run":
            return self._grype(command)
        return CommandResult(0, "")

    def _grype(self, command: Sequence[str]) -> CommandResult:
        if not self.scan_ok:
            return CommandResult(1, "db missing")
        mount = next(c for c in command if c.endswith(":/in"))
        folder = Path(mount.rsplit(":/in", 1)[0])
        (folder / "image-vulns.json").write_text(json.dumps({"matches": MATCHES}), encoding="utf-8")
        return CommandResult(0, "")


def _project(root: Path, dockerfile: str = "FROM node:20-slim\nEXPOSE 8080\n") -> Path:
    (root / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    return root


def _ok(url: str, timeout: float) -> tuple[int, str]:
    return 200, "ok\n"


def _run(
    root: Path,
    engine: FakeEngine,
    get: HttpGet = _ok,
    source_ids: frozenset[str] = frozenset({"CVE-LODASH"}),
) -> AppRun:
    return run_application(root, root / "fix", "p1", set(source_ids), engine, "docker", get)


def test_not_run_when_tests_did_not_pass(tmp_path: Path) -> None:
    root = _project(tmp_path)
    failed = TestRun(status="failed")
    assert "tests did not pass" in (not_run_reason(root, failed, "docker") or "")
    assert "tests did not pass" in (not_run_reason(root, None, "docker") or "")


def test_not_run_without_dockerfile_or_engine(tmp_path: Path) -> None:
    assert not_run_reason(tmp_path, PASSED, "docker") == (
        "no Dockerfile in the project; there is no image to build and run"
    )
    root = _project(tmp_path)
    assert "no container engine" in (not_run_reason(root, PASSED, None) or "")
    assert not_run_reason(root, PASSED, "docker") is None


def test_started_app_is_health_checked_and_image_scanned(tmp_path: Path) -> None:
    engine = FakeEngine()
    result = _run(_project(tmp_path), engine)
    assert result.status == "passed"
    assert result.health_url == "http://127.0.0.1:49153/health"
    assert result.http_status == 200 and result.response_snippet == "ok"
    assert engine.call("build")[2:4] == ["-t", "guardian-fix-p1:latest"]
    run = engine.call("run")
    for flag in ("--read-only", "--cap-drop", "no-new-privileges", "--pids-limit", "--memory"):
        assert flag in run
    assert "127.0.0.1::8080" in run
    assert engine.call("port")[-1] == "8080/tcp"


def test_container_is_always_removed(tmp_path: Path) -> None:
    engine = FakeEngine()
    _run(_project(tmp_path), engine)
    assert engine.call("rm")[-1] == engine.call("run")[engine.call("run").index("--name") + 1]


def test_image_vulnerabilities_are_counted_once_and_split_from_the_source(tmp_path: Path) -> None:
    result = _run(_project(tmp_path), FakeEngine())
    assert result.image_vulns == {"critical": 1, "high": 2, "medium": 1, "low": 1}
    assert result.image_only == ["CVE-LIBC-1", "CVE-LIBC-2", "GHSA-JWT", "CVE-ZLIB"]
    assert result.image_only_serious == 2


def test_aliases_of_source_findings_are_not_image_only(tmp_path: Path) -> None:
    result = _run(_project(tmp_path), FakeEngine(), source_ids=frozenset({"CVE-JWT"}))
    assert "GHSA-JWT" not in result.image_only


def test_image_only_lists_ten_at_most(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    many = [_match(f"CVE-{i:02d}", "Low", "libc6") for i in range(15)]
    monkeypatch.setattr(sys.modules[__name__], "MATCHES", many)
    result = _run(_project(tmp_path), FakeEngine())
    assert len(result.image_only) == 10


def test_unreachable_app_fails_with_its_logs(tmp_path: Path) -> None:
    engine = FakeEngine()

    def refuse(url: str, timeout: float) -> tuple[int, str]:
        raise OSError("connection refused")

    result = run_application(
        _project(tmp_path),
        tmp_path / "fix",
        "p1",
        set(),
        engine,
        "docker",
        refuse,
        health_timeout_s=0,
    )
    assert result.status == "failed"
    assert "did not answer /health" in result.reason and "connection refused" in result.reason
    assert "listening on 3000" in result.reason
    assert "rm" in engine.verbs()


def test_non_2xx_health_fails(tmp_path: Path) -> None:
    result = run_application(
        _project(tmp_path),
        tmp_path / "fix",
        "p1",
        set(),
        FakeEngine(),
        "docker",
        lambda url, timeout: (500, "oops"),
        health_timeout_s=0,
    )
    assert result.status == "failed" and result.http_status == 500


def test_build_failure_does_not_start_anything(tmp_path: Path) -> None:
    engine = FakeEngine(build_ok=False)
    result = _run(_project(tmp_path), engine)
    assert result.status == "failed" and "image build failed" in result.reason
    assert "npm ERR! boom" in result.reason
    assert "run" not in engine.verbs()


def test_failed_image_scan_keeps_the_health_result(tmp_path: Path) -> None:
    result = _run(_project(tmp_path), FakeEngine(scan_ok=False))
    assert result.status == "passed" and result.http_status == 200
    assert result.image_vulns is None and "db missing" in result.image_error


def test_port_defaults_and_dns_uses_host_network_for_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDIAN_SANDBOX_DNS", "1.1.1.1")
    engine = FakeEngine()
    _run(_project(tmp_path, "FROM node:20-slim\n"), engine)
    assert "--network" in engine.call("build") and "host" in engine.call("build")
    assert "127.0.0.1::3000" in engine.call("run")
