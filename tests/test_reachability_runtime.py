import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from guardian.models import (
    Component,
    Finding,
    FindingKind,
    FindingsArtifact,
    GraphArtifact,
    MatchBasis,
    Reachability,
    ReachabilityEvidence,
    Relevance,
    RelevanceSignal,
)
from guardian.policy import DEFAULT_POLICY_PATH, load_policy
from guardian.reachability import parse_runtime_trace, static_dependency_chains
from guardian.remediate.app_run import run_traced_application
from guardian.remediate.sandbox import CommandResult
from guardian.remediate.validate import _run_container
from guardian.risk import assess
from guardian.runtime_reachability import _cap_static_confidence, _merge_evidence


def _package(path: Path, name: str, version: str, imports: str = "") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "package.json").write_text(
        json.dumps({"name": name, "version": version, "main": "index.js"}), encoding="utf-8"
    )
    (path / "index.js").write_text(imports, encoding="utf-8")
    return path


def test_static_chain_tracks_scoped_and_nested_packages_with_line_evidence(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.js").write_text(
        "const a = require('a');\nimport '@s/c';\nrequire('./relative');\nrequire('fs');\n",
        encoding="utf-8",
    )
    modules = tmp_path / "node_modules"
    _package(modules / "a", "a", "1.0.0", "const b = require('b');\n")
    _package(modules / "b", "b", "2.0.0", "require('d');\n")
    _package(modules / "b" / "node_modules" / "d", "d", "4.0.0")
    _package(modules / "@s" / "c", "@s/c", "3.0.0")
    evidence = static_dependency_chains(
        tmp_path,
        {
            "b": {"2.0.0"},
            "d": {"4.0.0"},
            "@s/c": {"3.0.0"},
        },
    )
    by_package = {item.package: item for item in evidence}
    assert by_package["d"].chain == ["a", "b", "d"]
    assert by_package["d"].file == "node_modules/b/index.js:1"
    assert by_package["@s/c"].chain == ["@s/c"]
    assert by_package["@s/c"].file == "src/app.js:2"
    assert "fs" not in by_package and "relative" not in by_package


def test_static_chain_respects_depth_and_total_file_caps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.js").write_text("require('a');\n", encoding="utf-8")
    modules = tmp_path / "node_modules"
    _package(modules / "a", "a", "1", "require('b');\n")
    _package(modules / "b", "b", "2")
    import guardian.reachability as reachability

    monkeypatch.setattr(reachability, "MAX_CHAIN_DEPTH", 1)
    assert static_dependency_chains(tmp_path, {"b": {"2"}}) == []
    monkeypatch.setattr(reachability, "MAX_CHAIN_DEPTH", 8)
    monkeypatch.setattr(reachability, "MAX_CHAIN_FILES", 1)
    assert static_dependency_chains(tmp_path, {"b": {"2"}}) == []


def test_trace_parser_maps_scoped_and_nested_packages_from_container_paths(tmp_path: Path) -> None:
    _package(tmp_path / "node_modules" / "parent", "parent", "1.0")
    _package(tmp_path / "node_modules" / "@scope" / "pkg", "@scope/pkg", "2.0")
    _package(tmp_path / "node_modules" / "parent" / "node_modules" / "nested", "nested", "3.0")
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        "\n".join(
            json.dumps(row)
            for row in [
                {
                    "module": "@scope/pkg",
                    "resolved_path": "/work/node_modules/@scope/pkg/index.js",
                    "parent_path": "/work/node_modules/parent/index.js",
                },
                {
                    "module": "nested",
                    "resolved_path": "/work/node_modules/parent/node_modules/nested/index.js",
                    "parent_path": "/work/node_modules/@scope/pkg/index.js",
                },
            ]
        ),
        encoding="utf-8",
    )
    evidence = {item.package: item for item in parse_runtime_trace(trace, tmp_path, ["npm test"])}
    assert evidence["@scope/pkg"].version == "2.0"
    assert evidence["@scope/pkg"].chain == ["parent", "@scope/pkg"]
    assert evidence["nested"].chain == ["@scope/pkg", "nested"]
    assert evidence["nested"].observed_during == ["npm test"]


def _finding() -> Finding:
    relevance = Relevance(
        verdict="likely_relevant",
        reachability=Reachability.UNKNOWN,
        signals=[RelevanceSignal(name="version_in_affected_range", value="confirmed")],
    )
    return Finding(
        finding_id="f1",
        kind=FindingKind.VULNERABILITY,
        component_id="pkg",
        purl="pkg:npm/jws@1.0.0",
        match_basis=MatchBasis.PURL,
        relevance=relevance,
        source_severity="high",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )


def test_runtime_and_static_signals_and_non_detection_do_not_reduce_exposure() -> None:
    component = Component(
        component_id="pkg",
        purl="pkg:npm/jws@1.0.0",
        name="jws",
        version="1.0.0",
        ecosystem="npm",
        dev=False,
    )
    policy = load_policy(DEFAULT_POLICY_PATH)
    original = assess(_finding(), dev=False, policy=policy)
    runtime = ReachabilityEvidence(
        package="jws",
        version="1.0.0",
        source="runtime",
        chain=["express-jwt", "jsonwebtoken", "jws"],
        observed_during=["npm test"],
    )
    reached = _merge_evidence(_finding(), component, {}, {"jws": [runtime]}, "ev1")
    classified = assess(reached, dev=False, policy=policy)
    assert reached.relevance.reachability == Reachability.CONFIRMED
    assert classified.exposure.value == "open"
    assert any(
        s.name == "reachability_source" and s.value == "runtime" for s in reached.relevance.signals
    )
    missed = _merge_evidence(
        _finding(), component, {"tests_status": "passed", "app_status": "not_run"}, {}, "ev2"
    )
    missed_risk = assess(missed, dev=False, policy=policy)
    assert missed.relevance.reachability == Reachability.NOT_DETECTED
    assert missed_risk.exposure == original.exposure
    static = ReachabilityEvidence(
        package="jws",
        version="1.0.0",
        source="static_chain",
        chain=["app", "express-jwt", "jsonwebtoken", "jws"],
        file="node_modules/jsonwebtoken/index.js:4",
    )
    static_finding = _merge_evidence(_finding(), component, {}, {"jws": [static]}, "ev4")
    assert any(
        s.name == "reachability_source" and s.value == "static_chain"
        for s in static_finding.relevance.signals
    )
    static_confidence = _cap_static_confidence(
        static_finding.model_copy(update={"confidence_score": 0.9}), 0.7
    )
    runtime_confidence = _cap_static_confidence(
        reached.model_copy(update={"confidence_score": 0.9}), 0.7
    )
    assert static_confidence.confidence_score == 0.8
    assert runtime_confidence.confidence_score == 0.9
    unknown = _merge_evidence(
        _finding(), component, {"tests_status": "not_run", "app_status": "not_run"}, {}, "ev3"
    )
    assert unknown.relevance.reachability == Reachability.UNKNOWN


class FakeRunner:
    def __init__(self, result: CommandResult) -> None:
        self.calls: list[list[str]] = []
        self.result = result

    def __call__(self, command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
        self.calls.append(list(command))
        return self.result


def test_container_runner_mounts_trace_and_always_removes_timeout_container(tmp_path: Path) -> None:
    capture = FakeRunner(CommandResult(124, "timeout"))
    _run_container(
        capture,
        "docker",
        tmp_path,
        ["npm", "test"],
        offline=True,
        timeout=10,
        mounts=("/hook.cjs:/hook.cjs:ro", "/trace:/trace:rw"),
        env=("NODE_OPTIONS=--require=/hook.cjs",),
    )
    run, cleanup = capture.calls
    assert run[run.index("--network") + 1] == "none"
    assert "--read-only" in run and "--cap-drop" in run and "ALL" in run
    assert "/hook.cjs:/hook.cjs:ro" in run and "NODE_OPTIONS=--require=/hook.cjs" in run
    assert cleanup == ["docker", "rm", "-f", run[run.index("--name") + 1]]


def test_install_container_has_network_ignore_scripts_and_configured_dns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guardian.runtime_reachability import _install

    monkeypatch.setenv("GUARDIAN_SANDBOX_DNS", "1.1.1.1")
    capture = FakeRunner(CommandResult(0, "installed"))
    assert _install(tmp_path, "docker", capture) is None
    run = capture.calls[0]
    assert "--ignore-scripts" in run and "--dns" in run
    assert run[run.index("--dns") + 1] == "1.1.1.1"
    assert "--network" not in run or run[run.index("--network") + 1] != "none"
    assert capture.calls[1][:3] == ["docker", "rm", "-f"]


def test_traced_app_starts_offline_and_polls_health_inside_container(tmp_path: Path) -> None:
    class AppCapture:
        calls: list[list[str]] = []

        def __call__(self, command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
            args = list(command)
            self.calls.append(args)
            if args[1] == "exec":
                return CommandResult(0, '{"status":200,"body":"ok"}')
            return CommandResult(0, "container")

    trace = tmp_path / "trace.jsonl"
    trace.touch()
    capture = AppCapture()
    result = run_traced_application(
        tmp_path, trace, Path("hook.cjs"), Path("loader.mjs"), "docker", capture
    )
    start = capture.calls[0]
    assert result.status == "passed"
    assert start[start.index("--network") + 1] == "none"
    assert "--read-only" in start and "--cap-drop" in start
    assert "hook.cjs:/guardian-trace.cjs:ro" in start
    assert (
        "NODE_OPTIONS=--require=/guardian-trace.cjs --experimental-loader=file:///guardian-trace-loader.mjs"
        in start
    )
    assert capture.calls[-1][:3] == ["docker", "rm", "-f"]


def test_report_refreshes_after_reachability_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guardian.report import render as render_module
    from guardian.runtime_reachability import update_findings

    work = tmp_path / "scan"
    out = work / "out"
    (out / "raw").mkdir(parents=True)
    component = Component(
        component_id="pkg",
        purl="pkg:npm/jws@1.0.0",
        name="jws",
        version="1.0.0",
        ecosystem="npm",
        dev=False,
    )
    (out / "graph.json").write_text(
        GraphArtifact(nodes=[component]).model_dump_json(), encoding="utf-8"
    )
    (out / "findings.json").write_text(
        FindingsArtifact(findings=[_finding()]).model_dump_json(), encoding="utf-8"
    )
    (out / "reachability.json").write_text(
        json.dumps(
            {
                "status": "complete",
                "tests_status": "passed",
                "app_status": "not_run",
                "evidence": [],
            }
        ),
        encoding="utf-8",
    )
    rendered: list[Path] = []
    monkeypatch.setattr(render_module, "render", lambda path: rendered.append(path))
    update_findings(work)
    assert rendered == [out]
    saved = FindingsArtifact.model_validate_json((out / "findings.json").read_text("utf-8"))
    assert saved.findings[0].relevance.reachability == Reachability.NOT_DETECTED


def test_reachability_api_starts_polls_and_reports_missing_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from Bosch_Guardian_Clean.backend.app import main, pipeline
    from Bosch_Guardian_Clean.backend.app.schemas import ScanRecord

    scan_id = "reach-test"
    work = tmp_path / scan_id
    out = work / "out"
    out.mkdir(parents=True)
    (out / "run.json").write_text("{}", encoding="utf-8")
    record = ScanRecord(
        scan_id=scan_id,
        status="complete",
        repository_url="local",
        created_at=datetime.now(UTC),
        work_dir=work,
    )
    pipeline.SCANS[scan_id] = record

    def complete(active: ScanRecord) -> None:
        (active.work_dir / "out" / "reachability.json").write_text(
            json.dumps({"status": "complete", "evidence": []}), encoding="utf-8"
        )

    monkeypatch.setattr(main, "_run_reachability", complete)
    client = TestClient(main.app)
    assert client.get("/scan/unknown/reachability").status_code == 404
    response = client.post(f"/scan/{scan_id}/reachability")
    assert response.status_code == 202
    assert client.get(f"/scan/{scan_id}/reachability").json()["status"] == "complete"
    main._reachability_jobs.discard(scan_id)
    record.status = "running"
    assert client.post(f"/scan/{scan_id}/reachability").status_code == 409
    pipeline.SCANS.pop(scan_id, None)
