import json
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

from guardian import runner
from guardian.cli import main
from guardian.models import Component, Finding, FindingKind, GraphArtifact
from guardian.runner import ScanContext

VULN = FindingKind.VULNERABILITY


def _inventory(context: ScanContext) -> None:
    context.sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
    context.result.graph = GraphArtifact(
        nodes=[
            Component(
                component_id="lib", purl="pkg:npm/lib@1", name="lib", ecosystem="npm", dev=True
            ),
        ]
    )


def _fake_graph_module(
    shortest: Callable[[object, str], list[str] | None], count: Callable[[object, str], int]
) -> ModuleType:
    graph = ModuleType("guardian.graph")
    graph.__dict__.update(shortest_path=shortest, path_count=count)
    return graph


def test_scan_preserves_successful_stages_when_scanner_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "scan"
    review_calls: list[str] = []

    def scanner(context: ScanContext) -> None:
        raise RuntimeError("scanner unavailable")

    def detect(context: ScanContext) -> None:
        context.result.findings = [
            Finding(
                finding_id="advisory",
                kind=VULN,
                component_id="lib",
                purl="pkg:npm/lib@1",
                advisory_id="CVE-2000-1234",
                source_severity="high",
            ),
        ]

    def review(context: ScanContext) -> None:
        review_calls.append(context.result.scan.scan_id)

    def report(directory: Path) -> None:
        (directory / "report.html").write_text("report", encoding="utf-8")

    monkeypatch.setattr(runner, "_inventory", _inventory)
    monkeypatch.setattr(runner, "_scanners", scanner)
    monkeypatch.setattr(runner, "_detectors", detect)
    monkeypatch.setattr(runner, "_review", review)
    monkeypatch.setattr(runner, "_render", report)
    assert main(["scan", str(target), "--out", str(out), "--no-llm"]) == 2
    scan = json.loads((out / "run.json").read_text(encoding="utf-8"))
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert scan["status"] == "partial"
    assert scan["errors"]["scanners"] == "scanner unavailable"
    assert scan["llm_status"] == "unavailable"
    assert findings["findings"][0]["risk_level"] == "medium"
    assert (out / "report.html").is_file()
    assert not review_calls


def test_ai_failure_leaves_defensive_scan_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "scan"

    def unavailable(context: ScanContext) -> None:
        raise TimeoutError("review timed out")

    monkeypatch.setattr(runner, "_inventory", _inventory)
    monkeypatch.setattr(runner, "_scanners", lambda context: None)
    monkeypatch.setattr(runner, "_detectors", lambda context: None)
    monkeypatch.setattr(runner, "_review", unavailable)
    monkeypatch.setattr(runner, "_render", lambda directory: None)
    result = runner.scan(target, out)
    assert result.scan.status == "complete"
    assert result.scan.llm_status == "failed"
    assert result.scan.errors["ai"] == "review timed out"


def test_scan_rejects_using_target_as_output(tmp_path: Path) -> None:
    assert main(["scan", str(tmp_path), "--out", str(tmp_path)]) == 1


def _fixture_run(name: str) -> Callable[[Path, Path, str], Path]:
    fixtures = Path(__file__).parent / "fixtures"

    def run(sbom_path: Path, out_dir: Path, image: str) -> Path:
        assert sbom_path.is_file()
        output = out_dir / "raw" / f"{name}.json"
        output.parent.mkdir(exist_ok=True)
        shutil.copyfile(fixtures / f"{name}.sample.json", output)
        return output

    return run


def test_p2_parsers_merge_real_fixture_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from guardian.scanners import grype, osv

    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(grype, "run_grype", _fixture_run("grype"))
    monkeypatch.setattr(osv, "run_osv", _fixture_run("osv"))
    purl = "pkg:gem/actionmailbox@8.0.4"
    path = ["app", "direct", "bom-actionmailbox"]
    graph = _fake_graph_module(
        lambda graph, component: path if component == path[-1] else None,
        lambda graph, component: 2,
    )
    monkeypatch.setitem(sys.modules, "guardian.graph", graph)

    def inventory(context: ScanContext) -> None:
        _inventory(context)
        context.graph = object()
        context.result.graph.nodes.append(
            Component(
                component_id=path[-1],
                purl=purl,
                name="actionmailbox",
                ecosystem="gem",
            )
        )

    monkeypatch.setattr(runner, "_inventory", inventory)
    monkeypatch.setattr(runner, "_detectors", lambda context: None)
    result = runner.scan(target, output, use_llm=False)
    matched = [finding for finding in result.findings if finding.purl == purl]
    assert matched and all(finding.component_id == path[-1] for finding in matched)
    assert all(finding.dependency_path == path and finding.path_count == 2 for finding in matched)
    assert result.scan.status == "complete", result.scan.errors
    assert result.findings
    evidence_ids = {evidence.evidence_id for evidence in result.evidence}
    assert evidence_ids
    assert all(set(finding.evidence_ids) <= evidence_ids for finding in result.findings)
    assert {"grype", "osv"} == set(result.scan.scanner_versions)
    assert result.scan.db_built_at["grype"] == "2026-11-23T06:28:32Z"
    grype_evidence = [e for e in result.evidence if e.tool == "grype"]
    assert grype_evidence and {e.db_built_at for e in grype_evidence} == {"2026-11-23T06:28:32Z"}
    assert result.scan.db_built_at["osv"].startswith("live api.osv.dev")
    assert (output / "report.html").is_file()


def test_cache_reuses_clean_checkout_and_invalidates_changed_lockfile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    lockfile = target / "package-lock.json"
    lockfile.write_text("first", encoding="utf-8")
    out = tmp_path / "scan"
    scans: list[str] = []

    def git(path: Path, *args: str) -> str:
        return "1" * 40 if args[0] == "rev-parse" else ""

    def inventory(context: ScanContext) -> None:
        scans.append(context.result.scan.scan_id)
        _inventory(context)

    for name in ("SYFT", "GRYPE", "OSV"):
        monkeypatch.setenv(f"GUARDIAN_{name}_IMAGE", f"example/{name.lower()}@sha256:" + "1" * 64)
    monkeypatch.setenv("GUARDIAN_GRYPE_DB_BUILT_AT", "2026-11-23")
    monkeypatch.setenv("GUARDIAN_OSV_DB_BUILT_AT", "2026-11-23")
    monkeypatch.setattr(runner, "_git", git)
    monkeypatch.setattr(runner, "_inventory", inventory)
    monkeypatch.setattr(runner, "_scanners", lambda context: None)
    monkeypatch.setattr(runner, "_detectors", lambda context: None)
    first = runner.scan(target, out, use_llm=False)
    second = runner.scan(target, out, use_llm=False)
    assert first.scan.scan_id == second.scan.scan_id
    assert second.scan.cached_age_minutes is not None
    lockfile.write_text("second", encoding="utf-8")
    third = runner.scan(target, out, use_llm=False)
    assert third.scan.scan_id != first.scan.scan_id
    assert len(scans) == 2


def test_paths_preserve_exact_bom_ids_and_skip_ambiguous_purls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context, _ = runner._prepare(tmp_path, tmp_path / "output", None, False, None)
    context.graph = object()
    context.result.graph = GraphArtifact(
        nodes=[
            Component(component_id="copy-a", purl="pkg:npm/lib@1", name="lib"),
            Component(component_id="copy-b", purl="pkg:npm/lib@1", name="lib"),
            Component(component_id="unreachable", purl="pkg:npm/other@1", name="other"),
        ]
    )
    graph = _fake_graph_module(
        lambda _, component: ["app", component] if component != "unreachable" else None,
        lambda _, component: 1,
    )
    monkeypatch.setitem(sys.modules, "guardian.graph", graph)
    findings = [
        Finding(finding_id="a", kind=VULN, component_id="copy-a", purl="pkg:npm/lib@1"),
        Finding(finding_id="b", kind=VULN, component_id="unknown", purl="pkg:npm/lib@1"),
        Finding(finding_id="c", kind=VULN, component_id="unreachable", purl="pkg:npm/other@1"),
    ]
    exact, ambiguous, unreachable = runner._paths(context, findings)
    assert exact.dependency_path == ["app", "copy-a"]
    assert exact.path_count == 1
    assert ambiguous.component_id == "unknown" and ambiguous.dependency_path == []
    assert unreachable.dependency_path == [] and unreachable.path_count is None
