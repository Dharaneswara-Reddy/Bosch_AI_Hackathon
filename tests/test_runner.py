import json
from pathlib import Path

from guardian import runner
from guardian.cli import main
from guardian.models import Component, Finding, GraphArtifact


def _inventory(context):
    context.sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
    context.result.graph = GraphArtifact(nodes=[
        Component(component_id="lib", purl="pkg:npm/lib@1", name="lib", ecosystem="npm", dev=True),
    ])


def test_scan_preserves_successful_stages_when_scanner_fails(monkeypatch, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "scan"
    review_calls = []

    def scanner(context):
        raise RuntimeError("scanner unavailable")

    def detect(context):
        context.result.findings = [
            Finding(
                finding_id="advisory", kind="vulnerability", component_id="lib",
                purl="pkg:npm/lib@1", advisory_id="CVE-2000-1234", source_severity="high",
            ),
        ]

    def review(context):
        review_calls.append(context.result.scan.scan_id)

    def report(directory):
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


def test_ai_failure_leaves_defensive_scan_complete(monkeypatch, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "scan"

    def unavailable(context):
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


def test_scan_rejects_using_target_as_output(tmp_path):
    assert main(["scan", str(tmp_path), "--out", str(tmp_path)]) == 1

def test_p2_parsers_merge_real_fixture_findings(monkeypatch, tmp_path):
    import shutil

    import pytest

    grype = pytest.importorskip("guardian.scanners.grype")
    osv = pytest.importorskip("guardian.scanners.osv")
    fixtures = Path(__file__).parent / "fixtures"
    if not all((fixtures / f"{name}.sample.json").is_file() for name in ("grype", "osv")):
        pytest.skip("P2 scanner fixtures are not present on this checkout.")

    def fixture_run(name):
        def run(sbom_path, out_dir, image):
            assert sbom_path.is_file()
            output = out_dir / "raw" / f"{name}.json"
            output.parent.mkdir(exist_ok=True)
            shutil.copyfile(fixtures / f"{name}.sample.json", output)
            return output

        return run

    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(grype, "run_grype", fixture_run("grype"))
    monkeypatch.setattr(osv, "run_osv", fixture_run("osv"))
    monkeypatch.setattr(runner, "_inventory", _inventory)
    monkeypatch.setattr(runner, "_detectors", lambda context: None)
    result = runner.scan(target, output, use_llm=False)
    assert result.scan.status == "complete", result.scan.errors
    assert result.findings
    evidence_ids = {evidence.evidence_id for evidence in result.evidence}
    assert evidence_ids
    assert all(set(finding.evidence_ids) <= evidence_ids for finding in result.findings)
    assert {"grype", "osv"} == set(result.scan.scanner_versions)
    assert (output / "report.html").is_file()

def test_cache_reuses_clean_checkout_and_invalidates_changed_lockfile(monkeypatch, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    lockfile = target / "package-lock.json"
    lockfile.write_text("first", encoding="utf-8")
    out = tmp_path / "scan"
    scans = []

    def git(path, *args):
        return "1" * 40 if args[0] == "rev-parse" else ""

    def inventory(context):
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
