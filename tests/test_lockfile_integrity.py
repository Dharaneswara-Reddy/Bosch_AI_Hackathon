from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from guardian import runner
from guardian.detectors import DETECTORS
from guardian.detectors.lockfile_integrity import detect
from guardian.evidence import EvidenceStore
from guardian.models import Component, GraphArtifact

REGISTRY = "https://registry.npmjs.org"


def _lock(**entries: dict[str, Any]) -> dict[str, Any]:
    return {"packages": {f"node_modules/{name}": entry for name, entry in entries.items()}}


def _entry(version: str = "4.17.4", integrity: str | None = "sha512-AAA", host: str = REGISTRY):
    entry: dict[str, Any] = {"version": version, "resolved": f"{host}/lodash/-/lodash.tgz"}
    if integrity is not None:
        entry["integrity"] = integrity
    return entry


def _types(result: Any) -> dict[str, str]:
    return {
        result.finding_details[f.finding_id]["package_name"]: f.anomaly_type
        for f in result.findings
    }


def test_same_version_with_different_integrity_is_flagged() -> None:
    baseline = _lock(lodash=_entry(integrity="sha512-AAA"), other=_entry(integrity="sha512-ZZZ"))
    current = _lock(lodash=_entry(integrity="sha512-BBB"), other=_entry(integrity="sha512-ZZZ"))

    result = detect(current, baseline_lockfile=baseline, ecosystems=["npm"])

    assert _types(result) == {"lodash": "integrity_change"}
    assert result.coverage[0].status == "finding"


def test_new_version_with_new_integrity_is_not_flagged() -> None:
    baseline = _lock(lodash=_entry("4.17.4", "sha512-AAA"))
    current = _lock(lodash=_entry("4.17.21", "sha512-BBB"))

    result = detect(current, baseline_lockfile=baseline, ecosystems=["npm"])

    assert result.findings == []
    assert result.coverage[0].status == "pass"


def test_same_version_from_different_host_is_flagged() -> None:
    baseline = _lock(lodash=_entry())
    current = _lock(lodash=_entry(host="https://evil.example.net"))

    result = detect(current, baseline_lockfile=baseline, ecosystems=["npm"])

    assert _types(result) == {"lodash": "resolved_source_change"}


def test_registry_entry_without_integrity_is_flagged_without_baseline() -> None:
    current = _lock(lodash=_entry(integrity=None), local={"version": "1.0.0", "link": True})

    result = detect(current, baseline_lockfile=None, ecosystems=["npm"])

    assert _types(result) == {"lodash": "missing_integrity"}


def test_non_npm_is_not_covered() -> None:
    result = detect(None, baseline_lockfile=None, ecosystems=["pypi"])

    assert result.findings == []
    assert result.coverage[0].status == "not_covered"


def test_registered_for_npm() -> None:
    assert "lockfile_integrity" in {plugin.name for plugin in DETECTORS["npm"]}


def _git(path: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=path, check=True, capture_output=True, text=True,
    )
    return done.stdout.strip()


def test_scan_with_baseline_flags_tampered_lodash_integrity(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    _git(target, "init", "-q")
    lock = target / "package-lock.json"
    lock.write_text(json.dumps(_lock(lodash=_entry(integrity="sha512-AAA"))), encoding="utf-8")
    _git(target, "add", "package-lock.json")
    _git(target, "commit", "-q", "-m", "base")
    base_sha = _git(target, "rev-parse", "HEAD")
    lock.write_text(json.dumps(_lock(lodash=_entry(integrity="sha512-TAMPERED"))), encoding="utf-8")
    _git(target, "commit", "-qam", "bump")
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "run.json").write_text(
        json.dumps({
            "scan_id": "b", "target": str(target), "commit_sha": base_sha,
            "started_at": datetime.now(UTC).isoformat(),
        }),
        encoding="utf-8",
    )

    def inventory(context: Any) -> None:
        context.sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
        context.result.graph = GraphArtifact(nodes=[
            Component(
                component_id="l", purl="pkg:npm/lodash@4.17.4", name="lodash", ecosystem="npm"
            ),
        ])

    monkeypatch.setattr(runner, "_inventory", inventory)
    monkeypatch.setattr(runner, "_scanners", lambda context: None)
    monkeypatch.setattr(runner, "_render", lambda directory: None)

    result = runner.scan(target, tmp_path / "out", baseline=baseline, use_llm=False)

    flagged = [f for f in result.findings if f.anomaly_type == "integrity_change"]
    assert [f.purl for f in flagged] == ["pkg:npm/lodash@4.17.4"]
    assert (flagged[0].risk_rule_id, flagged[0].risk_level) == ("R-AN-1", "high")


def test_plugin_reads_baseline_lockfile_from_baseline_scan_artifacts(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "package-lock.json").write_text(
        json.dumps(_lock(lodash=_entry(integrity="sha512-TAMPERED"))), encoding="utf-8"
    )
    baseline = tmp_path / "baseline"
    saved = baseline / "raw/detectors/install_script/lockfiles/package-lock.json"
    saved.parent.mkdir(parents=True)
    saved.write_text(json.dumps(_lock(lodash=_entry(integrity="sha512-AAA"))), encoding="utf-8")
    out = tmp_path / "out"
    (out / "raw").mkdir(parents=True)
    context = SimpleNamespace(
        target_path=target, sbom=out / "sbom.cdx.json", baseline=baseline, out=out,
        result=SimpleNamespace(graph=GraphArtifact()), evidence=EvidenceStore(out),
    )
    plugin = next(item for item in DETECTORS["npm"] if item.name == "lockfile_integrity")

    result = plugin.run(context)

    assert [f.anomaly_type for f in result.findings] == ["integrity_change"]
