from __future__ import annotations

import json
from pathlib import Path

from guardian.detectors import DETECTORS, typosquat, unverified_source
from guardian.models import CoverageStatus, Finding, FindingKind
from guardian.policy import RiskPolicy
from guardian.risk import assess

DEMO = Path(__file__).resolve().parents[1] / "demo" / "vulnerable-app"


def _lock(tmp_path: Path, packages: dict[str, object]) -> Path:
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, **packages}}))
    return path


def test_demo_synthetic_package_is_flagged_and_labelled() -> None:
    result = unverified_source.detect(DEMO, [DEMO / "package-lock.json"])
    [finding] = result.findings
    assert finding.anomaly_type == "unverified_install_script"
    assert finding.purl == "pkg:npm/expresss-session@1.0.0"
    assert finding.risk_note is not None and finding.risk_note.startswith("SYNTHETIC")
    assert result.coverage[0].status == CoverageStatus.FINDING
    details = result.finding_details[finding.finding_id]
    assert details["synthetic"] is True and details["source"].startswith("local path")


def test_demo_typosquat_is_caught_without_hard_coding() -> None:
    result = typosquat.detect(None, target_path=DEMO, graph=None)
    names = {result.finding_details[f.finding_id]["package_name"] for f in result.findings}
    assert names == {"expresss-session"}


def test_registry_packages_with_install_scripts_are_not_flagged(tmp_path: Path) -> None:
    lock = _lock(
        tmp_path,
        {
            "node_modules/core-js": {
                "version": "3.51.0",
                "hasInstallScript": True,
                "resolved": "https://registry.npmjs.org/core-js/-/core-js-3.51.0.tgz",
            }
        },
    )
    assert unverified_source.detect(tmp_path, [lock]).findings == []


def test_git_dependency_with_install_script_is_flagged(tmp_path: Path) -> None:
    lock = _lock(
        tmp_path,
        {
            "node_modules/@acme/tool": {
                "version": "1.0.0",
                "hasInstallScript": True,
                "resolved": "git+ssh://git@example/x.git",
            }
        },
    )
    [finding] = unverified_source.detect(tmp_path, [lock]).findings
    assert finding.purl == "pkg:npm/%40acme/tool@1.0.0"
    assert finding.risk_note is None


def test_local_package_without_install_script_is_not_flagged(tmp_path: Path) -> None:
    lock = _lock(
        tmp_path,
        {
            "node_modules/local": {"resolved": "libs/local", "link": True},
            "libs/local": {"version": "1.0.0"},
        },
    )
    assert unverified_source.detect(tmp_path, [lock]).findings == []


def test_no_lockfile_is_not_applicable(tmp_path: Path) -> None:
    result = unverified_source.detect(tmp_path, [])
    assert result.coverage[0].status == CoverageStatus.NOT_APPLICABLE


def test_detector_is_registered_and_risk_rule_keeps_synthetic_label() -> None:
    assert "unverified_source" in [d.name for d in DETECTORS["npm"]]
    finding = Finding(
        finding_id="x",
        kind=FindingKind.ANOMALY,
        component_id="c",
        purl="p",
        anomaly_type="unverified_install_script",
        risk_note="SYNTHETIC fixture",
    )
    assessed = assess(finding, dev=True, policy=RiskPolicy())
    assert assessed.risk_rule_id == "R-AN-1"
    assert assessed.risk_note is not None
    assert assessed.risk_note.startswith("SYNTHETIC fixture")
    assert assessed.risk_level == "high"
