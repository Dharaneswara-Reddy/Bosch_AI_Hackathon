from __future__ import annotations

import json
from pathlib import Path

from guardian.eval.scorer import (
    DETECTOR_FOR_TYPE,
    ObservedFinding,
    evaluate,
    load_scenarios,
    package_identity,
)

REPO = Path(__file__).resolve().parents[2]


def _scenario(root: Path, sid: str, deps: dict[str, str], expected: list[dict[str, str]]) -> None:
    folder = root / sid
    (folder / "overlay").mkdir(parents=True)
    (folder / "overlay" / "package.json").write_text(json.dumps({"dependencies": deps}))
    (folder / "scenario.yaml").write_text(f"description: {sid}\nbase: test\nauthor: P4\n")
    (folder / "expected.json").write_text(json.dumps(expected))


def _fake_scan(base_deps: dict[str, str]):  # type: ignore[no-untyped-def]
    """Stands in for `guardian scan`: flags new names and changed versions against the base."""

    def scan(target: Path) -> list[ObservedFinding]:
        deps = json.loads((target / "package.json").read_text())["dependencies"]
        found = [
            ObservedFinding(
                kind="anomaly", anomaly_type="unexpected_dependency", purl=f"pkg:npm/{n}@{v}"
            )
            for n, v in deps.items()
            if n not in base_deps
        ]
        found += [
            ObservedFinding(
                kind="anomaly", anomaly_type="dependency_update", purl=f"pkg:npm/{n}@{v}"
            )
            for n, v in deps.items()
            if n in base_deps and base_deps[n] != v
        ]
        return found + [ObservedFinding(kind="vulnerability", purl="pkg:npm/jsonwebtoken@0.4.0")]

    return scan


def test_scores_planted_scenarios(tmp_path: Path) -> None:
    base_deps = {"express": "4.0.0", "z85": "0.0.2"}
    base = tmp_path / "base"
    base.mkdir()
    (base / "package.json").write_text(json.dumps({"dependencies": base_deps}))
    scenarios = tmp_path / "scenarios"
    _scenario(
        scenarios,
        "s1",
        {**base_deps, "left-pad": "1.3.0"},
        [{"kind": "anomaly", "anomaly_type": "unexpected_dependency", "purl": "pkg:npm/left-pad"}],
    )
    _scenario(
        scenarios,
        "s2",
        {**base_deps, "z85": "0.0.1"},
        [{"kind": "anomaly", "anomaly_type": "dependency_update", "purl": "pkg:npm/z85"}],
    )
    _scenario(
        scenarios,
        "s3",
        {**base_deps, "crossenv": "0.0.2-security"},
        [
            {"kind": "anomaly", "anomaly_type": "suspected_typosquat", "purl": "pkg:npm/crossenv"},
            {
                "kind": "anomaly",
                "anomaly_type": "unexpected_dependency",
                "purl": "pkg:npm/crossenv",
            },
        ],
    )

    report = evaluate(scenarios, base, _fake_scan(base_deps))

    passed = {r.scenario_id: r.passed for r in report.scenarios}
    assert passed == {"s1": True, "s2": True, "s3": False}
    scores = {s.detector: s for s in report.detectors}
    assert scores["sbom_diff"].precision == 1.0 and scores["sbom_diff"].recall == 1.0
    assert scores["typosquat"].recall == 0.0 and scores["typosquat"].precision is None


def test_scenario_error_is_reported_not_raised(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    (base / "package.json").write_text(json.dumps({"dependencies": {}}))
    _scenario(tmp_path / "scenarios", "boom", {"x": "1.0.0"}, [])
    calls = {"n": 0}

    def scan(target: Path) -> list[ObservedFinding]:
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("scanner crashed")
        return []

    report = evaluate(tmp_path / "scenarios", base, scan)
    assert report.scenarios[0].error is not None and not report.scenarios[0].passed


def test_package_identity_ignores_type_and_version() -> None:
    assert package_identity("pkg:npm/left-pad@1.3.0") == "left-pad"
    assert package_identity("pkg:npm/%40angular/core@17.0.0") == "@angular/core"
    assert package_identity("pkg:npm/@angular/core") == "@angular/core"
    assert (
        package_identity("pkg:github/aquasecurity/trivy-action@master")
        == "aquasecurity/trivy-action"
    )
    assert (
        package_identity("pkg:githubactions/aquasecurity/trivy-action@master")
        == "aquasecurity/trivy-action"
    )


def test_real_holdout_scenarios_are_well_formed() -> None:
    scenarios = load_scenarios(REPO / "holdout-scenarios")
    assert 3 <= len(scenarios) <= 5
    for scenario in scenarios:
        assert scenario.expected, scenario.scenario_id
        assert (scenario.folder / "overlay").is_dir()
        assert all(
            e.kind == "anomaly" and e.anomaly_type in DETECTOR_FOR_TYPE for e in scenario.expected
        )
