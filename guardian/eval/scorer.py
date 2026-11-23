"""Holdout scorer: measures anomaly-detector precision and recall on planted scenarios.

For each ``holdout-scenarios/<id>/``:
1. copy the clean base target to a temporary folder and copy ``overlay/`` over it;
2. scan it with ``scan_fn`` (wired by the runner/CLI, so the scorer has no pipeline imports);
3. keep only anomaly findings that are NEW compared with a scan of the clean base;
4. compare them with ``expected.json`` on (kind, anomaly_type, package identity).

Package identity ignores the purl type and version, so ``pkg:npm/left-pad@1.3.0``
matches an expected ``pkg:npm/left-pad``.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

DETECTOR_FOR_TYPE: dict[str, str] = {
    "unexpected_dependency": "sbom_diff",
    "dependency_update": "sbom_diff",
    "suspected_typosquat": "typosquat",
    "install_script_change": "install_script",
    "unpinned_base_image": "image_pin",
    "unpinned_ci_action": "ci_pin",
}


class ObservedFinding(BaseModel):
    kind: str
    anomaly_type: str | None = None
    purl: str

    def key(self) -> tuple[str, str, str]:
        return self.kind, self.anomaly_type or "", package_identity(self.purl)


class Scenario(BaseModel):
    scenario_id: str
    description: str
    base: str
    author: str
    folder: Path
    expected: list[ObservedFinding]


class ScenarioResult(BaseModel):
    scenario_id: str
    passed: bool
    missing: list[str] = Field(default_factory=list)
    unexpected: list[str] = Field(default_factory=list)
    error: str | None = None


class DetectorScore(BaseModel):
    detector: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float | None:
        found = self.true_positives + self.false_positives
        return self.true_positives / found if found else None

    @property
    def recall(self) -> float | None:
        planted = self.true_positives + self.false_negatives
        return self.true_positives / planted if planted else None


class EvalReport(BaseModel):
    scenarios: list[ScenarioResult]
    detectors: list[DetectorScore]


ScanFn = Callable[[Path], list[ObservedFinding]]


def package_identity(purl: str) -> str:
    """'pkg:npm/%40scope/name@1.0?x=y' -> '@scope/name' ; 'pkg:github/org/act@v1' -> 'org/act'."""
    body = purl.removeprefix("pkg:").split("?")[0].split("#")[0]
    body = body.split("/", 1)[1] if "/" in body else body
    body = body.replace("%40", "@")
    name = body.rsplit("@", 1)[0] if body.count("@") > (1 if body.startswith("@") else 0) else body
    return name.lower()


def load_scenarios(root: Path) -> list[Scenario]:
    scenarios = []
    for folder in sorted(p for p in root.iterdir() if (p / "scenario.yaml").is_file()):
        meta = yaml.safe_load((folder / "scenario.yaml").read_text(encoding="utf-8"))
        expected = json.loads((folder / "expected.json").read_text(encoding="utf-8"))
        scenarios.append(
            Scenario(
                scenario_id=folder.name,
                description=meta["description"],
                base=meta["base"],
                author=meta["author"],
                folder=folder,
                expected=[ObservedFinding.model_validate(e) for e in expected],
            )
        )
    return scenarios


def apply_overlay(base: Path, overlay: Path, dest: Path) -> None:
    shutil.copytree(base, dest, symlinks=True, ignore=shutil.ignore_patterns("node_modules"))
    if overlay.is_dir():
        shutil.copytree(overlay, dest, dirs_exist_ok=True)


def _anomaly_keys(findings: list[ObservedFinding]) -> set[tuple[str, str, str]]:
    return {f.key() for f in findings if f.kind == "anomaly"}


def _score_scenario(
    scenario: Scenario, base: Path, scan_fn: ScanFn, baseline: set[tuple[str, str, str]]
) -> tuple[ScenarioResult, set[tuple[str, str, str]]]:
    with tempfile.TemporaryDirectory(prefix=f"holdout-{scenario.scenario_id}-") as tmp:
        target = Path(tmp) / "target"
        apply_overlay(base, scenario.folder / "overlay", target)
        try:
            observed = _anomaly_keys(scan_fn(target)) - baseline
        except Exception as exc:  # noqa: BLE001 - one broken scenario must not stop the evaluation
            return ScenarioResult(
                scenario_id=scenario.scenario_id, passed=False, error=repr(exc)
            ), set()
    expected = {e.key() for e in scenario.expected}
    missing, unexpected = expected - observed, observed - expected
    return ScenarioResult(
        scenario_id=scenario.scenario_id,
        passed=not missing and not unexpected,
        missing=sorted(":".join(k) for k in missing),
        unexpected=sorted(":".join(k) for k in unexpected),
    ), observed


def _update_scores(
    scores: dict[str, DetectorScore],
    expected: set[tuple[str, str, str]],
    observed: set[tuple[str, str, str]],
) -> None:
    for key in expected | observed:
        detector = DETECTOR_FOR_TYPE.get(key[1], key[1] or "unknown")
        score = scores.setdefault(detector, DetectorScore(detector=detector))
        if key in expected and key in observed:
            score.true_positives += 1
        elif key in observed:
            score.false_positives += 1
        else:
            score.false_negatives += 1


def evaluate(scenarios_dir: Path, base: Path, scan_fn: ScanFn) -> EvalReport:
    baseline = _anomaly_keys(scan_fn(base))
    results: list[ScenarioResult] = []
    scores: dict[str, DetectorScore] = {}
    for scenario in load_scenarios(scenarios_dir):
        result, observed = _score_scenario(scenario, base, scan_fn, baseline)
        results.append(result)
        if result.error is None:
            _update_scores(scores, {e.key() for e in scenario.expected}, observed)
    return EvalReport(
        scenarios=results, detectors=sorted(scores.values(), key=lambda s: s.detector)
    )


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def format_report(report: EvalReport) -> str:
    lines = ["Scenario results:"]
    for r in report.scenarios:
        status = "PASS" if r.passed else "FAIL"
        detail = r.error or "; ".join(
            filter(
                None,
                [
                    f"missing {', '.join(r.missing)}" if r.missing else "",
                    f"unexpected {', '.join(r.unexpected)}" if r.unexpected else "",
                ],
            )
        )
        lines.append(f"  {status}  {r.scenario_id}" + (f"  ({detail})" if detail else ""))
    lines.append("Per-detector precision / recall:")
    for s in report.detectors:
        lines.append(
            f"  {s.detector:<15} precision {_fmt(s.precision):>4}  recall {_fmt(s.recall):>4}  "
            f"(TP {s.true_positives}, FP {s.false_positives}, FN {s.false_negatives})"
        )
    return "\n".join(lines)


def run_eval(scenarios_dir: Path, base: Path, scan_fn: ScanFn) -> int:
    """Entry point for ``guardian eval``. Returns 0 when every scenario passes."""
    report = evaluate(scenarios_dir, base, scan_fn)
    print(format_report(report))
    return 0 if all(r.passed for r in report.scenarios) else 1
