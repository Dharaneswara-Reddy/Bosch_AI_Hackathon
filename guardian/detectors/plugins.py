"""Adapters from detector functions to the shared runner's plugin protocol."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from guardian.detectors import ci_pin, git_diff, image_pin, install_script, sbom_diff, typosquat
from guardian.detectors._common import (
    DetectionResult,
    DetectorContext,
    coverage_rows,
    ecosystem_list,
    evidence_record,
    json_bytes,
    sha256_bytes,
)
from guardian.models import UNKNOWN, CoverageRow, Finding, Scan


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _ecosystems(context: DetectorContext) -> list[str]:
    nodes = getattr(context.result.graph, "nodes", [])
    return ecosystem_list(nodes)


def _baseline_commit(context: DetectorContext) -> str | None:
    if context.baseline is None:
        return None
    run_file = context.baseline / "run.json"
    if not run_file.is_file():
        return None
    scan = Scan.model_validate_json(run_file.read_text(encoding="utf-8"))
    return None if scan.commit_sha == UNKNOWN else scan.commit_sha


def _run_sbom_diff(context: DetectorContext) -> DetectionResult:
    current = _read_json(context.sbom)
    baseline_file = context.baseline / "sbom.cdx.json" if context.baseline else None
    baseline = _read_json(baseline_file) if baseline_file and baseline_file.is_file() else None
    return sbom_diff.detect(current, baseline)


def _run_git_diff(context: DetectorContext) -> DetectionResult:
    ecosystems = _ecosystems(context)
    if context.target_path is None:
        return DetectionResult(
            coverage=coverage_rows(
                "git_diff", ecosystems, "n/a", "Target is not a local repository"
            )
        )
    return git_diff.detect(context.target_path, _baseline_commit(context), ecosystems=ecosystems)


def _run_typosquat(context: DetectorContext) -> DetectionResult:
    return typosquat.detect(_read_json(context.sbom))


def _run_image_pin(context: DetectorContext) -> DetectionResult:
    ecosystems = _ecosystems(context)
    if context.target_path is None:
        return DetectionResult(
            coverage=coverage_rows(
                "image_pin", ecosystems, "n/a", "Dockerfile checks require a local repository"
            )
        )
    return image_pin.detect(context.target_path, ecosystems=ecosystems)


def _run_ci_pin(context: DetectorContext) -> DetectionResult:
    ecosystems = _ecosystems(context)
    if context.target_path is None:
        return DetectionResult(
            coverage=coverage_rows(
                "ci_pin", ecosystems, "n/a", "Workflow checks require a local repository"
            )
        )
    return ci_pin.detect(context.target_path, ecosystems=ecosystems)


def _git_lockfile(target: Path, commit: str, relative: str) -> dict[str, object]:
    completed = subprocess.run(
        ["git", "-C", str(target), "show", f"{commit}:{relative}"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        return {"packages": {}}
    parsed = json.loads(completed.stdout.decode("utf-8"))
    return parsed if isinstance(parsed, dict) else {"packages": {}}


def _run_install_script(context: DetectorContext) -> DetectionResult:
    ecosystems = _ecosystems(context)
    if context.target_path is None:
        return install_script.detect(None, baseline_lockfile=None, ecosystems=ecosystems)

    root = context.target_path
    target_lockfiles = sorted(
        path
        for path in root.rglob("package-lock.json")
        if path.is_file() and not ({".git", "node_modules", "artifacts"} & set(path.parts))
    )
    if not target_lockfiles:
        no_lock_rows = []
        for ecosystem in ecosystems:
            status = "n/a" if ecosystem == "npm" else "not_covered"
            reason = (
                "No npm lockfile found"
                if ecosystem == "npm"
                else "Install scripts are checked for npm only"
            )
            no_lock_rows.extend(coverage_rows("install_script", [ecosystem], status, reason))
        return DetectionResult(coverage=no_lock_rows)

    baseline_commit = _baseline_commit(context)
    combined = DetectionResult()
    for lockfile in target_lockfiles:
        relative = lockfile.relative_to(root).as_posix()
        baseline = _git_lockfile(root, baseline_commit, relative) if baseline_commit else None
        partial = install_script.detect(lockfile, baseline_lockfile=baseline, ecosystems=["npm"])
        lock_bytes = lockfile.read_bytes()
        artifact_file = f"raw/detectors/install_script/lockfiles/{relative}"
        combined.artifacts[artifact_file] = lock_bytes
        for record in partial.evidence:
            combined.evidence.append(
                record.model_copy(
                    update={"file": artifact_file, "sha256": sha256_bytes(lock_bytes)},
                    deep=True,
                )
            )
        combined.findings.extend(partial.findings)
        combined.finding_details.update(partial.finding_details)

    # The same package can occur in root and frontend lockfiles; keep one finding
    # with evidence from each lockfile.
    unique: dict[str, Finding] = {}
    for finding in combined.findings:
        existing = unique.get(finding.finding_id)
        if existing is None:
            unique[finding.finding_id] = finding
        else:
            existing.evidence_ids = sorted(set(existing.evidence_ids + finding.evidence_ids))
    combined.findings = list(unique.values())

    counts = {ecosystem: 0 for ecosystem in ecosystems}
    counts["npm"] = len(target_lockfiles)
    status = "finding" if combined.findings else "pass"
    coverage: list[CoverageRow] = []
    for ecosystem in ecosystems:
        if ecosystem == "npm":
            coverage.extend(coverage_rows("install_script", [ecosystem], status, "", counts))
        else:
            coverage.extend(
                coverage_rows(
                    "install_script",
                    [ecosystem],
                    "not_covered",
                    "Install scripts are checked for npm only",
                    counts,
                )
            )
    combined.coverage = coverage
    return combined


def _materialize_result(
    context: DetectorContext, name: str, result: DetectionResult
) -> DetectionResult:
    """Copy evidence into raw/, register it, then return the runner payload."""
    artifacts = dict(result.artifacts)
    staged_records = []
    for index, record in enumerate(result.evidence):
        if record.file.startswith("raw/"):
            staged_records.append(record)
            continue
        if record.file == "sbom.cdx.json":
            source = context.sbom
        elif context.target_path is not None:
            source = context.target_path / record.file
        else:
            raise ValueError(f"Cannot locate evidence source {record.file} for {name}.")
        content = source.read_bytes()
        raw_file = f"raw/detectors/{name}/source-{index:04d}-{source.name}"
        artifacts[raw_file] = content
        staged_records.append(
            record.model_copy(
                update={"file": raw_file, "sha256": sha256_bytes(content)}, deep=True
            )
        )

    if result.finding_details:
        details_file = f"raw/detectors/{name}/details.json"
        details_bytes = json_bytes({"findings": result.finding_details})
        artifacts[details_file] = details_bytes
        for finding in result.findings:
            record = evidence_record(
                name,
                details_file,
                f"/findings/{finding.finding_id}",
                details_bytes,
            )
            if record.evidence_id not in finding.evidence_ids:
                finding.evidence_ids.append(record.evidence_id)
            staged_records.append(record)

    raw_root = (context.out / "raw").resolve()
    for relative, content in artifacts.items():
        destination = (context.out / relative).resolve()
        if not destination.is_relative_to(raw_root):
            raise ValueError(f"Detector {name} tried to write outside raw/: {relative}.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    if staged_records:
        context.evidence.record_many(staged_records)
    result.artifacts = artifacts
    result.evidence = staged_records
    return result


@dataclass(frozen=True)
class DetectorPlugin:
    """Runner adapter around one detector's pure `detect` function."""

    name: str
    callback: Callable[[DetectorContext], DetectionResult]

    def run(self, context: DetectorContext) -> DetectionResult:
        return _materialize_result(context, self.name, self.callback(context))


__all__ = [
    "DetectorPlugin",
    "_run_ci_pin",
    "_run_git_diff",
    "_run_image_pin",
    "_run_install_script",
    "_run_sbom_diff",
    "_run_typosquat",
]
