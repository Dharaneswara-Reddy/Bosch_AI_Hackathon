"""Coordinate the Day 1 inventory, defensive checks, and evidence report."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from uuid import uuid4

from pydantic import BaseModel, Field, TypeAdapter, ValidationError

from guardian.ai.review import load_injected, run_review
from guardian.analysis import apply_relevance, apply_scope
from guardian.confidence import apply_confidence
from guardian.config import Settings
from guardian.coverage import build_coverage
from guardian.evidence import EvidenceStore, file_sha256
from guardian.models import (
    UNKNOWN, Component, CoverageArtifact, CoverageRow, CoverageStatus, Edge,
    Evidence, Finding, FindingsArtifact, GraphArtifact, LlmStatus, Resolution, RunResult,
    Scan, ScanStatus, Scope,
)
from guardian.policy import DEFAULT_POLICY_PATH, load_policy
from guardian.risk import assess
from guardian.tools import ToolError

LOCKFILES = {
    "Cargo.lock", "Gemfile.lock", "go.mod", "go.sum", "package-lock.json",
    "npm-shrinkwrap.json", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "yarn.lock",
}
OUTPUT_FILES = ("run.json", "graph.json", "findings.json", "coverage.json")
IMAGE_REF = re.compile(r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}")


@dataclass
class ScanContext:
    """Integration inputs shared by the P1–P4 stage entry points."""

    target: Path | str
    out: Path
    baseline: Path | None
    settings: Settings
    result: RunResult
    evidence: EvidenceStore
    inject_claim: Path | None
    coverage_rows: list[CoverageRow] = field(default_factory=list)
    graph: object | None = None

    @property
    def sbom(self) -> Path:
        return self.out / "sbom.cdx.json"

    @property
    def target_path(self) -> Path | None:
        return self.target if isinstance(self.target, Path) else None


class _BomComponent(BaseModel):
    ref: str | None = Field(default=None, alias="bom-ref")
    purl: str = UNKNOWN
    name: str
    version: str = UNKNOWN


class _Bom(BaseModel):
    components: list[_BomComponent] = Field(default_factory=list)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_model(path: Path, data: BaseModel) -> None:
    temporary = path.with_name(f".{path.name}-{uuid4().hex}.tmp")
    try:
        temporary.write_text(data.model_dump_json(indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _checkpoint(context: ScanContext) -> None:
    result = context.result
    result.evidence = context.evidence.records()
    findings = FindingsArtifact(
        findings=result.findings, evidence=result.evidence, claims=result.claims,
        agent_trace=result.agent_trace,
    )
    for filename, data in zip(OUTPUT_FILES, (result.scan, result.graph, findings, result.coverage)):
        _write_model(context.out / filename, data)


def _module(name: str) -> ModuleType:
    try:
        return import_module(name)
    except ModuleNotFoundError as error:
        missing = error.name or ""
        if name == missing or name.startswith(f"{missing}."):
            raise RuntimeError(f"Team stage {name} is unavailable on this checkout.") from error
        raise


def _attempt(
    context: ScanContext, name: str, action: Callable[[ScanContext], None],
    *, optional: bool = False,
) -> bool:
    try:
        action(context)
    except Exception as error:
        scan = context.result.scan
        if isinstance(error, ToolError) and error.run is not None:
            scan.tools.append(error.run)
        scan.errors[name] = str(error) or type(error).__name__
        if optional:
            scan.llm_status = LlmStatus.FAILED
        return False
    return True


def _resolve(context: ScanContext, work: Path) -> object | None:
    if context.target_path is None:
        context.result.scan.resolution = Resolution.IMAGE
        return None
    registry = _module("guardian.resolve")
    if callable(getattr(registry, "resolve_target", None)):
        resolved = registry.resolve_target(context.target_path, work)
    else:
        resolvers = registry.detect(context.target_path)
        if not resolvers:
            return None
        if len(resolvers) != 1:
            raise RuntimeError("P1 must expose resolve_target() to merge multiple resolvers.")
        resolved = resolvers[0].resolve(context.target_path, work)
    context.result.scan.resolution = Resolution(resolved.resolution)
    resolved_result: object = resolved
    return resolved_result


def _normalize_graph(path: Path, sbom: Path, graph: object) -> GraphArtifact:
    if isinstance(graph, GraphArtifact):
        return graph
    if isinstance(graph, dict):
        return GraphArtifact.model_validate(graph)
    if path.is_file():
        return GraphArtifact.model_validate_json(_read(path))
    if not callable(getattr(graph, "edges", None)):
        raise ValueError("P1 graph must return a GraphArtifact or a NetworkX graph.")
    bom = _Bom.model_validate_json(_read(sbom))
    nodes = [
        Component(
            component_id=component.ref or component.purl,
            purl=component.purl, name=component.name, version=component.version,
            ecosystem=component.purl.removeprefix("pkg:").split("/", 1)[0],
            scope=Scope.UNKNOWN,
        )
        for component in bom.components if component.ref or component.purl != UNKNOWN
    ]
    edge_rows = getattr(graph, "edges")(data=True)
    edges = [
        Edge(parent_id=str(parent), child_id=str(child), edge_source=attrs.get("edge_source", "sbom"))
        for parent, child, attrs in edge_rows
    ]
    return GraphArtifact(nodes=nodes, edges=edges)


def _inventory(context: ScanContext) -> None:
    with TemporaryDirectory(prefix="guardian-resolve-") as workspace:
        resolved: object | None = None

        def resolve(active: ScanContext) -> None:
            nonlocal resolved
            resolved = _resolve(active, Path(workspace))

        _attempt(context, "resolve", resolve)
        source = Path(_module("guardian.sbom").build_sbom(context.target, resolved))
        if source.resolve() != context.sbom.resolve():
            shutil.copyfile(source, context.sbom)
    graph_path = context.out / "graph.json"
    context.graph = _module("guardian.graph").load_graph(context.sbom)
    context.result.graph = _normalize_graph(graph_path, context.sbom, context.graph)


def _database_date(context: ScanContext, name: str, evidence: list[Evidence]) -> str:
    reported = {record.db_built_at for record in evidence} - {UNKNOWN}
    configured = context.result.scan.db_built_at.get(name, UNKNOWN)
    if len(reported) == 1:
        date = reported.pop()
    elif configured != UNKNOWN:
        date = configured
    elif name == "osv":
        # OSV-Scanner has no local database; it queries api.osv.dev during the scan.
        date = f"live api.osv.dev at {datetime.now(UTC).isoformat(timespec='seconds')}"
    else:
        date = UNKNOWN
    context.result.scan.db_built_at[name] = date
    return date


def _scan_advisories(context: ScanContext, name: str) -> list[Finding]:
    scanner = _module(f"guardian.scanners.{name}")
    image = context.settings.tool_images.get(name)
    image = image or getattr(scanner, f"{name.upper()}_IMAGE")
    source = Path(getattr(scanner, f"run_{name}")(context.sbom, context.out, image))
    artifact = source.resolve()
    artifact.relative_to(context.out / "raw")
    relative = artifact.relative_to(context.out).as_posix()
    checksum = file_sha256(source)
    raw = TypeAdapter(dict[str, object]).validate_json(_read(source))
    parse = getattr(scanner, f"parse_{name}")
    if name == "grype":
        findings, records = parse(raw, relative, checksum)
    else:
        tool_version = "2.7.1" if image == scanner.OSV_IMAGE else image
        findings, records = parse(raw, relative, checksum, tool_version)
    context.result.scan.scanner_versions[name] = image
    evidence = TypeAdapter(list[Evidence]).validate_python(records)
    database_date = _database_date(context, name, evidence)
    context.evidence.record_many(
        record.model_copy(update={"db_built_at": database_date}) for record in evidence
    )
    return TypeAdapter(list[Finding]).validate_python(findings)


def _paths(context: ScanContext, findings: list[Finding]) -> list[Finding]:
    if context.graph is None:
        return findings
    graph_api = _module("guardian.graph")
    scanner_api = _module("guardian.scanners.merge")
    component_ids = {node.component_id for node in context.result.graph.nodes}
    ids_by_purl: dict[str, set[str]] = {}
    for node in context.result.graph.nodes:
        if node.purl != UNKNOWN:
            ids_by_purl.setdefault(node.purl, set()).add(node.component_id)

    matched: list[Finding] = []
    for finding in findings:
        if finding.component_id not in component_ids:
            candidates = ids_by_purl.get(finding.purl, set())
            if len(candidates) == 1:
                finding = finding.model_copy(update={"component_id": next(iter(candidates))})
        matched.append(finding)

    paths: dict[str, tuple[list[str], int]] = {}
    for component in sorted({finding.component_id for finding in matched} & component_ids):
        path = graph_api.shortest_path(context.graph, component)
        if path:
            paths[component] = (list(path), graph_api.path_count(context.graph, component))
    return TypeAdapter(list[Finding]).validate_python(scanner_api.attach_paths(matched, paths))


def _scanners(context: ScanContext) -> None:
    if not context.sbom.is_file():
        raise RuntimeError("Scanner checks require the SBOM artifact.")
    batches: list[list[Finding]] = []
    for name in ("grype", "osv"):
        def apply(active: ScanContext, scanner: str = name) -> None:
            batches.append(_scan_advisories(active, scanner))

        _attempt(context, name, apply)
    findings = [finding for batch in batches for finding in batch]
    context.result.findings.extend(findings)
    if findings:
        merged = _module("guardian.scanners.merge").merge_findings(findings)
        context.result.findings = TypeAdapter(list[Finding]).validate_python(merged)
        context.result.findings = _paths(context, context.result.findings)


def _detectors(context: ScanContext) -> None:
    registry = _module("guardian.detectors").DETECTORS
    ecosystems = sorted({node.ecosystem for node in context.result.graph.nodes} - {UNKNOWN})
    for key in ("any", *ecosystems):
        for detector in registry.get(key, []):
            name = getattr(detector, "name", type(detector).__name__)

            def apply(active: ScanContext, plugin: object = detector) -> None:
                result = getattr(plugin, "run")(active)
                findings = TypeAdapter(list[Finding]).validate_python(result.findings)
                rows = TypeAdapter(list[CoverageRow]).validate_python(result.coverage_rows)
                active.result.findings.extend(findings)
                active.coverage_rows.extend(rows)

            if not _attempt(context, f"detector:{key}:{name}", apply):
                context.coverage_rows.append(CoverageRow(
                    detector=name, ecosystem=key, status=CoverageStatus.ERROR,
                    reason=context.result.scan.errors[f"detector:{key}:{name}"],
                ))


def _classify(context: ScanContext) -> None:
    policy = load_policy(DEFAULT_POLICY_PATH)
    development = {node.component_id: node.dev for node in context.result.graph.nodes}
    for index, finding in enumerate(context.result.findings):
        try:
            assessed = assess(finding, dev=development.get(finding.component_id), policy=policy)
            revised = apply_confidence(assessed, policy)
        except ValueError as error:
            context.result.scan.errors[f"risk:{finding.finding_id}"] = str(error)
        else:
            context.result.findings[index] = revised


def _scope(context: ScanContext) -> None:
    roots = getattr(context.graph, "graph", {}).get("roots", []) if context.graph else []
    apply_scope(context.result, context.target_path, list(roots))


def _relevance(context: ScanContext) -> None:
    apply_relevance(context.result, context.target_path, context.out, context.evidence)


def _review(context: ScanContext) -> None:
    result = context.result
    injected = load_injected(context.inject_claim, result) if context.inject_claim else []
    claims, status, trace = run_review(result, context.settings, injected)
    result.claims.extend(claims)
    result.agent_trace = trace
    result.scan.llm_status = status


def _render(run_dir: Path) -> None:
    _module("guardian.report.render").render(run_dir)


def _git(target: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", *args],
            cwd=target, capture_output=True, check=True, text=True, timeout=10,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    return completed.stdout.strip()


def _lockfile_hash(target: Path) -> str:
    digest = hashlib.sha256()
    count = 0
    for directory, folders, files in os.walk(target):
        folders[:] = sorted(
            name for name in folders
            if not name.startswith(".") and name not in {"node_modules", "artifacts", "venv"}
        )
        for name in sorted(LOCKFILES.intersection(files)):
            path = Path(directory) / name
            if not path.is_symlink():
                identity = path.relative_to(target).as_posix()
                digest.update(json.dumps([identity, file_sha256(path)]).encode("utf-8"))
                count += 1
    return digest.hexdigest() if count else UNKNOWN


def _cache(context: ScanContext, clean_commit: bool) -> RunResult | None:
    wanted = context.result.scan
    if (
        not clean_commit or wanted.lockfile_hash == UNKNOWN or context.baseline is not None
        or context.inject_claim is not None or context.settings.provider != "none"
        or not {"syft", "grype", "osv"} <= wanted.scanner_versions.keys()
        or not {"grype", "osv"} <= wanted.db_built_at.keys()
    ):
        return None
    try:
        previous = Scan.model_validate_json(_read(context.out / "run.json"))
        fields = ("target", "commit_sha", "lockfile_hash", "scanner_versions", "db_built_at")
        if (
            previous.status != ScanStatus.COMPLETE or previous.ended_at is None
            or previous.llm_status != LlmStatus.UNAVAILABLE
            or not context.sbom.is_file()
            or any(getattr(previous, field) != getattr(wanted, field) for field in fields)
        ):
            return None
        artifacts = FindingsArtifact.model_validate_json(_read(context.out / "findings.json"))
        graph = GraphArtifact.model_validate_json(_read(context.out / "graph.json"))
        coverage = CoverageArtifact.model_validate_json(_read(context.out / "coverage.json"))
        hashes: dict[Path, str] = {}
        for evidence in artifacts.evidence:
            path = (context.out / evidence.file).resolve()
            if not path.is_relative_to(context.out / "raw"):
                return None
            if path not in hashes:
                hashes[path] = file_sha256(path)
            if hashes[path] != evidence.sha256:
                return None
        if previous.ended_at.tzinfo is None or artifacts.claims:
            return None
    except (OSError, ValidationError, UnicodeError):
        return None
    previous.cached_age_minutes = max(0, (datetime.now(UTC) - previous.ended_at).total_seconds() / 60)
    _write_model(context.out / "run.json", previous)
    return RunResult(scan=previous, graph=graph, coverage=coverage, **artifacts.model_dump())


def _prepare(
    target: Path | str, out: Path, baseline: Path | None, use_llm: bool,
    inject_claim: Path | None,
) -> tuple[ScanContext, bool]:
    candidate = Path(target).resolve()
    out = out.resolve()
    baseline = baseline.resolve(strict=True) if baseline is not None else None
    settings = Settings.load(use_llm=use_llm)
    load_policy(DEFAULT_POLICY_PATH)
    commit, lock_hash, clean = UNKNOWN, UNKNOWN, False
    local: Path | str
    if candidate.is_dir():
        if out == candidate or out in candidate.parents:
            raise ValueError("Choose an output directory separate from the target and its parents.")
        local = candidate
        revision = _git(candidate, "rev-parse", "--verify", "HEAD")
        if revision and re.fullmatch(r"[0-9a-f]{40,64}", revision):
            commit = revision
            clean = _git(candidate, "status", "--porcelain", "--untracked-files=all") == ""
        lock_hash = _lockfile_hash(candidate)
    elif IMAGE_REF.fullmatch(str(target)):
        local = str(target)
    else:
        raise ValueError("Target must be a local directory or a digest-pinned image reference.")
    if baseline == out:
        raise ValueError("Choose a separate output directory from the baseline.")
    out.mkdir(parents=True, exist_ok=True)
    start = datetime.now(UTC)
    record = Scan(
        scan_id=f"{start:%Y%m%dT%H%M%SZ}-{uuid4().hex[:8]}",
        target=str(local), commit_sha=commit, lockfile_hash=lock_hash,
        started_at=start, scanner_versions=settings.tool_images, db_built_at=settings.db_built_at,
    )
    result = RunResult(scan=record)
    claim_file = inject_claim.resolve(strict=True) if inject_claim else None
    return ScanContext(local, out, baseline, settings, result, EvidenceStore(out), claim_file), clean


def scan(
    target: Path | str, out: Path, baseline: Path | None = None, use_llm: bool = True,
    *, inject_claim: Path | None = None,
) -> RunResult:
    """Scan a local checkout or digest-pinned image and write run artifacts."""
    context, clean_commit = _prepare(target, out, baseline, use_llm, inject_claim)
    with _output_lock(context.out):
        return _scan_context(context, clean_commit, use_llm)


@contextmanager
def _output_lock(out: Path) -> Iterator[None]:
    """Prevent concurrent writers; the operating system releases the lock on exit."""
    with (out / ".guardian-scan.lock").open("a+b") as handle:
        try:
            if sys.platform == "win32":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError(f"Another scan is writing to {out}, or it cannot be locked.") from error
        yield


def _scan_context(context: ScanContext, clean_commit: bool, use_llm: bool) -> RunResult:
    cached = _cache(context, clean_commit)
    if cached is not None:
        _render(context.out)
        return cached
    context.sbom.unlink(missing_ok=True)
    (context.out / "graph.json").unlink(missing_ok=True)
    _write_model(context.out / "run.json", context.result.scan)
    for name, action in (
        ("inventory", _inventory), ("scope", _scope), ("scanners", _scanners),
        ("detectors", _detectors), ("relevance", _relevance), ("risk", _classify),
    ):
        _attempt(context, name, action)
        _write_model(context.out / "run.json", context.result.scan)
    result = context.result
    result.coverage = build_coverage(result.graph, result.findings, context.coverage_rows)
    result.evidence = context.evidence.records()
    if use_llm or context.inject_claim is not None:
        _attempt(context, "ai", _review, optional=True)
    result.scan.status = (
        ScanStatus.PARTIAL if result.scan.errors.keys() - {"ai"} else ScanStatus.COMPLETE
    )
    result.scan.ended_at = datetime.now(UTC)
    _checkpoint(context)
    try:
        _render(context.out)
    except Exception as error:
        result.scan.errors["report"] = str(error) or type(error).__name__
        result.scan.status = ScanStatus.PARTIAL
        _write_model(context.out / "run.json", result.scan)
    return result
