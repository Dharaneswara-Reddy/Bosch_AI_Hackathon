"""User-triggered npm runtime trace and transitive dependency reachability."""

from __future__ import annotations

import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guardian.reachability import parse_runtime_trace, static_dependency_chains
from guardian.remediate.app_run import run_traced_application
from guardian.remediate.sandbox import Runner, create_sandbox
from guardian.remediate.source import overlay_source
from guardian.remediate.validate import _has_source, _run_container, run_captured

TRACE_HOOK = Path(__file__).parent / "remediate" / "trace" / "guardian-trace.cjs"
TRACE_LOADER = Path(__file__).parent / "remediate" / "trace" / "guardian-trace-loader.mjs"
INSTALL_TIMEOUT = int(os.environ.get("GUARDIAN_REACHABILITY_INSTALL_TIMEOUT", "600"))
TEST_TIMEOUT = int(os.environ.get("GUARDIAN_REACHABILITY_TEST_TIMEOUT", "600"))
APP_TIMEOUT = int(os.environ.get("GUARDIAN_REACHABILITY_APP_TIMEOUT", "60"))


def _scripts(root: Path) -> tuple[bool, bool]:
    try:
        scripts = json.loads((root / "package.json").read_text(encoding="utf-8")).get("scripts", {})
    except (OSError, ValueError):
        return False, False
    return bool(scripts.get("test")), bool(scripts.get("start"))


def run_reachability(work_dir: Path, engine: str | None) -> dict[str, Any]:
    """Run explicitly requested npm tests/start in a locked container and persist evidence."""
    out = work_dir / "out"
    out.mkdir(parents=True, exist_ok=True)
    payload = _empty_payload()
    if engine is None:
        payload["reason"] = "Docker or Podman is unavailable; project code did not run on the host."
        return _save(out, payload)
    repo = work_dir / "repo"
    if not (repo / "package.json").is_file():
        payload["reason"] = "Runtime tracing currently supports npm projects only."
        return _save(out, payload)
    sandbox = work_dir / "reachability-sandbox"
    trace = work_dir / "reachability-trace.jsonl"
    trace.touch()
    try:
        create_sandbox(repo, sandbox)
        source = overlay_source(work_dir, sandbox, run_captured)
        if source.status == "failed":
            payload["reason"] = source.detail
            return _save(out, payload)
        if not _has_source(sandbox):
            payload["reason"] = "no source files were available after fetching the scanned commit"
            return _save(out, payload)
        install = _install(sandbox, engine, run_captured)
        if install:
            payload["reason"] = install
            return _save(out, payload)
        payload.update(_collect_evidence(sandbox, engine, trace, out))
        return _save(out, payload)
    except Exception as error:  # worker boundary: persist a useful fail-safe reason
        payload["status"] = "error"
        payload["reason"] = f"{type(error).__name__}: {error}"
        return _save(out, payload)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
        trace.unlink(missing_ok=True)


def _empty_payload() -> dict[str, Any]:
    return {
        "status": "not_run",
        "reason": "",
        "ran_at": datetime.now(UTC).isoformat(),
        "tests_status": "not_run",
        "app_status": "not_run",
        "evidence": [],
        "packages_loaded_count": 0,
    }


def _install(sandbox: Path, engine: str, capture: Runner) -> str | None:
    result = _run_container(
        capture,
        engine,
        sandbox,
        ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        offline=False,
        timeout=INSTALL_TIMEOUT,
    )
    if result.returncode:
        return f"npm ci --ignore-scripts failed in the container: {result.output[-300:]}"
    return None


def _collect_evidence(sandbox: Path, engine: str, trace: Path, out: Path) -> dict[str, Any]:
    test_script, app_script = _scripts(sandbox)
    statuses = _run_scripts(sandbox, engine, trace, test_script, app_script)
    observed = [
        name
        for name, enabled in (("npm test", test_script), ("app start + /health", app_script))
        if enabled
    ]
    runtime = parse_runtime_trace(trace, sandbox, observed)
    static = static_dependency_chains(sandbox, _finding_packages(out))
    evidence = [item.model_dump() for item in runtime]
    known = {(item["package"], item["version"]) for item in evidence}
    evidence.extend(
        item.model_dump() for item in static if (item.package, item.version) not in known
    )
    ran = bool(test_script or app_script)
    return {
        **statuses,
        "evidence": evidence,
        "packages_loaded_count": len(runtime),
        "status": "complete" if ran or evidence else "not_run",
        "reason": _result_reason(ran),
    }


def _run_scripts(sandbox: Path, engine: str, trace: Path, tests: bool, app: bool) -> dict[str, str]:
    result = {"tests_status": "not_run", "app_status": "not_run"}
    if tests:
        mounts = (
            f"{TRACE_HOOK}:/guardian-trace.cjs:ro",
            f"{TRACE_LOADER}:/guardian-trace-loader.mjs:ro",
            f"{trace}:/trace.jsonl:rw",
        )
        env = (
            "NODE_OPTIONS=--require=/guardian-trace.cjs "
            "--experimental-loader=file:///guardian-trace-loader.mjs",
            "GUARDIAN_TRACE_FILE=/trace.jsonl",
            "GUARDIAN_TRACE_MAX_BYTES=5242880",
        )
        done = _run_container(
            run_captured,
            engine,
            sandbox,
            ["npm", "test"],
            offline=True,
            timeout=TEST_TIMEOUT,
            mounts=mounts,
            env=env,
        )
        result["tests_status"] = "passed" if done.returncode == 0 else "failed"
    if app:
        app_result = run_traced_application(
            sandbox, trace, TRACE_HOOK, TRACE_LOADER, engine, run_captured, APP_TIMEOUT
        )
        result["app_status"] = app_result.status
    return result


def _result_reason(ran: bool) -> str:
    return (
        "npm tests and/or app ran inside an offline container. No test run covers every code path."
        if ran
        else "Static dependency-chain check completed; runtime tests and app were unavailable."
    )


def _finding_packages(out: Path) -> dict[str, set[str]]:
    from guardian.models import FindingsArtifact, GraphArtifact

    try:
        findings = FindingsArtifact.model_validate_json((out / "findings.json").read_text("utf-8"))
        graph = GraphArtifact.model_validate_json((out / "graph.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    nodes = {node.component_id: node for node in graph.nodes}
    packages: dict[str, set[str]] = {}
    for finding in findings.findings:
        node = nodes.get(finding.component_id)
        if node:
            packages.setdefault(node.name, set()).add(node.version)
    return packages


def _save(out: Path, payload: dict[str, Any]) -> dict[str, Any]:
    target = out / "reachability.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)
    return payload


def update_findings(work_dir: Path) -> None:
    """Merge positive trace evidence into existing findings and refresh report artifacts."""
    from guardian.models import FindingsArtifact, GraphArtifact

    out = work_dir / "out"
    data = json.loads((out / "reachability.json").read_text(encoding="utf-8"))
    artifact = FindingsArtifact.model_validate_json((out / "findings.json").read_text("utf-8"))
    graph = GraphArtifact.model_validate_json((out / "graph.json").read_text("utf-8"))
    store, evidence_id, evidence_map = _record_evidence(out, artifact, data)
    artifact.findings = _classify_findings(artifact, graph, data, evidence_map, evidence_id)
    artifact.evidence = store.records()
    _save_findings(out, artifact)
    from guardian.report.render import render

    render(out)


def _record_evidence(
    out: Path, artifact: Any, data: dict[str, Any]
) -> tuple[Any, str, dict[str, list[Any]]]:
    from guardian.evidence import EvidenceStore
    from guardian.models import ReachabilityEvidence

    data = {**data, "status": "complete"}
    evidence_path = out / "raw" / "reachability" / "runtime.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    store = EvidenceStore(out)
    store.record_many(artifact.evidence)
    evidence_id = store.add(
        "guardian-runtime-reachability", "raw/reachability/runtime.json", "/evidence"
    )
    evidence_map: dict[str, list[ReachabilityEvidence]] = {}
    for value in data.get("evidence", []):
        item = ReachabilityEvidence.model_validate(value)
        evidence_map.setdefault(item.package, []).append(item)
    return store, evidence_id, evidence_map


def _classify_findings(
    artifact: Any,
    graph: Any,
    data: dict[str, Any],
    evidence_map: dict[str, list[Any]],
    evidence_id: str,
) -> list[Any]:
    from guardian.adjust import apply_adjustments
    from guardian.confidence import apply_confidence
    from guardian.policy import DEFAULT_POLICY_PATH, load_policy
    from guardian.risk import assess

    nodes = {node.component_id: node for node in graph.nodes}
    policy = load_policy(DEFAULT_POLICY_PATH)
    revised = []
    for finding in artifact.findings:
        component = nodes.get(finding.component_id)
        finding = _merge_evidence(finding, component, data, evidence_map, evidence_id)
        classified = apply_confidence(
            assess(finding, dev=component.dev if component else None, policy=policy),
            policy,
            artifact.agreement,
        )
        revised.append(classified)
    adjusted = apply_adjustments(revised, artifact.risk_adjustments)
    reclassified = [apply_confidence(f, policy, artifact.agreement) for f in adjusted]
    return [_cap_static_confidence(f, policy.review_confidence_threshold) for f in reclassified]


def _merge_evidence(
    finding: Any,
    component: Any,
    data: dict[str, Any],
    evidence_map: dict[str, list[Any]],
    evidence_id: str,
) -> Any:
    from guardian.models import Reachability

    relevance = finding.relevance
    if relevance is None:
        return finding
    match = _component_evidence(component, evidence_map)
    if match is not None:
        source = match.source
        chain = " → ".join(match.chain or [match.package])
        detail = (
            f"loaded at runtime via {chain}" if source == "runtime" else f"imported via {chain}"
        )
        if match.file and source == "static_chain":
            detail += f" at {match.file}"
        if match.observed_during:
            detail += f" during {', '.join(match.observed_during)}"
        next_relevance = _with_reachability(
            relevance, "confirmed", detail, evidence_id, component, source
        )
        return finding.model_copy(update={"relevance": next_relevance})
    if _runtime_ran(data) and relevance.reachability != Reachability.CONFIRMED:
        detail = (
            "package was not observed during the requested tests/app run; "
            "tests do not cover every code path, so this is not proof it is unused"
        )
        next_relevance = _with_reachability(
            relevance, "not_detected", detail, evidence_id, component, "runtime"
        )
        return finding.model_copy(update={"relevance": next_relevance})
    return finding


def _component_evidence(component: Any, evidence_map: dict[str, list[Any]]) -> Any | None:
    if component is None:
        return None
    items = evidence_map.get(component.name, [])
    return next(
        (
            item
            for item in items
            if item.version == component.version
            or component.version == "UNKNOWN"
            or item.version == "UNKNOWN"
        ),
        None,
    )


def _with_reachability(
    relevance: Any, state: str, detail: str, evidence_id: str, component: Any, source: str
) -> Any:
    from guardian.models import Reachability, RelevanceSignal

    signals = [
        s for s in relevance.signals if s.name not in {"reachability", "reachability_source"}
    ]
    signals.append(
        RelevanceSignal(name="reachability", value=state, detail=detail, evidence_ids=[evidence_id])
    )
    signals.append(
        RelevanceSignal(
            name="reachability_source", value=source, detail=detail, evidence_ids=[evidence_id]
        )
    )
    verdict = relevance.verdict
    version_confirmed = any(
        s.name == "version_in_affected_range" and s.value == "confirmed" for s in relevance.signals
    )
    if (
        state == "confirmed"
        and version_confirmed
        and (component is None or component.dev is not True)
    ):
        verdict = "relevant"
    reachability = Reachability.CONFIRMED if state == "confirmed" else Reachability.NOT_DETECTED
    return relevance.model_copy(
        update={
            "reachability": reachability,
            "verdict": verdict,
            "signals": signals,
            "summary": f"{verdict}: {detail}",
        }
    )


def _runtime_ran(data: dict[str, Any]) -> bool:
    return data.get("tests_status") != "not_run" or data.get("app_status") != "not_run"


def _save_findings(out: Path, artifact: Any) -> None:
    temp = out / "findings.json.tmp"
    temp.write_text(artifact.model_dump_json(indent=2) + "\n", encoding="utf-8")
    temp.replace(out / "findings.json")


def _cap_static_confidence(finding: Any, threshold: float) -> Any:
    if not finding.relevance or not any(
        s.name == "reachability_source" and s.value == "static_chain"
        for s in finding.relevance.signals
    ):
        return finding
    score = max(0.0, (finding.confidence_score or 0.0) - 0.10)
    reasons = list(finding.review_reasons)
    required = finding.review_required
    if score < threshold:
        required = True
        reason = "static dependency-chain evidence is less certain than runtime evidence"
        if reason not in reasons:
            reasons.append(reason)
    return finding.model_copy(
        update={"confidence_score": score, "review_required": required, "review_reasons": reasons}
    )
