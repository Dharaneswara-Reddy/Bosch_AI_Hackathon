from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from guardian.analysis import REACHABILITY_FILE, apply_relevance, apply_scope
from guardian.evidence import EvidenceStore
from guardian.models import (
    Component,
    Edge,
    EdgeSource,
    Finding,
    FindingKind,
    GraphArtifact,
    MatchBasis,
    Reachability,
    RelevanceVerdict,
    RunResult,
    Scan,
    Scope,
)
from guardian.reachability import scan_imports
from guardian.relevance import AdvisoryDetails, PathFacts, assess, path_facts, rank
from guardian.scope import npm_dev_flags

DEMO = Path(__file__).resolve().parents[1] / "demo" / "vulnerable-app"
APP = "app"


def _node(name: str, version: str) -> Component:
    purl = f"pkg:npm/{name}@{version}"
    return Component(component_id=purl, purl=purl, name=name, version=version, ecosystem="npm")


def _demo_graph() -> GraphArtifact:
    app = Component(
        component_id=APP,
        purl="pkg:npm/guardian-demo-app@1.0.0",
        name="guardian-demo-app",
        version="1.0.0",
        ecosystem="npm",
    )
    nodes = [
        app,
        _node("express-jwt", "0.1.3"),
        _node("jsonwebtoken", "0.1.0"),
        _node("lodash", "4.17.4"),
        _node("minimist", "0.0.8"),
    ]
    pairs = [(APP, nodes[1]), (nodes[1].component_id, nodes[2]), (APP, nodes[3]), (APP, nodes[4])]
    edges = [
        Edge(parent_id=p, child_id=c.component_id, edge_source=EdgeSource.RESOLVER)
        for p, c in pairs
    ]
    return GraphArtifact(nodes=nodes, edges=edges)


def _vuln(name: str, version: str, path: list[str], fixed: list[str]) -> Finding:
    purl = f"pkg:npm/{name}@{version}"
    return Finding(
        finding_id=f"f-{name}",
        kind=FindingKind.VULNERABILITY,
        component_id=purl,
        purl=purl,
        advisory_id=f"GHSA-{name}",
        match_basis=MatchBasis.PURL,
        confirmed_by=["grype"],
        fixed_versions=fixed,
        dependency_path=path,
        path_count=1,
        evidence_ids=[],
    )


def _demo_run(tmp_path: Path) -> tuple[RunResult, Path, EvidenceStore]:
    target = tmp_path / "app"
    shutil.copytree(DEMO, target)
    (target / "src" / "stats.js").unlink()
    out = tmp_path / "out"
    (out / "raw").mkdir(parents=True)
    jwt, lodash, mini = (
        f"pkg:npm/{n}" for n in ("jsonwebtoken@0.1.0", "lodash@4.17.4", "minimist@0.0.8")
    )
    findings = [
        _vuln("minimist", "0.0.8", [APP, mini], ["0.2.1"]),
        _vuln("lodash", "4.17.4", [APP, lodash], ["4.17.21"]),
        _vuln("jsonwebtoken", "0.1.0", [APP, "pkg:npm/express-jwt@0.1.3", jwt], ["4.2.2"]),
    ]
    result = RunResult(
        scan=Scan(scan_id="s", target="t", started_at="2026-11-23T00:00:00Z"),
        graph=_demo_graph(),
        findings=findings,
    )
    return result, target, EvidenceStore(out)


def test_npm_dev_flags_from_demo_lockfile() -> None:
    flags = npm_dev_flags(DEMO)
    assert flags[("minimist", "0.0.8")] is True
    assert flags[("lodash", "4.17.4")] is False


def test_apply_scope_marks_direct_transitive_and_dev(tmp_path: Path) -> None:
    result, target, _ = _demo_run(tmp_path)
    apply_scope(result, target, [APP])
    nodes = {n.name: n for n in result.graph.nodes}
    assert nodes["express-jwt"].scope == Scope.DIRECT
    assert nodes["jsonwebtoken"].scope == Scope.TRANSITIVE
    assert nodes["minimist"].dev is True and nodes["lodash"].dev is False


def test_reachability_finds_imports_and_skips_vendor() -> None:
    scan = scan_imports(DEMO, {"express-jwt", "lodash", "expresss-session"})
    assert scan.source_available
    assert [(h.file, h.line) for h in scan.hits["express-jwt"]] == [("src/server.js", 5)]
    assert [(h.file, h.line) for h in scan.hits["lodash"]] == [("src/stats.js", 1)]
    assert "expresss-session" not in scan.hits


def test_reachability_patterns(tmp_path: Path) -> None:
    (tmp_path / "a.mjs").write_text("import jwt from 'jsonwebtoken/sign';\nimport('lodash')\n")
    (tmp_path / "b.rb").write_text("require 'rack'\n")
    (tmp_path / "c.py").write_text("from py_yaml import load\n")
    scan = scan_imports(tmp_path, {"jsonwebtoken", "lodash", "rack", "py-yaml", "debug"})
    assert set(scan.hits) == {"jsonwebtoken", "lodash", "rack", "py-yaml"}


def test_demo_relevance_ranks_reachable_above_unused_and_dev(tmp_path: Path) -> None:
    result, target, store = _demo_run(tmp_path)
    apply_scope(result, target, [APP])
    apply_relevance(result, target, store.root, store)
    verdicts = {f.finding_id: f.relevance.verdict for f in result.findings if f.relevance}
    assert verdicts == {
        "f-jsonwebtoken": RelevanceVerdict.RELEVANT,
        "f-lodash": RelevanceVerdict.LIKELY_RELEVANT,
        "f-minimist": RelevanceVerdict.LOW_RELEVANCE,
    }
    ordered = [f.finding_id for f in sorted(result.findings, key=rank)]
    assert ordered == ["f-jsonwebtoken", "f-lodash", "f-minimist"]
    jwt = next(f for f in result.findings if f.finding_id == "f-jsonwebtoken")
    assert jwt.relevance is not None
    assert jwt.relevance.introduced_by == "express-jwt"
    assert jwt.relevance.reachability == Reachability.CONFIRMED
    reach = next(s for s in jwt.relevance.signals if s.name == "reachability")
    assert "src/server.js:5" in reach.detail and "via express-jwt" in reach.detail
    assert reach.evidence_ids and store.exists(reach.evidence_ids[0])
    hits = json.loads((store.root / REACHABILITY_FILE).read_text())
    assert hits["hits"]["express-jwt"][0]["line"] == 5


def _facts(dev: bool | None, path: list[str]) -> PathFacts:
    component = _node("pkg", "1.0.0").model_copy(update={"dev": dev})
    return path_facts(_vuln("pkg", "1.0.0", path, ["2.0.0"]), {component.component_id: component})


@pytest.mark.parametrize(
    ("basis", "dev", "kev", "expected"),
    [
        (MatchBasis.CPE, False, None, RelevanceVerdict.UNKNOWN),
        (MatchBasis.PURL, True, True, RelevanceVerdict.RELEVANT),
        (MatchBasis.PURL, True, None, RelevanceVerdict.LOW_RELEVANCE),
        (MatchBasis.PURL, False, None, RelevanceVerdict.LIKELY_RELEVANT),
        (MatchBasis.PURL, None, None, RelevanceVerdict.UNKNOWN),
    ],
)
def test_verdict_rules(
    basis: MatchBasis, dev: bool | None, kev: bool | None, expected: RelevanceVerdict
) -> None:
    finding = _vuln("pkg", "1.0.0", [APP, "pkg:npm/pkg@1.0.0"], ["2.0.0"]).model_copy(
        update={"match_basis": basis}
    )
    relevance = assess(
        finding,
        _facts(dev, finding.dependency_path),
        AdvisoryDetails(known_exploited=kev),
        None,
        {},
    )
    assert relevance.verdict == expected
    assert relevance.reachability == Reachability.UNKNOWN
    assert "safe" not in relevance.summary


def test_malicious_is_always_relevant_and_missing_data_is_unknown() -> None:
    finding = _vuln("pkg", "1.0.0", [], []).model_copy(
        update={"kind": FindingKind.MALICIOUS, "match_basis": MatchBasis.UNKNOWN}
    )
    relevance = assess(finding, PathFacts(), AdvisoryDetails(), None, {})
    assert relevance.verdict == RelevanceVerdict.RELEVANT
    signals = {s.name: s.value for s in relevance.signals}
    assert signals["position"] == "unknown" and signals["known_exploited"] == "unknown"
    assert signals["fix_available"] == "no"


def test_grype_affected_range_and_exploit_data_are_read(tmp_path: Path) -> None:
    from guardian.relevance import advisory_details

    raw = tmp_path / "raw"
    raw.mkdir()
    match = {
        "matchDetails": [{"found": {"versionConstraint": "<4.2.2 (semver)"}}],
        "vulnerability": {"knownExploited": [{"cve": "CVE-1"}], "epss": [{"epss": 0.9}]},
    }
    (raw / "grype.json").write_text(json.dumps({"matches": [match]}))
    store = EvidenceStore(tmp_path)
    evidence_id = store.add("grype", "raw/grype.json", "/matches/0")
    finding = _vuln("pkg", "1.0.0", [], []).model_copy(update={"evidence_ids": [evidence_id]})
    details = advisory_details(finding, {evidence_id: store.get(evidence_id)}, tmp_path, {})
    assert details.affected_range == "<4.2.2 (semver)"
    assert details.known_exploited is True and details.epss == 0.9
