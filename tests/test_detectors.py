from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from guardian.detectors import DETECTORS
from guardian.detectors.ci_pin import detect as detect_ci_pins
from guardian.detectors.git_diff import detect as detect_git_diff
from guardian.detectors.image_pin import detect as detect_image_pins
from guardian.detectors.install_script import detect as detect_install_scripts
from guardian.detectors.sbom_diff import detect as detect_sbom_diff
from guardian.detectors.typosquat import detect as detect_typosquats
from guardian.evidence import EvidenceStore
from guardian.models import (
    Component,
    CoverageStatus,
    Edge,
    EdgeSource,
    FindingKind,
    GraphArtifact,
)


def _component(name: str, version: str, *, scope: str = "transitive") -> dict[str, str]:
    return {
        "name": name,
        "version": version,
        "purl": f"pkg:npm/{name}@{version}",
        "ecosystem": "npm",
        "scope": scope,
    }


def _as_dict(value: object) -> dict[str, object]:
    return value.model_dump(mode="json")  # type: ignore[attr-defined,no-any-return]


def _result_findings(result: object) -> list[dict[str, object]]:
    findings = result.findings  # type: ignore[attr-defined]
    return [_as_dict(finding) for finding in findings]


def _result_coverage(result: object) -> list[dict[str, object]]:
    return [_as_dict(row) for row in result.coverage]  # type: ignore[attr-defined,no-any-return]


def _finding_details(result: object, finding: dict[str, object]) -> dict[str, object]:
    return result.finding_details[finding["finding_id"]]  # type: ignore[attr-defined,no-any-return]


def test_sbom_diff_reports_added_and_updated_components_only() -> None:
    baseline = {"components": [_component("old", "1.0.0"), _component("keep", "1.0.0")]}
    current = {
        "components": [
            _component("keep", "1.0.0"),
            _component("added", "1.0.0"),
            _component("updated", "2.0.0"),
        ]
    }
    baseline["components"].append(_component("updated", "1.0.0"))

    result = detect_sbom_diff(current, baseline)

    findings = _result_findings(result)
    assert {(f["anomaly_type"], _finding_details(result, f)["name"]) for f in findings} == {
        ("unexpected_dependency", "added"),
        ("dependency_update", "updated"),
    }
    assert all(f["kind"] == "anomaly" and f["evidence_ids"] for f in findings)
    assert _result_coverage(result)[0]["status"] == "finding"


def test_sbom_diff_without_baseline_reports_not_applicable() -> None:
    result = detect_sbom_diff({"components": [_component("x", "1")]}, None)

    assert _result_findings(result) == []
    assert _result_coverage(result)[0]["status"] == "n/a"


def test_sbom_diff_clean_baseline_passes() -> None:
    sbom = {"components": [_component("same", "1.0.0")]}

    result = detect_sbom_diff(sbom, sbom)

    assert _result_findings(result) == []
    assert _result_coverage(result)[0]["status"] == "pass"


def test_git_diff_emits_hash_and_line_range_evidence_for_relevant_files(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "detector@example.test")
    _git(tmp_path, "config", "user.name", "Detector Test")
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies": {"left-pad": "1.0.0"}}\n', encoding="utf-8")
    _git(tmp_path, "add", "package.json")
    _git(tmp_path, "commit", "-m", "baseline")
    baseline = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    manifest.write_text('{"dependencies": {"left-pad": "1.0.0", "evil": "*"}}\n', encoding="utf-8")
    _git(tmp_path, "add", "package.json")
    _git(tmp_path, "commit", "-m", "changed dependency")

    result = detect_git_diff(tmp_path, baseline, ecosystems=["npm"])

    assert _result_findings(result) == []
    evidence = [_as_dict(item) for item in result.evidence]  # type: ignore[attr-defined]
    assert len(evidence) == 1
    assert evidence[0]["file"] == "raw/git-diff/package.json.patch"
    assert "lines:1-1" in evidence[0]["pointer"]
    assert "old_sha256=" in evidence[0]["pointer"]
    assert "new_sha256=" in evidence[0]["pointer"]
    assert "raw/git-diff/package.json.patch" in result.artifacts  # type: ignore[attr-defined]
    assert _result_coverage(result)[0]["status"] == "finding"


def test_git_diff_without_baseline_is_not_applicable(tmp_path: Path) -> None:
    result = detect_git_diff(tmp_path, None, ecosystems=["npm"])

    assert result.evidence == []  # type: ignore[attr-defined]
    assert _result_coverage(result)[0]["status"] == "n/a"


def test_git_diff_clean_repository_passes(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "detector@example.test")
    _git(tmp_path, "config", "user.name", "Detector Test")
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")
    _git(tmp_path, "add", "package.json")
    _git(tmp_path, "commit", "-m", "baseline")
    baseline = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()

    result = detect_git_diff(tmp_path, baseline, ecosystems=["npm"])

    assert result.evidence == []  # type: ignore[attr-defined]
    assert _result_coverage(result)[0]["status"] == "pass"


def test_typosquat_flags_near_name_without_hard_coding_suspect(tmp_path: Path) -> None:
    popular = tmp_path / "popular.txt"
    allowlist = tmp_path / "allowlist.txt"
    popular.write_text("# test snapshot\nngx-cookie\nreact\n", encoding="utf-8")
    allowlist.write_text("# known legitimate names\n", encoding="utf-8")
    sbom = {
        "components": [
            _component("ngy-cookie", "1.0.0", scope="direct"),
            _component("react", "18.0.0", scope="direct"),
            _component("scoped-typo", "1.0.0", scope="transitive"),
            {
                **_component("wrong-cookie", "1.0.0", scope="direct"),
                "name": "@team/ngy-cookie",
                "purl": "pkg:npm/%40team/ngy-cookie@1.0.0",
            },
        ]
    }

    result = detect_typosquats(sbom, popular_path=popular, allowlist_path=allowlist)

    findings = _result_findings(result)
    assert len(findings) == 2
    assert {_finding_details(result, f)["package_name"] for f in findings} == {
        "ngy-cookie",
        "@team/ngy-cookie",
    }
    assert all(f["anomaly_type"] == "suspected_typosquat" for f in findings)
    assert all(
        _finding_details(result, f)["nearest_popular_name"] == "ngx-cookie" for f in findings
    )
    assert all(
        _finding_details(result, f)["distance"] == 1
        and _finding_details(result, f)["threshold"] == 2
        for f in findings
    )


def test_typosquat_respects_allowlist(tmp_path: Path) -> None:
    popular = tmp_path / "popular.txt"
    allowlist = tmp_path / "allowlist.txt"
    popular.write_text("ngx-cookie\n", encoding="utf-8")
    allowlist.write_text("ngy-cookie\n", encoding="utf-8")

    result = detect_typosquats(
        {"components": [_component("ngy-cookie", "1.0.0", scope="direct")]},
        popular_path=popular,
        allowlist_path=allowlist,
    )

    assert _result_findings(result) == []
    assert _result_coverage(result)[0]["status"] == "pass"


def test_install_script_detects_only_new_or_changed_npm_entries(tmp_path: Path) -> None:
    baseline = {"packages": {"node_modules/pkg": {"version": "1.0.0", "hasInstallScript": False}}}
    current = {
        "packages": {
            "node_modules/pkg": {"version": "1.0.0", "hasInstallScript": True},
            "node_modules/new": {"version": "2.0.0", "hasInstallScript": True},
        }
    }
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(current), encoding="utf-8")

    result = detect_install_scripts(path, baseline_lockfile=baseline, ecosystems=["npm"])

    assert {
        _finding_details(result, finding)["package_name"] for finding in _result_findings(result)
    } == {"pkg", "new"}
    assert all(f["anomaly_type"] == "install_script_change" for f in _result_findings(result))
    assert _result_coverage(result)[0]["status"] == "finding"


def test_install_script_marks_non_npm_not_covered() -> None:
    result = detect_install_scripts(None, baseline_lockfile=None, ecosystems=["pypi"])

    assert _result_findings(result) == []
    assert _result_coverage(result)[0]["status"] == "not_covered"


def test_install_script_reports_coverage_separately_per_ecosystem() -> None:
    lockfile = {"packages": {"node_modules/pkg": {"version": "1.0.0", "hasInstallScript": False}}}

    result = detect_install_scripts(
        lockfile,
        baseline_lockfile=lockfile,
        ecosystems=["npm", "pypi"],
    )

    assert {row["ecosystem"]: row["status"] for row in _result_coverage(result)} == {
        "npm": "pass",
        "pypi": "not_covered",
    }


def test_install_script_unchanged_entry_passes(tmp_path: Path) -> None:
    lockfile = {"packages": {"node_modules/pkg": {"version": "1.0.0", "hasInstallScript": True}}}

    result = detect_install_scripts(lockfile, baseline_lockfile=lockfile, ecosystems=["npm"])

    assert _result_findings(result) == []
    assert _result_coverage(result)[0]["status"] == "pass"


def test_image_pin_flags_unpinned_from_and_ignores_digest(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nFROM node:20@sha256:" + "a" * 64 + "\n",
        encoding="utf-8",
    )

    result = detect_image_pins(tmp_path, ecosystems=["npm", "pypi"])

    findings = _result_findings(result)
    assert len(findings) == 1
    assert findings[0]["anomaly_type"] == "unpinned_base_image"
    assert _finding_details(result, findings[0])["image"] == "python:3.11"
    assert _finding_details(result, findings[0])["line"] == 1
    assert len(_result_coverage(result)) == 2


def test_image_pin_digest_only_passes(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM node:20@sha256:" + "a" * 64 + "\n", encoding="utf-8")

    result = detect_image_pins(tmp_path, ecosystems=["npm"])

    assert _result_findings(result) == []
    assert _result_coverage(result)[0]["status"] == "pass"


def test_ci_pin_flags_non_sha_and_ignores_local_and_full_sha(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "steps:\n  - uses: actions/checkout@v4\n"
        + "  - uses: owner/action@"
        + "b" * 40
        + "\n  - uses: ./local\n",
        encoding="utf-8",
    )

    result = detect_ci_pins(tmp_path, ecosystems=["npm"])

    findings = _result_findings(result)
    assert len(findings) == 1
    assert findings[0]["anomaly_type"] == "unpinned_ci_action"
    assert _finding_details(result, findings[0])["action"] == "actions/checkout@v4"
    assert _finding_details(result, findings[0])["line"] == 2


def test_ci_pin_full_sha_only_passes(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("steps:\n  - uses: owner/action@" + "a" * 40 + "\n", encoding="utf-8")

    result = detect_ci_pins(tmp_path, ecosystems=["npm"])

    assert _result_findings(result) == []
    assert _result_coverage(result)[0]["status"] == "pass"


def test_registry_covers_each_detector_for_any_and_npm() -> None:
    expected = {"sbom_diff", "git_diff", "typosquat", "install_script", "image_pin", "ci_pin"}

    assert {plugin.name for plugin in DETECTORS["any"]} >= {
        "sbom_diff",
        "git_diff",
        "image_pin",
        "ci_pin",
    }
    assert {plugin.name for plugin in DETECTORS["npm"]} >= {"typosquat", "install_script"}
    assert {plugin.name for plugins in DETECTORS.values() for plugin in plugins} >= expected


def test_registry_plugin_matches_runner_interface_and_records_evidence(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "package.json").write_text(
        '{\n  "dependencies": {\n    "lodahs": "^1.0.0"\n  }\n}\n', encoding="utf-8"
    )
    out = tmp_path / "run"
    (out / "raw").mkdir(parents=True)
    sbom = {
        "components": [
            {
                "component_id": "pkg:npm/lodahs@1.0.0",
                "purl": "pkg:npm/lodahs@1.0.0",
                "name": "lodahs",
                "version": "1.0.0",
                "ecosystem": "npm",
            }
        ]
    }
    sbom_path = out / "sbom.cdx.json"
    sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
    graph = GraphArtifact(
        nodes=[
            Component(
                component_id="pkg:npm/lodahs@1.0.0",
                purl="pkg:npm/lodahs@1.0.0",
                name="lodahs",
                version="1.0.0",
                ecosystem="npm",
            )
        ]
    )
    context = SimpleNamespace(
        target_path=target,
        sbom=sbom_path,
        baseline=None,
        out=out,
        result=SimpleNamespace(graph=graph),
        evidence=EvidenceStore(out),
    )
    plugin = next(item for item in DETECTORS["npm"] if item.name == "typosquat")

    result = plugin.run(context)

    assert result.findings[0].anomaly_type == "suspected_typosquat"
    assert result.coverage_rows[0].status == "finding"
    records = context.evidence.records()
    assert {record.evidence_id for record in records} >= set(result.findings[0].evidence_ids)
    assert all((out / record.file).is_file() for record in records)


def _write_manifest(
    path: Path, dependencies: dict[str, str], section: str = "dependencies"
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = ",\n".join(f'    "{name}": "{spec}"' for name, spec in dependencies.items())
    path.write_text(
        f'{{\n  "name": "demo",\n  "{section}": {{\n{body}\n  }}\n}}\n', encoding="utf-8"
    )


def _typosquat_inputs(tmp_path: Path) -> tuple[Path, Path]:
    popular = tmp_path / "popular.txt"
    allowlist = tmp_path / "allowlist.txt"
    popular.write_text("# test snapshot\nngx-cookie\nreact\nlodash\n", encoding="utf-8")
    allowlist.write_text("# none\n", encoding="utf-8")
    return popular, allowlist


def test_typosquat_uses_manifests_when_sbom_has_no_scope(tmp_path: Path) -> None:
    popular, allowlist = _typosquat_inputs(tmp_path)
    target = tmp_path / "repo"
    _write_manifest(target / "package.json", {"react": "^18.0.0"})
    _write_manifest(
        target / "frontend" / "package.json",
        {"@angular/core": "^17.0.0", "ngy-cookie": "^6.0.0"},
        section="devDependencies",
    )
    _write_manifest(target / "node_modules" / "evil" / "package.json", {"lodahs": "1.0.0"})
    sbom = {
        "components": [
            {k: v for k, v in _component(n, ver).items() if k != "scope"}
            for n, ver in [("ngy-cookie", "6.0.1"), ("react", "18.2.0"), ("lodahs", "1.0.0")]
        ]
    }

    result = detect_typosquats(
        sbom, target_path=target, popular_path=popular, allowlist_path=allowlist
    )

    findings = _result_findings(result)
    assert [f["purl"] for f in findings] == ["pkg:npm/ngy-cookie@6.0.1"]
    details = _finding_details(result, findings[0])
    assert details["nearest_popular_name"] == "ngx-cookie"
    assert details["distance"] == 1
    assert details["manifest_file"] == "frontend/package.json"
    assert details["manifest_line"] == 5
    record = next(r for r in result.evidence if r.evidence_id in findings[0]["evidence_ids"])
    assert (record.file, record.pointer) == ("frontend/package.json", "lines:5-5")
    assert _result_coverage(result)[0]["status"] == "finding"


def test_typosquat_ignores_transitive_only_and_short_names(tmp_path: Path) -> None:
    popular, allowlist = _typosquat_inputs(tmp_path)
    popular.write_text("ngx-cookie\ncors\n", encoding="utf-8")
    target = tmp_path / "repo"
    _write_manifest(target / "package.json", {"cores": "1.0.0", "@types/ngy-cookie": "1.0.0"})
    sbom = {"components": [_component("ngy-cookie", "1.0.0"), _component("cores", "1.0.0")]}

    result = detect_typosquats(
        sbom, target_path=target, popular_path=popular, allowlist_path=allowlist
    )

    assert _result_findings(result) == []
    assert _result_coverage(result)[0]["status"] == "pass"


def test_typosquat_scoped_short_names_use_suffix_length_for_threshold(tmp_path: Path) -> None:
    popular, allowlist = _typosquat_inputs(tmp_path)
    popular.write_text("@types/ws\n@types/pg\n", encoding="utf-8")
    target = tmp_path / "repo"
    _write_manifest(target / "package.json", {"@types/jws": "1.0.0", "@types/pug": "1.0.0"})

    result = detect_typosquats(
        {"components": []}, target_path=target, popular_path=popular, allowlist_path=allowlist
    )

    assert _result_findings(result) == []


def test_typosquat_checks_scoped_manifest_name_by_suffix(tmp_path: Path) -> None:
    popular, allowlist = _typosquat_inputs(tmp_path)
    target = tmp_path / "repo"
    _write_manifest(target / "package.json", {"@team/ngy-cookie": "1.0.0"})

    result = detect_typosquats(
        {"components": []}, target_path=target, popular_path=popular, allowlist_path=allowlist
    )

    findings = _result_findings(result)
    assert len(findings) == 1
    assert _finding_details(result, findings[0])["package_name"] == "@team/ngy-cookie"
    assert findings[0]["purl"].startswith("pkg:npm/%40team/ngy-cookie")


def test_typosquat_falls_back_to_graph_children_of_root(tmp_path: Path) -> None:
    popular, allowlist = _typosquat_inputs(tmp_path)

    def node(name: str) -> Component:
        return Component(
            component_id=name,
            purl=f"pkg:npm/{name}@1.0.0",
            name=name,
            version="1.0.0",
            ecosystem="npm",
        )

    graph = GraphArtifact(
        nodes=[node("app"), node("ngy-cookie"), node("lodahs")],
        edges=[
            Edge(parent_id="app", child_id="ngy-cookie", edge_source=EdgeSource.SBOM),
            Edge(parent_id="ngy-cookie", child_id="lodahs", edge_source=EdgeSource.SBOM),
        ],
    )
    sbom = {"components": [_component("ngy-cookie", "1.0.0"), _component("lodahs", "1.0.0")]}

    result = detect_typosquats(sbom, graph=graph, popular_path=popular, allowlist_path=allowlist)

    assert [f["purl"] for f in _result_findings(result)] == ["pkg:npm/ngy-cookie@1.0.0"]


def test_typosquat_reports_unparseable_manifest_in_coverage(tmp_path: Path) -> None:
    popular, allowlist = _typosquat_inputs(tmp_path)
    target = tmp_path / "repo"
    target.mkdir()
    (target / "package.json").write_text("{not json", encoding="utf-8")

    result = detect_typosquats(
        {"components": [_component("react", "1.0.0")]},
        target_path=target,
        popular_path=popular,
        allowlist_path=allowlist,
    )

    row = _result_coverage(result)[0]
    assert "package.json" in str(row["reason"])


def test_popular_snapshot_is_sourced_and_not_hand_picked() -> None:
    path = Path(__file__).resolve().parents[1] / "data" / "popular" / "npm.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    header = [line for line in lines if line.startswith("#")]
    names = [line for line in lines if line and not line.startswith("#")]

    assert any("https://registry.npmjs.org/npm-high-impact" in line for line in header)
    assert any("2026-11-23" in line for line in header)
    assert 1000 <= len(names) <= 5000
    assert "ngx-cookie" not in names


def test_image_pin_records_tag_on_finding(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nFROM node\nFROM registry:5000/team/app:latest\n", encoding="utf-8"
    )

    result = detect_image_pins(tmp_path, ecosystems=["npm"])

    tags = {_finding_details(result, f)["image"]: f["image_tag"] for f in _result_findings(result)}
    assert tags == {"python:3.11": "3.11", "node": None, "registry:5000/team/app:latest": "latest"}


def test_finding_and_coverage_use_model_enums(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n", encoding="utf-8")

    result = detect_image_pins(tmp_path, ecosystems=["npm"])

    assert result.findings[0].kind is FindingKind.ANOMALY
    assert result.coverage[0].status is CoverageStatus.FINDING


def test_git_diff_emits_evidence_without_findings(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "T")
    (tmp_path / "package.json").write_text('{"dependencies": {}}\n', encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    base = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1"}}\n', encoding="utf-8")

    result = detect_git_diff(tmp_path, base, ecosystems=["npm"])

    assert result.findings == []
    assert len(result.evidence) == 1


def _git(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    )
