import subprocess
from pathlib import Path

import pytest

from guardian.resolve.edges import LockfileEdges
from guardian.sbom import SYFT_IMAGE, build_sbom, merge_resolver_edges
from guardian.tools import ToolError

Commands = list[list[str]]


def _fake_syft(commands: Commands, code: int = 0) -> object:
    def fake_run(
        command: list[str], *, stdout: object, stderr: int, timeout: int,
    ) -> subprocess.CompletedProcess[bytes]:
        commands.append(command)
        if code == 0:
            stdout.write(b'{"bomFormat": "CycloneDX"}')  # type: ignore[attr-defined]
        return subprocess.CompletedProcess(command, code, stderr=b"boom: no such file")

    return fake_run


def test_directory_scan_mounts_target_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: Commands = []
    monkeypatch.setattr("guardian.tools.subprocess.run", _fake_syft(commands))
    sbom = build_sbom(tmp_path, None)
    command = commands[0]
    assert sbom.name.endswith(".cdx.json")
    assert sbom.read_text(encoding="utf-8") == '{"bomFormat": "CycloneDX"}'
    assert SYFT_IMAGE in command
    assert "--network=host" in command
    assert any("readonly" in arg and f"source={tmp_path.resolve()}" in arg for arg in command)
    assert command[command.index(SYFT_IMAGE) + 1:] == [
        "dir:/input", "-o", "cyclonedx-json", "-q",
    ]


def test_image_reference_is_scanned_without_mounts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: Commands = []
    monkeypatch.setattr("guardian.tools.subprocess.run", _fake_syft(commands))
    build_sbom("alpine@sha256:" + "b" * 64, None)
    command = commands[0]
    assert "--mount" not in command
    assert command[command.index(SYFT_IMAGE) + 1] == "alpine@sha256:" + "b" * 64


def test_failure_surfaces_stderr_tail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("guardian.tools.subprocess.run", _fake_syft([], code=2))
    with pytest.raises(ToolError, match="no such file"):
        build_sbom(tmp_path, None)


def _bom() -> dict[str, object]:
    def comp(name: str, version: str) -> dict[str, object]:
        purl = f"pkg:gem/{name}@{version}"
        return {"bom-ref": f"{purl}?package-id=x{name}", "type": "library", "name": name,
                "version": version, "purl": purl}

    return {
        "components": [comp("a", "1.0"), comp("b", "2.0"), comp("c", "3.0")],
        "dependencies": [{"ref": "pkg:gem/a@1.0?package-id=xa",
                          "dependsOn": ["pkg:gem/b@2.0?package-id=xb"]}],
    }


def _edges(tmp_path: Path) -> LockfileEdges:
    return LockfileEdges(
        lockfile=tmp_path / "app" / "Gemfile.lock",
        edges=[("pkg:gem/a@1.0", "pkg:gem/b@2.0"), ("pkg:gem/b@2.0", "pkg:gem/c@3.0"),
               ("pkg:gem/b@2.0", "pkg:gem/zzz@9"), ("pkg:gem/nope@1", "pkg:gem/c@3.0")],
        direct=["pkg:gem/a@1.0", "pkg:gem/missing@1"],
    )


def test_merge_adds_edges_root_and_counts_skips(tmp_path: Path) -> None:
    bom = merge_resolver_edges(_bom(), [_edges(tmp_path)], tmp_path)
    deps = {entry["ref"]: entry["dependsOn"] for entry in bom["dependencies"]}
    assert deps["pkg:gem/a@1.0?package-id=xa"] == ["pkg:gem/b@2.0?package-id=xb"]
    assert deps["pkg:gem/b@2.0?package-id=xb"] == ["pkg:gem/c@3.0?package-id=xc"]
    root = "guardian:root:app/Gemfile.lock"
    assert deps[root] == ["pkg:gem/a@1.0?package-id=xa"]
    props = {item["name"]: item["value"] for item in bom["properties"]}
    assert props["guardian:resolver-edges-skipped"] == "3"
    assert "pkg:gem/b@2.0?package-id=xb pkg:gem/c@3.0?package-id=xc" in props.values()
    assert "pkg:gem/a@1.0?package-id=xa pkg:gem/b@2.0?package-id=xb" not in props.values()


def test_synthetic_root_is_marked(tmp_path: Path) -> None:
    bom = merge_resolver_edges(_bom(), [_edges(tmp_path)], tmp_path)
    root = next(c for c in bom["components"] if c["bom-ref"].startswith("guardian:root:"))
    assert root["type"] == "application"
    assert {"name": "guardian:synthetic", "value": "true"} in root["properties"]
    assert {"name": "syft:location:0:path", "value": "/app/Gemfile.lock"} in root["properties"]


def test_merge_without_edges_leaves_bom_untouched(tmp_path: Path) -> None:
    assert merge_resolver_edges(_bom(), [], tmp_path) == _bom()
