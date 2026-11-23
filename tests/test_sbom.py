import subprocess
from pathlib import Path

import pytest

from guardian.sbom import SYFT_IMAGE, build_sbom
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
