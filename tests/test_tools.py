import subprocess
from pathlib import Path

import pytest

from guardian.tools import ToolError, run_tool

IMAGE = "anchore/grype:0.122.1@sha256:" + "a" * 64


def test_scanner_records_completed_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(
        command: list[str], *, stdout: object, stderr: int, timeout: int,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 0, stderr=b"")

    monkeypatch.setattr("guardian.tools.subprocess.run", fake_run)
    result = run_tool("grype", ["-o", "json"], {tmp_path: "/input"}, run_dir=tmp_path, image=IMAGE)
    assert ["--entrypoint", "/grype"] == result.command[
        result.command.index("--entrypoint"):result.command.index("--entrypoint") + 2
    ]
    assert "readonly" in next(arg for arg in result.command if "type=bind" in arg)
    assert result.exit_code == 0
    assert len(result.sha256) == 64
    assert (tmp_path / result.file).is_file()


def test_scanner_rejects_unpinned_image(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="digest"):
        run_tool("grype", [], {}, run_dir=tmp_path, image="anchore/grype:latest")


def test_scanner_carries_timeout_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def time_out(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("docker", 1)

    monkeypatch.setattr("guardian.tools.subprocess.run", time_out)
    with pytest.raises(ToolError, match="timed out") as error:
        run_tool("grype", [], {}, 1, run_dir=tmp_path, image=IMAGE)
    assert error.value.run is not None
    assert error.value.run.exit_code == 124
