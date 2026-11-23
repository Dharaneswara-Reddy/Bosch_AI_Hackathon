"""Record stable pointers into existing, run-local raw artifacts."""

from datetime import UTC, datetime
from pathlib import Path

from guardian.models import UNKNOWN, Evidence, finding_id


def file_sha256(path: Path) -> str:
    import hashlib

    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class EvidenceStore:
    def __init__(self, run_dir: Path) -> None:
        self.root = run_dir.resolve()
        self._records: dict[str, Evidence] = {}

    def add(
        self, tool: str, file: Path | str, pointer: str, url: str | None = None,
        *, tool_version: str = UNKNOWN, db_built_at: str = UNKNOWN,
    ) -> str:
        path = (self.root / file).resolve()
        relative = path.relative_to(self.root / "raw")
        artifact = (Path("raw") / relative).as_posix()
        sha = file_sha256(path)
        key = finding_id(tool, artifact, pointer, [sha, tool_version, db_built_at, url or ""])
        if key not in self._records:
            self._records[key] = Evidence(
                evidence_id=key, tool=tool, tool_version=tool_version, file=artifact,
                pointer=pointer, sha256=sha, url=url, db_built_at=db_built_at,
                collected_at=datetime.now(UTC),
            )
        return key

    def get(self, evidence_id: str) -> Evidence:
        return self._records[evidence_id].model_copy(deep=True)

    def exists(self, evidence_id: str) -> bool:
        return evidence_id in self._records

    def records(self) -> list[Evidence]:
        return [self.get(key) for key in self._records]
