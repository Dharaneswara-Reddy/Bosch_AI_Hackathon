"""Record stable pointers into existing, run-local raw artifacts."""

from collections.abc import Iterable
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
        path = self._raw_path(file)
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

    def _raw_path(self, file: Path | str) -> Path:
        path = (self.root / file).resolve()
        if not path.is_relative_to(self.root / "raw"):
            raise ValueError("Evidence file must be inside the run's raw directory.")
        return path

    def record_many(self, records: Iterable[Evidence]) -> None:
        """Validate scanner-supplied records before appending them under their IDs."""
        pending: dict[str, Evidence] = {}
        hashes: dict[Path, str] = {}
        for record in records:
            path = self._raw_path(record.file)
            if path not in hashes:
                hashes[path] = file_sha256(path)
            if record.sha256 != hashes[path]:
                raise ValueError(f"Evidence SHA-256 mismatch for {record.file}.")
            canonical = record.model_copy(
                update={"file": path.relative_to(self.root).as_posix()}, deep=True
            )
            existing = pending.get(record.evidence_id) or self._records.get(record.evidence_id)
            if existing is not None and existing != canonical:
                raise ValueError(f"Conflicting evidence ID {record.evidence_id}.")
            pending[record.evidence_id] = canonical
        self._records.update(pending)

    def get(self, evidence_id: str) -> Evidence:
        return self._records[evidence_id].model_copy(deep=True)

    def exists(self, evidence_id: str) -> bool:
        return evidence_id in self._records

    def records(self) -> list[Evidence]:
        return [self.get(key) for key in self._records]
