from pathlib import Path

import pytest

from guardian.evidence import EvidenceStore, file_sha256


def test_evidence_ids_are_stable_and_records_are_add_only(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    file = raw / "scanner.json"
    file.write_text('{"matches": []}', encoding="utf-8")
    store = EvidenceStore(tmp_path)
    first = store.add("grype", file, "/matches")
    assert store.add("grype", "raw/scanner.json", "/matches") == first
    assert store.exists(first)
    record = store.get(first)
    assert record.sha256 == file_sha256(file)
    record.pointer = "/other"
    assert store.get(first).pointer == "/matches"
    file.write_text("{}", encoding="utf-8")
    assert store.add("grype", file, "/matches") != first
    assert len(store.records()) == 2


def test_evidence_rejects_files_outside_raw(tmp_path: Path) -> None:
    file = tmp_path / "outside.json"
    file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        EvidenceStore(tmp_path).add("grype", file, "")


def test_scanner_records_are_verified_as_a_batch(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    file = raw / "scanner.json"
    file.write_text("{}", encoding="utf-8")
    original = EvidenceStore(tmp_path)
    key = original.add("grype", file, "/matches")
    record = original.get(key)
    imported = EvidenceStore(tmp_path)
    corrupt = record.model_copy(update={"evidence_id": "bad", "sha256": "wrong"})
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        imported.record_many([record, corrupt])
    assert imported.records() == []
    imported.record_many([record, record])
    assert imported.get(key) == record
