import json

from guardian.report.render import render


def test_report_renders_artifacts_and_escapes_untrusted_text(tmp_path):
    fixtures = {
        "run.json": {
            "scan_id": "test", "target": "<script>alert(1)</script>",
            "started_at": "2026-11-23T10:00:00Z",
            "status": "partial", "llm_status": "unavailable",
        },
        "graph.json": {
            "nodes": [{"component_id": "lib", "purl": "pkg:npm/lib@1", "name": "lib",
                       "version": "1", "ecosystem": "npm", "scope": "transitive"}],
        },
        "findings.json": {
            "findings": [{"finding_id": "finding", "kind": "vulnerability",
                          "component_id": "lib", "purl": "pkg:npm/lib@1",
                          "advisory_id": "CVE-2000-1234", "dependency_path": ["app", "lib"],
                          "evidence_ids": ["e1"]}],
            "evidence": [{"evidence_id": "e1", "tool": "fixture", "tool_version": "1",
                          "file": "raw/scanner.json", "pointer": "/matches/0",
                          "sha256": "a" * 64, "collected_at": "2026-11-23T10:00:00Z"}],
            "claims": [{"claim_id": "claim", "step": "explain", "text": "Unsupported claim.",
                        "kind": "evidence", "validated": False, "rejected_reason": "No evidence"}],
        },
        "coverage.json": {"rows": [], "warnings": ["Inventory is partial."]},
    }
    for name, value in fixtures.items():
        (tmp_path / name).write_text(json.dumps(value), encoding="utf-8")
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw/scanner.json").write_text("{}", encoding="utf-8")

    render(tmp_path)

    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    markdown = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "<script>" not in html
    assert "<script>" not in markdown
    for report in (html, markdown):
        assert "CVE-2000-1234" in report
        assert "No evidence" in report
        assert "partial" in report
        assert "unavailable" in report
        assert "raw/scanner.json" in report

def test_diff_evidence_is_bounded_to_the_referenced_lines(tmp_path):
    from guardian.report.render import _diff_excerpt

    raw = tmp_path / "changes.patch"
    raw.write_text("hidden before\n-old\n+new\nhidden after\n", encoding="utf-8")
    assert _diff_excerpt(raw, "L2-L3") == "-old\n+new"
    assert _diff_excerpt(raw, "/matches/0") is None
