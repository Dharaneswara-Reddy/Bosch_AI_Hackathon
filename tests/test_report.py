import json

from guardian.report.render import render


def test_report_renders_artifacts_and_escapes_untrusted_text(tmp_path):
    fixtures = {
        "run.json": {
            "scan_id": "test",
            "target": "<script>alert(1)</script>",
            "started_at": "2026-11-23T10:00:00Z",
            "status": "partial",
            "llm_status": "unavailable",
        },
        "graph.json": {
            "nodes": [
                {
                    "component_id": "lib",
                    "purl": "pkg:npm/lib@1",
                    "name": "lib",
                    "version": "1",
                    "ecosystem": "npm",
                    "scope": "transitive",
                }
            ],
        },
        "findings.json": {
            "findings": [
                {
                    "finding_id": "finding",
                    "kind": "vulnerability",
                    "component_id": "lib",
                    "purl": "pkg:npm/lib@1",
                    "advisory_id": "CVE-2000-1234",
                    "dependency_path": ["app", "lib"],
                    "evidence_ids": ["e1"],
                }
            ],
            "evidence": [
                {
                    "evidence_id": "e1",
                    "tool": "fixture",
                    "tool_version": "1",
                    "file": "raw/scanner.json",
                    "pointer": "/matches/0",
                    "sha256": "a" * 64,
                    "collected_at": "2026-11-23T10:00:00Z",
                }
            ],
            "claims": [
                {
                    "claim_id": "claim",
                    "step": "explain",
                    "text": "Unsupported claim.",
                    "kind": "evidence",
                    "validated": False,
                    "rejected_reason": "No evidence",
                }
            ],
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


def _grouping_run(tmp_path):
    def node(cid, name, version):
        return {
            "component_id": cid,
            "purl": f"pkg:gem/{name}@{version}",
            "name": name,
            "version": version,
            "ecosystem": "gem",
        }

    def vuln(fid, cid, advisory, risk):
        return {
            "finding_id": fid,
            "kind": "vulnerability",
            "component_id": cid,
            "purl": f"pkg:gem/{cid}",
            "advisory_id": advisory,
            "risk_level": risk,
            "relevance": {"verdict": "unknown", "summary": "reachability unknown"},
        }

    fixtures = {
        "run.json": {
            "scan_id": "t",
            "target": "repo",
            "started_at": "2026-11-23T10:00:00Z",
            "status": "complete",
            "llm_status": "ok",
        },
        "graph.json": {
            "nodes": [
                node("n1", "nokogiri", "1.19.0"),
                node("n2", "nokogiri", "1.19.0-aarch64-linux-gnu"),
                node("r1", "rack", "3.1.19"),
            ]
        },
        "findings.json": {
            "findings": [
                vuln("f1", "n1", "CVE-2026-0001", "high"),
                vuln("f2", "n2", "CVE-2026-0001", "high"),
                vuln("f3", "r1", "CVE-2026-0002", "low"),
            ],
            "agent_trace": [{"agent": "triage", "produced": ["pack-f1"]}],
        },
        "coverage.json": {"rows": []},
    }
    for name, value in fixtures.items():
        (tmp_path / name).write_text(json.dumps(value), encoding="utf-8")
    render(tmp_path)
    return (tmp_path / "report.html").read_text(encoding="utf-8")


def test_report_groups_platform_builds_of_one_advisory_into_one_row(tmp_path):
    html = _grouping_run(tmp_path)
    assert html.count('class="finding-row"') == 2
    assert "1.19.0, 1.19.0-aarch64-linux-gnu" in html
    assert "3 findings" in html and "2 advisories" in html


def test_report_explains_that_triage_only_selects_findings_for_ai(tmp_path):
    html = _grouping_run(tmp_path)
    assert "All 3 findings are listed" in html
    assert html.count('class="tag ai"') == 1


def test_report_states_unknown_relevance_once_instead_of_on_every_row(tmp_path):
    html = _grouping_run(tmp_path)
    assert "v-unknown" not in html
    assert "Relevance could not be assessed" in html


def test_diff_evidence_is_bounded_to_the_referenced_lines(tmp_path):
    from guardian.report.render import _diff_excerpt

    raw = tmp_path / "changes.patch"
    raw.write_text("hidden before\n-old\n+new\nhidden after\n", encoding="utf-8")
    assert _diff_excerpt(raw, "L2-L3") == "-old\n+new"
    assert _diff_excerpt(raw, "/matches/0") is None
