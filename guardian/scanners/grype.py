import subprocess
from pathlib import Path
from typing import Any

from guardian.models import (
    UNKNOWN,
    Evidence,
    Finding,
    FindingKind,
    MatchBasis,
    finding_id,
)

# Filled by scripts/prefetch.sh; auto-update is off so scans work offline during the demo.
GRYPE_DB_VOLUME = "guardian-grype-db"
GRYPE_DB_DIR = "/root/.cache/grype"
GRYPE_IMAGE = (
    "anchore/grype@sha256:661583704a253c0448ed63998b5ea2cd9d5a76ee71eedc4aed439b8ce3e93a1c"
)
STDERR_TAIL_CHARS = 1000


class GrypeError(RuntimeError):
    pass


def _purl(artifact: dict[str, Any]) -> str:
    purl = artifact.get("purl")
    if purl:
        return str(purl)
    kind = artifact.get("type", UNKNOWN)
    return f"pkg:{kind}/{artifact.get('name', UNKNOWN)}@{artifact.get('version', UNKNOWN)}"


def _match_basis(details: list[dict[str, Any]]) -> MatchBasis:
    types = [str(d.get("type", "")) for d in details]
    if any("cpe" in t for t in types):
        return MatchBasis.CPE
    if any(t.startswith("exact") for t in types):
        return MatchBasis.PURL
    return MatchBasis.UNKNOWN


def _evidence_url(vuln: dict[str, Any]) -> str | None:
    if vuln.get("dataSource"):
        return str(vuln["dataSource"])
    urls = vuln.get("urls") or []
    return str(urls[0]) if urls else None


def _best_cvss(vuln: dict[str, Any]) -> tuple[str | None, float | None]:
    entries = [c for c in vuln.get("cvss") or [] if isinstance(c, dict) and c.get("vector")]
    if not entries:
        return None, None
    scored = [(float(c.get("metrics", {}).get("baseScore", 0)), str(c["vector"])) for c in entries]
    score, vector = max(scored, key=lambda item: item[0])
    return vector, score


def _best_epss(vuln: dict[str, Any]) -> dict[str, Any]:
    entries = [e for e in vuln.get("epss") or [] if isinstance(e, dict) and "epss" in e]
    if not entries:
        return {}
    best = max(entries, key=lambda e: float(e["epss"]))
    return {
        "epss": float(best["epss"]),
        "epss_percentile": float(best["percentile"]) if "percentile" in best else None,
        "epss_date": str(best["date"]) if best.get("date") else None,
    }


def _intel(
    vuln: dict[str, Any], base: Evidence, index: int
) -> tuple[dict[str, Any], list[Evidence]]:
    """Exploit and severity intel from one match, each field cited by its own evidence record."""
    vector, score = _best_cvss(vuln)
    fields: dict[str, Any] = {"cvss_vector": vector, "cvss_score": score, **_best_epss(vuln)}
    if isinstance(vuln.get("knownExploited"), list):
        fields["known_exploited"] = bool(vuln["knownExploited"])
    present = {
        "cvss": vector is not None,
        "epss": "epss" in fields,
        "knownExploited": "known_exploited" in fields,
    }
    records = [
        base.model_copy(update={
            "evidence_id": f"ev-grype-{index}-{key}-{base.sha256[:8]}",
            "pointer": f"{base.pointer}/vulnerability/{key}",
        })
        for key, has in present.items() if has
    ]
    return fields, records


def _parse_match(
    match: dict[str, Any], index: int, tool_version: str, raw_file: str, raw_sha256: str
) -> tuple[Finding, list[Evidence]]:
    vuln = match["vulnerability"]
    purl = _purl(match["artifact"])
    advisory_id = str(vuln["id"])
    severity = str(vuln.get("severity") or UNKNOWN)
    aliases = {str(r["id"]) for r in match.get("relatedVulnerabilities", [])} - {advisory_id}
    evidence = Evidence(
        evidence_id=f"ev-grype-{index}-{raw_sha256[:8]}",
        tool="grype",
        tool_version=tool_version,
        file=raw_file,
        pointer=f"/matches/{index}",
        sha256=raw_sha256,
        url=_evidence_url(vuln),
    )
    intel, intel_records = _intel(vuln, evidence, index)
    finding = Finding(
        finding_id=finding_id("grype", purl, advisory_id, []),
        kind=FindingKind.VULNERABILITY,
        component_id=purl,
        purl=purl,
        advisory_id=advisory_id,
        aliases=sorted(aliases),
        confirmed_by=["grype"],
        source_severity=severity,
        severities={"grype": severity},
        fixed_versions=[str(v) for v in vuln.get("fix", {}).get("versions", [])],
        match_basis=_match_basis(match.get("matchDetails", [])),
        evidence_ids=[evidence.evidence_id],
        intel_evidence_ids=[r.evidence_id for r in intel_records],
        **intel,
    )
    return finding, [evidence, *intel_records]


def parse_grype(
    raw: dict[str, Any], raw_file: str, raw_sha256: str
) -> tuple[list[Finding], list[Evidence]]:
    descriptor = raw.get("descriptor", {})
    tool_version = str(descriptor.get("version", UNKNOWN))
    db_built_at = str(descriptor.get("db", {}).get("status", {}).get("built", UNKNOWN))
    pairs = [
        _parse_match(m, i, tool_version, raw_file, raw_sha256)
        for i, m in enumerate(raw.get("matches", []))
    ]
    evidence = [
        e.model_copy(update={"db_built_at": db_built_at}) for _, records in pairs for e in records
    ]
    return [f for f, _ in pairs], evidence


def run_grype(
    sbom_path: Path, out_dir: Path, image: str = GRYPE_IMAGE, timeout_s: int = 600
) -> Path:
    argv = [
        "docker", "run", "--rm", "--network", "host", "--entrypoint", "/grype",
        "-v", f"{sbom_path.resolve().parent}:/in:ro",
        "-v", f"{GRYPE_DB_VOLUME}:{GRYPE_DB_DIR}",
        "-e", f"GRYPE_DB_CACHE_DIR={GRYPE_DB_DIR}",
        "-e", "GRYPE_DB_AUTO_UPDATE=false",
        image, f"sbom:/in/{sbom_path.name}", "-o", "json",
    ]  # fmt: skip
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s, check=False)
    if proc.returncode != 0:
        raise GrypeError(f"grype exited {proc.returncode}: {proc.stderr[-STDERR_TAIL_CHARS:]}")
    out = out_dir / "raw" / "grype.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(proc.stdout)
    return out
