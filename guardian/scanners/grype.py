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


def _parse_match(
    match: dict[str, Any], index: int, tool_version: str, raw_file: str, raw_sha256: str
) -> tuple[Finding, Evidence]:
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
    )
    return finding, evidence


def parse_grype(
    raw: dict[str, Any], raw_file: str, raw_sha256: str
) -> tuple[list[Finding], list[Evidence]]:
    tool_version = str(raw.get("descriptor", {}).get("version", UNKNOWN))
    pairs = [
        _parse_match(m, i, tool_version, raw_file, raw_sha256)
        for i, m in enumerate(raw.get("matches", []))
    ]
    return [f for f, _ in pairs], [e for _, e in pairs]


def run_grype(
    sbom_path: Path, out_dir: Path, image: str = GRYPE_IMAGE, timeout_s: int = 600
) -> Path:
    argv = [
        "docker", "run", "--rm", "--network", "host", "--entrypoint", "/grype",
        "-v", f"{sbom_path.resolve().parent}:/in:ro",
        image, f"sbom:/in/{sbom_path.name}", "-o", "json",
    ]  # fmt: skip
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s, check=False)
    if proc.returncode != 0:
        raise GrypeError(f"grype exited {proc.returncode}: {proc.stderr[-STDERR_TAIL_CHARS:]}")
    out = out_dir / "raw" / "grype.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(proc.stdout)
    return out
