"""OSV-Scanner adapter: runs the scanner on an SBOM and maps its JSON to findings."""

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

OSV_IMAGE = (
    "ghcr.io/google/osv-scanner@sha256:"
    "a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde"
)

PURL_TYPES = {
    "RubyGems": "gem",
    "npm": "npm",
    "PyPI": "pypi",
    "Maven": "maven",
    "Go": "golang",
    "crates.io": "cargo",
    "NuGet": "nuget",
    "Packagist": "composer",
}
DB_SEVERITY = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}
TAIL_CHARS = 2000


class OsvError(Exception):
    pass


def _purl(pkg: dict[str, Any]) -> str:
    if pkg.get("purl"):
        return str(pkg["purl"])
    eco = str(pkg.get("ecosystem", UNKNOWN))
    return f"pkg:{PURL_TYPES.get(eco, eco.lower())}/{pkg['name']}@{pkg.get('version', UNKNOWN)}"


def _label(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW" if score > 0 else UNKNOWN


def _severity(vuln: dict[str, Any], groups: list[dict[str, Any]]) -> str:
    vid = vuln["id"]
    for g in groups:
        if vid in g.get("ids", []) and g.get("max_severity"):
            try:
                label = _label(float(g["max_severity"]))
            except ValueError:
                continue
            if label != UNKNOWN:
                return label
    db = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    return DB_SEVERITY.get(db, UNKNOWN)


def _fixed_versions(vuln: dict[str, Any], name: str) -> list[str]:
    fixed: list[str] = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name") != name:
            continue
        for rng in aff.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event and event["fixed"] not in fixed:
                    fixed.append(event["fixed"])
    return fixed


def _convert(
    vuln: dict[str, Any],
    pkg_entry: dict[str, Any],
    pointer: str,
    ev_id: str,
    raw_file: str,
    raw_sha256: str,
    tool_version: str,
) -> tuple[Finding, Evidence]:
    pkg = pkg_entry["package"]
    purl = _purl(pkg)
    vid = str(vuln["id"])
    severity = _severity(vuln, pkg_entry.get("groups", []))
    evidence = Evidence(
        evidence_id=ev_id,
        tool="osv-scanner",
        tool_version=tool_version,
        file=raw_file,
        pointer=pointer,
        sha256=raw_sha256,
        url=f"https://osv.dev/vulnerability/{vid}",
    )
    finding = Finding(
        finding_id=finding_id("osv", purl, vid, []),
        kind=FindingKind.MALICIOUS if vid.startswith("MAL-") else FindingKind.VULNERABILITY,
        component_id=purl,
        purl=purl,
        advisory_id=vid,
        aliases=sorted(set(vuln.get("aliases", [])) - {vid}),
        confirmed_by=["osv"],
        source_severity=severity,
        severities={"osv": severity},
        fixed_versions=_fixed_versions(vuln, str(pkg["name"])),
        match_basis=MatchBasis.PURL,
        evidence_ids=[ev_id],
    )
    return finding, evidence


def parse_osv(
    raw: dict[str, Any], raw_file: str, raw_sha256: str, tool_version: str
) -> tuple[list[Finding], list[Evidence]]:
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    packages = 0
    for r, result in enumerate(raw.get("results", [])):
        for p, entry in enumerate(result.get("packages", [])):
            packages += 1
            for v, vuln in enumerate(entry.get("vulnerabilities", [])):
                pointer = f"/results/{r}/packages/{p}/vulnerabilities/{v}"
                ev_id = f"ev-osv-{r}-{p}-{v}-{raw_sha256[:8]}"
                f, e = _convert(vuln, entry, pointer, ev_id, raw_file, raw_sha256, tool_version)
                findings.append(f)
                evidence.append(e)
    if packages == 0:
        raise OsvError("no packages scanned")
    return findings, evidence


def run_osv(sbom_path: Path, out_dir: Path, image: str = OSV_IMAGE, timeout_s: int = 600) -> Path:
    argv = [
        "docker", "run", "--rm", "--network", "host",
        "-v", f"{sbom_path.parent}:/in:ro",
        image, "scan", "source", "--format", "json", "-L", f"/in/{sbom_path.name}",
    ]  # fmt: skip
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s, check=False)
    if proc.returncode not in (0, 1):
        raise OsvError(f"osv-scanner exited {proc.returncode}: {proc.stderr[-TAIL_CHARS:]}")
    out = out_dir / "raw" / "osv.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(proc.stdout)
    return out
