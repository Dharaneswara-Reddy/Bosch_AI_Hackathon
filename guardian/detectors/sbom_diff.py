"""Compare CycloneDX component purls with a baseline SBOM."""

from __future__ import annotations

from typing import Any

from guardian.detectors._common import (
    DetectionResult,
    components_from,
    coverage_rows,
    ecosystem_list,
    evidence_record,
    finding_payload,
    json_bytes,
    package_identity,
    purl_of,
    read_value,
)
from guardian.models import CoverageStatus


def detect(current_sbom: Any, baseline_sbom: Any | None) -> DetectionResult:
    current = components_from(current_sbom)
    ecosystems = ecosystem_list(current)
    counts = {
        ecosystem: sum(package_identity(item)[0] == ecosystem for item in current)
        for ecosystem in ecosystems
    }
    if baseline_sbom is None:
        return DetectionResult(
            coverage=coverage_rows(
                "sbom_diff", ecosystems, CoverageStatus.NOT_APPLICABLE, "No baseline SBOM", counts
            )
        )

    baseline = components_from(baseline_sbom)
    baseline_purls = {purl_of(item) for item in baseline}
    baseline_identities = {package_identity(item) for item in baseline}
    findings = []
    evidence = []
    finding_details: dict[str, dict[str, Any]] = {}
    for index, component in enumerate(current):
        purl = purl_of(component)
        if purl in baseline_purls:
            continue
        anomaly_type = (
            "dependency_update"
            if package_identity(component) in baseline_identities
            else "unexpected_dependency"
        )
        record = evidence_record(
            "sbom_diff",
            "sbom.cdx.json",
            f"/components/{index}",
            json_bytes(current_sbom),
        )
        evidence.append(record)
        finding, details = finding_payload(
            "sbom_diff",
            component,
            anomaly_type,
            [record.evidence_id],
            baseline_purls=sorted(
                purl_of(item)
                for item in baseline
                if package_identity(item) == package_identity(component)
            ),
            current_purl=purl,
            name=read_value(component, "name", "UNKNOWN"),
            version=read_value(component, "version", "UNKNOWN"),
        )
        findings.append(finding)
        finding_details[finding.finding_id] = details
    status = CoverageStatus.FINDING if findings else CoverageStatus.PASS
    return DetectionResult(
        findings=findings,
        evidence=evidence,
        coverage=coverage_rows("sbom_diff", ecosystems, status, "", counts),
        finding_details=finding_details,
    )
