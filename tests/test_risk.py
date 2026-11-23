import pytest

from guardian.models import Finding
from guardian.risk import assess


@pytest.mark.parametrize("kind, severity, anomaly, tag, rule, level", [
    ("malicious", "UNKNOWN", "UNKNOWN", None, "R-MAL", "critical"),
    ("vulnerability", "Critical", "UNKNOWN", None, "R-CVE-1", "critical"),
    ("vulnerability", "High", "UNKNOWN", None, "R-CVE-2", "high"),
    ("vulnerability", "Medium", "UNKNOWN", None, "R-CVE-3", "medium"),
    ("vulnerability", "Low", "UNKNOWN", None, "R-CVE-4", "low"),
    ("vulnerability", "UNKNOWN", "UNKNOWN", None, "R-CVE-U", "medium"),
    ("anomaly", "UNKNOWN", "suspected_typosquat", None, "R-AN-1", "high"),
    ("anomaly", "UNKNOWN", "unpinned_base_image", "latest", "R-AN-2", "medium"),
    ("anomaly", "UNKNOWN", "unpinned_base_image", "3", "R-AN-3", "low"),
])
def test_risk_rules(kind, severity, anomaly, tag, rule, level):
    finding = assess(Finding(
        finding_id="x", component_id="lib", purl="pkg:npm/lib@1", kind=kind, source_severity=severity,
        anomaly_type=anomaly, image_tag=tag,
    ))
    assert (finding.risk_rule_id, finding.risk_level) == (rule, level)


def test_dev_and_cpe_modifiers():
    finding = assess(Finding(
        finding_id="x", component_id="lib", purl="pkg:npm/lib@1", kind="vulnerability", severities={"grype": "high", "osv": "low"},
        confirmed_by=["grype", "osv"], match_basis="cpe",
    ), dev=True)
    assert (finding.risk_rule_id, finding.risk_level, finding.confidence) == (
        "R-CVE-2", "medium", "low",
    )
