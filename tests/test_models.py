import pytest
from pydantic import ValidationError

from guardian.models import Edge, Finding, finding_id


def test_contract_and_identity():
    with pytest.raises(ValidationError):
        Edge(parent_id="app", child_id="lib", edge_source="guessed")
    identity = finding_id("grype", "pkg:npm/lib@1", "CVE-2000-1234", ["app", "lib"])
    assert len(identity) == 64
    assert identity != finding_id("grype", "pkg:npm/lib@1", "CVE-2000-1234", ["lib"])
    assert Finding(finding_id=identity, kind="vulnerability").risk_level == "UNKNOWN"
