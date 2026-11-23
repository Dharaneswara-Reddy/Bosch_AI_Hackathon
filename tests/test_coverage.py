from guardian.coverage import build_coverage
from guardian.models import GraphArtifact


def test_empty_inventory_warns():
    result = build_coverage(GraphArtifact(), [], [])
    assert result.warnings
    assert not result.ecosystems
