from pathlib import Path

import pytest

from guardian.policy import DEFAULT_POLICY_PATH, PolicyError, RiskPolicy, load_policy


def test_default_policy_file_matches_documented_defaults() -> None:
    policy = load_policy()
    assert DEFAULT_POLICY_PATH.is_file()
    assert policy == RiskPolicy()
    assert policy.epss_threshold == 0.1
    assert policy.review_confidence_threshold == 0.6


def test_bad_value_fails_fast_with_field_name(tmp_path: Path) -> None:
    bad = tmp_path / "risk.toml"
    bad.write_text("epss_threshold = 3\n", encoding="utf-8")
    with pytest.raises(PolicyError, match=r"epss_threshold"):
        load_policy(bad)


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "risk.toml"
    bad.write_text("epss_treshold = 0.2\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="epss_treshold"):
        load_policy(bad)


def test_missing_file_names_the_path(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="missing.toml"):
        load_policy(tmp_path / "missing.toml")


def test_malformed_toml_is_a_policy_error(tmp_path: Path) -> None:
    bad = tmp_path / "risk.toml"
    bad.write_text("epss_threshold = = 1\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="risk.toml"):
        load_policy(bad)
