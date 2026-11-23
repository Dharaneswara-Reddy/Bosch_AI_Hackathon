from pathlib import Path

from guardian.resolve import resolve_target
from guardian.resolve.edges import EDGE_PARSERS, parse_gemfile_lock

GEMFILE_LOCK = """\
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.2.0)
      rack (>= 2.2)
      rack-session (>= 1.0)
      ghost (>= 1)
    ffi (1.17.3)
    ffi (1.17.3-x86_64-linux-gnu)
    nokogiri (1.19.0)
      racc (~> 1.4)
    racc (1.8.1)
    rack (3.1.19)
    rack-session (2.1.1)
      rack (>= 3.0)
    rspec-rails (8.0.2)
      actionpack (>= 7.2)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  ffi
  nokogiri (~> 1.19)
  rspec-rails!

BUNDLED WITH
   2.5.0
"""


def _parse(tmp_path: Path) -> tuple[set[tuple[str, str]], list[str]]:
    lock = tmp_path / "Gemfile.lock"
    lock.write_text(GEMFILE_LOCK, encoding="utf-8")
    parsed = parse_gemfile_lock(lock)
    return set(parsed.edges), parsed.direct


def test_nested_children_map_to_resolved_versions(tmp_path: Path) -> None:
    edges, _ = _parse(tmp_path)
    assert ("pkg:gem/actionpack@7.2.0", "pkg:gem/rack@3.1.19") in edges
    assert ("pkg:gem/rack-session@2.1.1", "pkg:gem/rack@3.1.19") in edges
    assert ("pkg:gem/nokogiri@1.19.0", "pkg:gem/racc@1.8.1") in edges


def test_missing_child_version_is_skipped(tmp_path: Path) -> None:
    edges, _ = _parse(tmp_path)
    assert not any("ghost" in child for _, child in edges)


def test_direct_deps_cover_platform_variants(tmp_path: Path) -> None:
    _, direct = _parse(tmp_path)
    assert sorted(direct) == [
        "pkg:gem/ffi@1.17.3", "pkg:gem/ffi@1.17.3-x86_64-linux-gnu",
        "pkg:gem/nokogiri@1.19.0", "pkg:gem/rspec-rails@8.0.2",
    ]


def test_platform_sections_are_not_gems(tmp_path: Path) -> None:
    edges, direct = _parse(tmp_path)
    flat = {purl for pair in edges for purl in pair} | set(direct)
    assert not any("x86_64-linux@" in purl or "pkg:gem/ruby" in purl for purl in flat)


def test_children_link_to_every_platform_variant(tmp_path: Path) -> None:
    lock = tmp_path / "Gemfile.lock"
    lock.write_text(
        "GEM\n  specs:\n    a (1.0)\n      ffi (>= 1)\n    ffi (2.0)\n"
        "    ffi (2.0-arm64-darwin)\n\nDEPENDENCIES\n  a\n", encoding="utf-8")
    edges = set(parse_gemfile_lock(lock).edges)
    assert edges == {("pkg:gem/a@1.0", "pkg:gem/ffi@2.0"),
                     ("pkg:gem/a@1.0", "pkg:gem/ffi@2.0-arm64-darwin")}


def test_registry_and_resolve_target_carry_edges(tmp_path: Path) -> None:
    assert EDGE_PARSERS["Gemfile.lock"] is parse_gemfile_lock
    (tmp_path / "Gemfile.lock").write_text(GEMFILE_LOCK, encoding="utf-8")
    (tmp_path / "yarn.lock").write_text("", encoding="utf-8")
    result = resolve_target(tmp_path, tmp_path / "work")
    assert [item.lockfile.name for item in result.lockfile_edges] == ["Gemfile.lock"]
    assert result.lockfile_edges[0].edges
