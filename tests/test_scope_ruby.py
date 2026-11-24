from pathlib import Path

from guardian.analysis import apply_scope
from guardian.models import (
    Component,
    Edge,
    EdgeSource,
    GraphArtifact,
    RunResult,
    Scan,
)
from guardian.scope import gemfile_groups

GEMFILE = """\
source 'https://rubygems.org'
ruby '3.2.0'

gem 'rails', '~> 8.0'
gem "pg"
gem 'pry', group: :development
gem 'dotenv', :groups => [:development, :test]
gem 'mixed', group: :test
gem 'rspec-core', groups: %i[test]

group :development, :test do
  gem 'rspec-rails'
  gem "byebug", platforms: [:mri]
  source 'https://gems.example.com' do
    gem 'private-dev'
  end
end

group :production do
  gem 'puma'
end

gem 'mixed'

platforms :jruby do
  gem 'jdbc-pg'
end
"""


def test_gems_directly_in_dev_or_test_groups_are_dev_others_production(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text(GEMFILE, encoding="utf-8")
    groups = gemfile_groups(tmp_path)
    assert groups.dev == {"pry", "dotenv", "rspec-core", "rspec-rails", "byebug", "private-dev"}
    assert groups.prod == {"rails", "pg", "puma", "mixed", "jdbc-pg"}


def test_no_gemfile_means_no_groups(tmp_path: Path) -> None:
    groups = gemfile_groups(tmp_path)
    assert not groups.dev and not groups.prod


def _gem(name: str) -> Component:
    purl = f"pkg:gem/{name}@1.0"
    return Component(component_id=purl, purl=purl, name=name, version="1.0", ecosystem="gem")


def _graph(edges: list[tuple[str, str]], names: list[str]) -> GraphArtifact:
    nodes = [_gem(n) for n in names]
    ids = {n: f"pkg:gem/{n}@1.0" for n in names}
    return GraphArtifact(nodes=nodes, edges=[
        Edge(parent_id=ids.get(p, p), child_id=ids[c], edge_source=EdgeSource.SBOM)
        for p, c in edges
    ])


def test_transitive_gem_is_dev_only_when_every_path_goes_through_dev_gems(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text(
        "gem 'rails'\ngroup :development do\n  gem 'pry'\nend\n", encoding="utf-8"
    )
    graph = _graph(
        [("app", "rails"), ("app", "pry"), ("rails", "rack"), ("pry", "coderay"),
         ("pry", "rack"), ("rails", "shared")],
        ["rails", "pry", "rack", "coderay", "shared"],
    )
    result = RunResult(scan=Scan(scan_id="s", target="t", started_at="2026-01-01T00:00:00Z"),
                       graph=graph)
    apply_scope(result, tmp_path, ["app"])
    dev = {n.name: n.dev for n in result.graph.nodes}
    assert dev == {"rails": False, "pry": True, "rack": False, "coderay": True, "shared": False}


def test_gem_with_production_path_and_dev_listing_stays_production(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text(
        "gem 'rails'\ngroup :test do\n  gem 'rack'\nend\n", encoding="utf-8"
    )
    graph = _graph([("app", "rails"), ("app", "rack"), ("rails", "rack")], ["rails", "rack"])
    result = RunResult(scan=Scan(scan_id="s", target="t", started_at="2026-01-01T00:00:00Z"),
                       graph=graph)
    apply_scope(result, tmp_path, ["app"])
    assert {n.name: n.dev for n in result.graph.nodes}["rack"] is False
