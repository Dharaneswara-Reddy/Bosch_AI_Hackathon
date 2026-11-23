"""Regenerate the committed JSON schemas with python -m scripts.generate_schemas."""

import json
from pathlib import Path

from guardian.models import CoverageArtifact, FindingsArtifact, GraphArtifact, Scan


def main() -> None:
    destination = Path("schemas")
    destination.mkdir(exist_ok=True)
    for name, model in {
        "coverage": CoverageArtifact,
        "findings": FindingsArtifact,
        "graph": GraphArtifact,
        "run": Scan,
    }.items():
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        (destination / f"{name}.schema.json").write_text(
            json.dumps(schema, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
