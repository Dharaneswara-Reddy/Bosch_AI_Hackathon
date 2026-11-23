# Software Supply Chain Guardian

Guardian inventories dependencies, combines scanner and detector evidence, and produces a static report. It assigns risk using fixed rules and displays the status of optional AI review.

## Setup

Use Python 3.11 or later and Docker for live scanner stages.

```sh
python -m pip install -e '.[dev]'
python -m pytest
python -m scripts.generate_schemas
```

The demo targets in the team plan are Juice Shop (`c9f9922`) and RailsGoat (`f5951f1`). The scanner versions verified by the team are Grype `0.122.1` and OSV-Scanner `2.7.1`.

Copy `.env.example` to `.env` for local settings. Use the exact image tags, digests, and database dates provided by the scanner team's prefetch step. The report records the tool metadata from each run. Leave the AI provider as `none` for an offline demo.

## Run a local scan

```sh
guardian scan targets/juice-shop --out artifacts/juice-shop --no-llm
guardian scan targets/railsgoat --out artifacts/second-target --no-llm
```

Open `report.html` inside each output folder. The same folder contains the JSON artifacts and the Markdown report. Exit codes are 0 for complete, 2 for partial, and 1 for failed. Review the scan header for any missing stages.

## Team integration

Live scans require the P1 inventory and graph modules, P2 scanner modules, and P3 detector registry. AI review and claim injection also require the P4 modules. A missing scan stage is recorded in the report, and available stages keep running.

| Owner | Provides | Consumed by |
| --- | --- | --- |
| P1 | SBOM, components and dependency edges | P2, P3, P5 |
| P2 | Scanner findings and evidence | P4, P5 |
| P3 | Anomaly findings, evidence and coverage rows | P4, P5 |
| P4 | AI claims, validation status and rejection reasons | P5 |
| P5 | Shared models, schemas, runner, risk policy, coverage and reports | All |

See [the demo walkthrough](docs/P5_DEMO.md) for the live sequence.
