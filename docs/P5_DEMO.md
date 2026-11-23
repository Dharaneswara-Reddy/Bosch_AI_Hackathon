# Day 1 Guardian demo

## Before the walkthrough

Confirm both target directories and prefetch the team’s pinned scanner images and databases. Run both scans before the judges arrive. Verify that the real reports show the inventory, at least one transitive dependency path, advisory evidence, and honest coverage for both ecosystems. Keep those output folders as a fallback.

## Live walkthrough

1. Open the frozen Juice Shop lockfile. Run `guardian scan targets/juice-shop --out artifacts/juice-clean --no-llm`. Open the generated `report.html`.
2. Show the component count and SBOM link. Pick a finding with a complete dependency path and follow it from the root to the affected package.
3. Expand the advisory card. Highlight the affected version, available fix, individual scanner severities, confirmation sources, evidence pointer and risk-rule ID.
4. Run the team’s suspicious-copy target against the clean artifacts with `--baseline artifacts/juice-clean` and a new output directory. Open the anomaly section and show the detector’s evidence and coverage row.
5. Run `guardian scan targets/railsgoat --out artifacts/railsgoat --no-llm`. Point out the ecosystem and checks that applied.
6. With the P4 validator available, rerun with the team's synthetic claim file using `--inject-claim FILE`. In the rejected claims section, show the validator’s reason.
7. Rerun with `--no-llm`. Show AI status and the findings and evidence that are still present.

## Relevance and malicious-package walkthrough (demo app)

Uses `demo/vulnerable-app`, a local, deliberately vulnerable app (see its README). Nothing is
fetched, installed or run.

1. In the UI choose **Scan the built-in demo app** (or run
   `guardian scan demo/vulnerable-app --out artifacts/demo`).
2. Findings tab: `jsonwebtoken` is ranked first as **relevant**, `lodash` **likely relevant**,
   `minimist` **low relevance**. Click the `jsonwebtoken` row: show the signals (version in the
   affected range, production scope, transitive at depth 2, fix is a major-version change,
   reachability confirmed at `src/server.js:5` via `express-jwt`, exploitation unknown).
3. Click **Show this path in the dependency graph**: the highlighted chain
   `guardian-demo-app → express-jwt → jsonwebtoken`, each edge labelled with its source.
4. Anomalies tab: `expresss-session` flagged as a typosquat of `express-session` and as an
   install script from outside the npm registry, labelled **SYNTHETIC**; plus the unpinned
   `actions/checkout@v4`.
5. AI review tab (with a Groq key): the agent trace from triage to report writer, validated
   explanations of why each finding is or is not relevant, and fix proposals that need human
   approval. Tick the hallucination test to show the fabricated CVE rejected.
6. Open the full report: sections follow the brief, ending with remaining unknowns and limitations.
