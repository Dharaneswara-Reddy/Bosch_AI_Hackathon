# Software Supply Chain Guardian (merged plan, v2)

* **Author:** GojoV339
* **Date:** 2026-11-23

Inputs: [problem statement transcript](docs/00-problem-statement.md) · [tool research](docs/01-research.md) · six-lens Goldfish review · the team's technical plan PDF (`Bosch_Supply_Chain_Guardian_TechnicalPlan.pdf`). This version merges the best parts of our plan and the PDF.

## Overview

The Guardian takes **any** app (any language, a repo or a container image) and answers three questions with proof:

1. **What's inside?** Every library, its exact version, and who pulled it in.
2. **What's dangerous?** Known security holes (CVEs) and suspicious changes (typosquats, unexpected new libraries, install scripts, unpinned images or CI steps).
3. **Why do we think so?** Each finding points to raw tool output that can be checked.

The judges care about two things, and the plan answers each:

- **Scalability.** The core only understands one universal format: a CycloneDX ingredients list (SBOM) in which every library carries a universal name tag (purl, e.g. `pkg:npm/express@4.0`, `pkg:maven/...`). Language-specific code lives only in small plug-ins.
- **Trust.** Facts come from tools, never from the AI. A validator rejects any AI claim without evidence. Planted test cases measure accuracy, and the scan keeps working when the AI is down.

Day 1 checkpoint: *"Show us what is in the application, what changed, and what appears risky."*

## Locked decisions

| # | Decision |
|---|---|
| 1 | Language: **Python 3.11** |
| 2 | Core contract: CycloneDX + purl only. Dependency links are optional and always record where they came from. None is ever guessed |
| 3 | CVEs: **Grype as the main source** + **OSV-Scanner**. OSV-Scanner supplies malicious-package (`MAL-`) entries for any language, and also marks each CVE "confirmed by 1 or 2 scanners". Duplicates are merged on the advisory ID and its aliases |
| 4 | Targets: **Juice Shop + 1 app in another language** (to be picked; see Next steps) |
| 5 | Risk level is set by a fixed rule table, not by the AI. Every finding shows its rule ID |
| 6 | Never say "safe". Report states: `affected / not_affected / under_investigation`; reachability: `confirmed / not_detected / unknown` |
| 7 | Out of scope: bugs in application code. **Semgrep and Gitleaks are removed** |

## Pipeline

1. **Resolve** (per-language plug-in). Get the true dependency tree from the package manager without running install scripts.
   - npm: `npm install --package-lock-only --ignore-scripts`, then `npm ls --all --json --package-lock-only` for the true parent→child links.
   - Other languages: use their lockfile, or their tool (`mvn dependency:tree`, `go mod graph`, poetry/uv lock).
   - The generated lockfile is frozen and committed as a labelled baseline.
2. **SBOM.** Syft produces CycloneDX. Links from step 1 are merged in, each tagged `resolver` or `sbom`.
3. **Graph.** NetworkX finds the shortest path from the app to each affected library, plus the total number of paths.
4. **Detect.**
   - CVEs: Grype (main) + OSV-Scanner (malicious packages + second opinion).
   - Anomalies: SBOM diff against the baseline; Git diff of manifest, lockfile and workflow files (line, old and new hash); typosquat check on direct dependencies; npm install-script flag; Dockerfile base image pinned by digest; CI actions pinned by SHA.
5. **AI review (agentic, checked).** A chain of small steps: inventory review → advisory context → change analyst → **validator** → report writer.
   - Each AI claim must cite evidence IDs.
   - Code checks that the cited CVE ID, version, path and source link really exist in the tool output. If not, the claim is rejected.
   - Repo text (README, package descriptions) is treated as data, never as instructions.
   - If the AI times out, the report is built without it.
   - LangGraph is used if the owner knows it; plain Python functions otherwise.
6. **Report.** `findings.json` is the source of truth. An HTML report page and a Markdown report are generated from it, along with a coverage table and a run record.

## Shared format (freeze before coding)

| Object | Fields |
|---|---|
| Scan | `scan_id`, `target`, `commit_sha`, `lockfile_hash`, `resolution` (`lockfile/resolved/image/manifest-only`), `scanner_versions`, `db_built_at`, start/end time, `status` (`complete/partial/failed`), `llm_status` (separate from scan health) |
| Component | `component_id`, `purl`, `version`, `scope` (`direct/transitive/unknown`), `source_file` |
| Edge | `parent_id`, `child_id`, `edge_source` (`resolver/sbom`) |
| Evidence | `evidence_id`, `tool` + `tool_version`, file, path or advisory URL, `sha256`, `collected_at`, `raw_pointer` (JSON pointer into the raw output) |
| Finding | `finding_id` (hash of detector + purl + version + path, so it stays the same across reruns), `kind`, `component_id`, `advisory_id` + `aliases[]` OR `anomaly_type`, `confirmed_by[]`, `fixed_versions[]`, `match_basis` (`purl/cpe`), `dependency_path[]`, `evidence_ids[]`, `state`, `risk_level`, `risk_rule_id` |
| Agent claim | `claim`, `evidence_ids[]`, `kind` (`evidence/inference`), `validated`, `uncertainty`, `rejected_reason` |
| Fix (Day 2) | `finding_id`, `patch_ref`, `approval_user/time`, `test_results`, `rescan_id` |

Missing values are written as `UNKNOWN`, never guessed.

## Trust and scale: what we show the judges

| Claim | Proof |
|---|---|
| Works on any language | Same command, unchanged, on Juice Shop (npm) and a second-language app. The coverage table, generated from the run, shows exactly which checks ran per language and which were skipped |
| AI can't make things up | Inject a fake CVE into the AI's answer and show the validator rejecting it. Put a prompt-injection line in a README and show it being ignored |
| Works without AI | Turn off the AI and show every scanner finding and its evidence still appears |
| Detectors are accurate | 3–5 planted test cases in `holdout-scenarios/` (unexpected dependency, changed install script, modified lockfile, unpinned action). Planted by someone who writes no detectors. Scored by precision and recall |
| Large repos | Count of AI calls vs packages (AI sees only flagged findings, not 1,000 packages); a rescan of an unchanged lockfile is skipped and reused |
| Honest uncertainty | `under_investigation` or `unknown` shown instead of "safe"; empty checks shown as "pass" or "n/a" in the coverage table, never left blank |

## Who does what (5 people)

| Person | Owns | Hands over |
|---|---|---|
| **P1** | Resolve, SBOM, graph, dependency paths. **Critical path: everyone needs this** | `sbom.cdx.json`, `graph.json`, `inventory.json`, run record |
| **P2** | Grype + OSV-Scanner adapters, merging duplicates, malicious-package lookup | `findings.json` (CVE + MAL), raw outputs |
| **P3** | Anomaly detectors (SBOM diff, Git diff, typosquat, install scripts, image and CI pinning) + "clean vs suspicious" commits for the demo | `anomalies.json`, rules file, demo commits |
| **P4** | AI chain + validator + adversarial tests (fake CVE, prompt injection, AI down) + **holdout test cases and scorer**. P4 writes no detectors, so the test stays fair | `validator.py`, tests, scorer results |
| **P5** | Owns the shared format (freezes it first), joins all parts, risk rules, report (HTML + Markdown + JSON), coverage table | Runnable `guardian scan` command + report page |

P2–P5 start immediately with sample JSON that matches the shared format, while P1 builds the real pipeline.

## Goals vs. Non-Goals

* **In-Scope Goals (Day 1):**
  - One command runs on Juice Shop and the second app.
  - Outputs: SBOM, graph with a real path to a vulnerable library, CVE findings confirmed by 1 or 2 scanners, at least one anomaly with a Git diff, evidence for each finding, initial risk level.
  - Coverage table, run record, fake-CVE rejection, report works without AI, holdout scorer.
  - **Day 1 live demo of the Day 1 requirements (not a full product).** The HTML report page is a must-have. It shows, in order: the repo and lockfile, the SBOM, a real dependency path, a CVE card, an anomaly with its Git diff, evidence and risk level. Then the fake-CVE rejection and the AI-off run.
* **Out-of-Scope Non-Goals (Day 1):**
  - React website, FastAPI server, Redis/RQ, PostgreSQL, queue with 10 parallel scans (Day 2 if time allows).
  - Semgrep, Gitleaks.
  - Our own resolvers beyond npm plus the second app's language.
  - Building images.
  - Reachability, Sigstore, OPA, continuous monitoring (stretch goals).
  - Any claim about languages that the coverage table doesn't show.

## Alternatives Weighed

- **PDF stack as-is (FastAPI + React + Redis/RQ + Postgres + LangGraph + Semgrep + Gitleaks) on Day 1:** rejected. Far too much to build in about 2 hours, and Semgrep and Gitleaks are outside the agreed scope (code bugs and secrets, not package risk).
- **Our original "AI writes one summary" layer:** replaced by the PDF's checked chain of AI steps. The problem statement asks for an *agentic* solution, and one summary didn't show that.
- **Grype only (our original plan):** expanded. OSV-Scanner adds malicious packages for any language, plus a second opinion that raises confidence.
- **SBOM links only for the dependency tree (our original plan):** replaced by package-manager resolution (from the PDF). Syft may drop links (Syft issue #2832).
- **PDF's npm/Maven/Python-only design without a common core:** rejected. It doesn't scale to "any language". The purl-only core and coverage table stay.
- **Hand-written coverage table; AI-assigned risk levels; building the Juice Shop image; Dependency-Track; Socket CLI:** rejected (see v1 reasons in the tool research).

## Key Decisions & Staging for Next Steps

1. **Pick the second app.** It needs a different language, real vulnerable packages, and a committed lockfile with dependency links. Verify it scans cleanly (about 10–15 minutes) before the team relies on it.
2. **Resolved:** Day 1 needs a live walkthrough of the Day 1 requirements only. The HTML report page (P5) is the demo screen.
3. **Check before building on it:** whether Juice Shop's `.npmrc` blocks lockfile creation; whether `npm ls --package-lock-only` gives full links; exact tool versions.
4. **Before the demo:** download the Grype and OSV databases and the scan targets in advance, so the demo works without internet.
5. **Day 2:** FastAPI + approval page, sandbox branch build, test and rescan, before/after SBOM, downloadable report, then Redis/queue if time allows.
