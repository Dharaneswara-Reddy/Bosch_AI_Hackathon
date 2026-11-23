# Changes

What the team built and changed, per component, and why. Newest first.

## 2026-11-23 · Relevance, entry paths, safe demo app, final report

**Goal:** do not just list CVEs: explain how each one enters the application, decide with
evidence whether it matters, and demonstrate a malicious-package detection safely.

| Component | Change | Why |
|---|---|---|
| `guardian/models.py` | Added `Relevance`, `RelevanceSignal`, `RelevanceVerdict`, `Reachability`, `AgentTrace`; `Finding.relevance`; `FindingsArtifact.agent_trace` (all optional, backward compatible) | Shared contract for relevance and the agent audit trail |
| `guardian/scope.py` (new) + runner `scope` stage | Marks each component direct/transitive (from the graph) and production/dev-only (from npm lockfile `dev` flags) | Scope was always unknown before, so the risk rule's dev-dependency modifier never applied |
| `guardian/reachability.py` (new) | Static search of the app's own source for `require`/`import` of a package (JS/TS, Ruby, Python); skips `node_modules`, `vendor`, tests | Shows whether the app actually uses the vulnerable package or the dependency that pulls it in |
| `guardian/relevance.py` (new) + `guardian/analysis.py` (new) + runner `relevance` stage | Per vulnerability: signals (version in affected range from Grype's `versionConstraint`, scope, position and depth, path count, fix and major-version jump, reachability, CISA KEV/EPSS when present) and a verdict: relevant / likely relevant / unknown / low relevance. Import hits are stored as evidence (`raw/relevance/reachability.json`) | Rank findings by whether they matter, with proof, never declaring anything safe |
| `guardian/detectors/unverified_source.py` (new) | Flags npm packages from a local path or git URL that declare an install script (`unverified_install_script`, rule `R-AN-1`); labels packages marked `"guardian": {"synthetic": true}` | Catches the classic planted-dependency pattern without needing a baseline commit |
| `guardian/risk.py` | New anomaly type in `R-AN-1`; keeps an existing note (e.g. SYNTHETIC) when adding the dev-dependency note | Synthetic label must survive risk classification |
| `guardian/ai/` | New code-only `relevance` agent (triage → relevance → analysts); evidence packs carry the relevance signals; triage ranks by relevance then risk; vuln analyst explains relevance from the signals; critic checks that reasoning; validator rejects claims about reachability, dev/production scope or exploitation that contradict the recorded signal; `run_review` returns the agent trace | Intelligent analyst validation: agents explain relevance, code checks it |
| `guardian/report/` | Report reordered: repository and tools → SBOM → how each vulnerability enters the app (every hop with its edge source, introduced by, path count) → vulnerabilities ranked by relevance with signals and evidence → suspicious/malicious packages (synthetic labelled) → AI analysis → fix proposals → agent trace → coverage → remaining unknowns and limitations | Final-stage report required by the brief |
| `guardian/eval/scorer.py`, `holdout-scenarios/hs-06-*` | Scores the new detector; new planted case (local package with install script on Juice Shop), verified against a real resolved lockfile | Measure the new detector like the others |
| `demo/vulnerable-app/` (new) | Small Node app: reachable transitive CVE, unused production CVE, dev-only CVE, synthetic typosquat with inert install script, unpinned CI action | Safe, local demonstration of every feature, including a malicious-style package |
| `Bosch_Guardian_Clean` (UI) | "Scan the built-in demo app" (local copy, source included, no network); findings ranked by relevance with signals; click a finding to see why and to highlight its path in the graph; agent trace in the AI review tab | Show the analysis in the live demo |
| Docs | `docs/open-source.md`, this file, `demo/vulnerable-app/README.md`, updates to `README.md`, `guardian/ai/README.md`, `docs/p4-ai-trust.md` | Team documentation requirement |

## 2026-11-23 · UI shows the AI review

- UI backend loads the repository-root `.env`, enables the AI agents only when a provider and
  key are set, returns the AI claims, and offers a hallucination test (injects a fabricated CVE).
- Frontend: AI review tab, hallucination-test checkbox, AI status in the sidebar.
- `scripts/start-backend.bat`, `scripts/start-frontend.bat` for Windows.

## 2026-11-23 · Multi-agent AI review (LangGraph)

- Replaced the single explain step with a LangGraph graph of agents: triage, vulnerability
  analyst, change analyst, evidence validator (with one revision round), independent risk
  critic, remediation candidates, remediation planner, report writer.
- Fix proposals: code computes the allowed actions and versions; the planner chooses; code
  rejects anything outside them; every proposal needs human approval.
- Groq through LangChain (`ChatGroq`) with strict structured outputs.

## 2026-11-23 · Day 1 pipeline

Fetch → lockfile edges → Syft SBOM → NetworkX graph → Grype + OSV-Scanner (merged by alias)
→ anomaly detectors (typosquat, unexpected dependency, install script, version swap,
unpinned image, unpinned CI action) → fixed risk rules → coverage → AI review with a code
validator → HTML/Markdown report. Holdout scenarios and a precision/recall scorer.
