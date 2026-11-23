# Guardian v2 architecture: contextual risk, parallel agents, confidence-gated review

* **Author:** P2 (with Claude)
* **Date:** 2026-11-24
* **Status:** proposal for team review

## The problem with v1

v1 assigns the final risk from the scanner's severity alone (`guardian/risk.py`). A Medium
CVE that attackers exploit every day stays Medium, and a Critical CVE in an unused dev
dependency stays Critical. Day 2 asks for the opposite: "combine severity with exploitability,
reachability and exposure" and "an explainable risk score and confidence level".

Other v1 problems:

* The AI agents run one after another, even when they do not depend on each other.
* Triage caps the AI at 20 findings. The number is arbitrary and hard to explain.
* "Relevance signals" are computed but never change the risk. They only add a label, so they
  confuse more than they help.
* There is no confidence score and no rule for when a person must review a finding.
* Day 2 stages (sandbox, rescan, before/after) are not in the graph at all.

## The idea in one paragraph

Scanners say *what* is vulnerable. v2 adds a context step that asks four questions about every
finding: is it being exploited, can the app reach it, is it exposed in production, and how
bad is the impact? A deterministic risk engine answers with the CISA SSVC decision tree.
SSVC is the US government's published method for exactly this decision. Its answer gives the
risk level, a 0–100 score, and the reasons. AI agents then work in parallel, one package at a
time. They explain each finding and may propose a one-level adjustment, but only with cited
evidence. Code validates every claim and an independent AI critic reviews it. A confidence
score sends uncertain or high-impact decisions to a human. Day 2 continues in the same graph:
fix proposal, human approval, sandbox build and tests, rescan, before/after comparison.

## Pipeline (8 stages)

| # | Stage | Runs as | Parallel? | Output |
|---|---|---|---|---|
| 1 | Discover | code | — | SBOM, dependency graph |
| 2 | Detect | code | Grype ‖ OSV-Scanner ‖ detectors ‖ git diff | findings |
| 3 | Enrich context | code | exploit intel ‖ reachability ‖ package health ‖ scope/exposure | signals per finding |
| 4 | Score | code | — | SSVC decision, level, score, reasons |
| 5 | Analyze | LLM agents | one branch per package group | explanations, proposed adjustments |
| 6 | Verify | code + LLM | per package group | validated claims, confidence |
| 7 | Remediate (Day 2) | LLM + code + human | per approved fix | patch, build/test, rescan, diff |
| 8 | Evidence & report | code + LLM | — | audit log, report.html / report.json |

LangGraph orchestrates the whole run. The graph is checkpointed, so a crash resumes instead of
restarting. Parallel branches use LangGraph's `Send` fan-out with a concurrency limit, so
provider rate limits are respected. The human gates use LangGraph `interrupt`.

## Stage 3: context enrichment (all code, all evidence-backed)

| Signal | Source | Already available? |
|---|---|---|
| Known exploited | CISA KEV catalog (daily JSON feed) | Grype reports KEV status when the DB has it |
| Exploit probability | FIRST EPSS (probability of exploitation in the next 30 days) | **Yes.** Grype returns EPSS for 174 of RailsGoat's matches today; we ignore it |
| Public exploit / PoC | advisory references tagged exploit/PoC (OSV, GHSA) | partly, in raw OSV output |
| Reachability | static import search of the app source (exists, `guardian/relevance.py`) | yes, when the source is available |
| Scope | manifest groups (`Gemfile` groups, npm `devDependencies`, Maven `test`) | npm yes; Ruby groups missing |
| Exposure | Dockerfile `EXPOSE`, web-framework entry points, CI-only vs runtime | new |
| Package health | deps.dev API: OpenSSF Scorecard, release recency, maintainer count | new, optional |
| Technical impact | CVSS vector (attack vector, privileges, impact) | yes, in scanner output |

Each signal becomes an evidence record (source, timestamp, hash), just like a scanner result.
A missing signal is `unknown`, never "safe".

## Stage 4: the risk engine (SSVC)

SSVC (Stakeholder-Specific Vulnerability Categorization) is CISA's decision tree. It replaces
"sort by CVSS" with four questions. The engine answers them from the stage 3 evidence:

1. **Exploitation:** `active` (in KEV) · `likely` (EPSS above the policy threshold, or a public
   PoC) · `none`.
2. **Exposure:** `open` (reachable, production, internet-facing) · `limited` (production but
   not reached, or reachability unknown) · `small` (dev or test only).
3. **Automatable:** can an attacker exploit it without user interaction, over the network?
   Read from the CVSS vector.
4. **Technical impact:** `total` (CVSS critical or high impact) or `partial`.

| SSVC decision | Guardian level | Example |
|---|---|---|
| **Act** | Critical | Exploitation active + exposure open or limited; or any malicious package |
| **Attend** | High | Active exploitation on a dev dependency; or likely exploitation + total impact + production |
| **Track\*** | Medium | Likely exploitation, or total impact, with no exposure evidence |
| **Track** | Low | No exploitation signal, partial impact, or dev-only |

**Your example:** vulnerability 2 is CVSS Medium but in KEV and used in production. Exploitation
is active and exposure is limited or open, so the decision is **Act**, which means **Critical**.
Vulnerability 1 is CVSS Critical with no exploitation and only a dev dependency, so it becomes
**Track** or **Track\*** (Low or Medium). The report prints the path through the tree, for
example "Critical because: in CISA KEV (added 2026-03-02), production dependency, network
exploitable".

The 0–100 score orders findings within a level: base CVSS, weighted by EPSS percentile and
exposure. Thresholds and weights live in a policy file (`policy/risk.yaml`), which also covers
the policy-as-code stretch goal.

Supply-chain anomalies (typosquat, install-script change, unpinned image) follow the same
engine. They get exploitation `likely` for an install-script change on a new package, and their
exposure comes from scope.

## Stage 5: agents, in parallel

Work is split **per package group** (all advisories for one package, with its platform builds
merged). RailsGoat has 258 findings but 114 groups, and each group is one parallel branch.

| Agent | Kind | Job | Can it change risk? |
|---|---|---|---|
| Vulnerability analyst | LLM | What the CVE means for this app, with path, fix and preconditions | No |
| Change & provenance analyst | LLM | Why a change is suspicious; compares versions, scripts, lockfile hashes | No |
| **Risk analyst** | LLM | Reads what code cannot: advisory preconditions ("only on Windows", "only when feature X is enabled") against the app context | Proposes **±1 level**, with a cited reason |

The risk analyst is bounded by rules enforced in code:

* **Floors:** KEV + production can never drop below High, and a malicious package stays Critical.
* **Citations:** every adjustment must cite evidence IDs, and the validator rejects any
  adjustment whose cited evidence does not contain the stated precondition.
* **Visibility:** the engine's level and the AI's adjustment are both shown, never merged
  silently.

**Why not "top 20":** every finding gets the deterministic engine. The LLM runs per package
group, not per finding, in batches, and only for groups at Track\* or above, set by policy.
That bounds cost and is easy to explain: "AI reviews every package that matters, one call per
package." With 114 groups and 5 groups per call, that's about 23 calls.

## Stage 6: verify and the confidence gate

1. **Evidence validator** (code, exists today): 7 checks on every claim.
2. **Risk critic** (LLM, exists today): an independent model reviews accepted claims and any
   risk adjustment. Its verdict is supported, overstated (downgrade to inference) or unsupported
   (reject).
3. **Confidence score** (code, new), from 0 to 1 per finding:

| Factor | Weight |
|---|---|
| Installed version confirmed inside the affected range | 0.25 |
| Dependency path resolved from a lockfile | 0.15 |
| Two scanners agree (Grype + OSV) | 0.15 |
| Exploit data present (KEV/EPSS) | 0.15 |
| Reachability known (confirmed or not detected) | 0.15 |
| Risk analyst and critic agree | 0.15 |

**Human review queue:** confidence below 0.6, *or* the AI moved a finding into or out of
Critical, *or* the analyst and critic disagree. Everything else is accepted automatically, with
its confidence shown. This is the "confidence score mechanism to go to human review".

## Stage 7: Day 2 remediation loop (same graph)

1. **Remediation candidates** (code): upgrade to the nearest fixed version, replace, pin,
   update the base image, block, or escalate. Each has a semver impact (patch, minor or major).
2. **Remediation planner** (LLM): picks one action per finding, with expected risk reduction,
   compatibility impact and a rollback step. Code validates it against the candidates.
3. **Human approval** (`interrupt`): the UI shows the plan, and nothing runs without approval.
4. **Sandbox executor** (code): applies the change on a throwaway branch in a container, then
   builds and runs the tests.
5. **Rescan + diff** (code): runs stages 1–4 again on the branch and compares SBOMs and
   findings before and after: fixed, new and remaining.
6. **Verification analyst** (LLM): explains the outcome. Its claims are validated like any other.

## Stage 8: evidence store and report

One folder per scan, append-only: raw tool output with SHA-256, enrichment records, SBOM
before/after, findings, claims, decisions, approvals and test results. The report comes in two
forms: human (`report.html`) and machine (`report.json`). It lists every decision with its SSVC
path, confidence and who approved it.

## Reliability

* **LLM provider chain:** Groq → Gemini → OpenAI → Anthropic. It falls over on 429, 5xx,
  timeouts and bad keys, and a per-run breaker skips a provider that has failed. This is built.
* **AI off:** if every provider fails, stages 1–4 and 7's code steps still work. The report
  says the AI review failed, and every finding still has an SSVC risk and confidence.
* **Rate limits:** the parallel branches share one concurrency limit, set from the provider's
  limits.

## Why this beats a typical entry

1. **Risk is explainable and standard.** The judges see "Critical *because* in KEV +
   production + network-exploitable", using CISA's own framework, not an LLM's opinion and not
   raw CVSS.
2. **AI adds context without being trusted blindly.** It can adjust risk, but only one level,
   only with cited evidence, behind code floors, an independent critic and a confidence gate.
3. **It scales.** Deterministic for every component, AI per package group, parallel, behind a
   provider fallback chain.
4. **It closes the loop.** Detection → contextual risk → plan → human approval → sandbox →
   rescan → before/after proof, all in one checkpointed graph with an audit trail.
5. **It degrades gracefully.** Without any LLM it still produces the full SBOM, graph, findings,
   SSVC risk and confidence.

## Honest risks

* **Scope:** this is a lot to build in the time left. The phases below put the parts judges
  see first.
* **EPSS is a probability, not proof.** Treating it as "likely exploited" at a threshold is a
  policy choice, and the threshold must be shown.
* **Reachability is import-level, not call-level.** It cannot prove that a vulnerable function
  runs, so it raises confidence but never proves safety.
* **Exposure** inferred from Dockerfiles and frameworks is heuristic. It should be labelled as
  such.

## Build phases

| Phase | Contents | Why first |
|---|---|---|
| A | Risk engine (SSVC) using KEV + EPSS from Grype, scope incl. Gemfile groups, confidence score, report/UI showing "why" | Fixes the main complaint; mostly data we already have |
| B | Risk analyst agent with floors; parallel fan-out per package group (`Send` + concurrency limit); remove the top-20 cap | Visible agentic depth, faster runs |
| C | Human review queue + approval with LangGraph `interrupt`; UI approve/reject | Day 2 requirement |
| D | Sandbox executor, rescan, before/after diff, verification analyst | Day 2 final demo |
| E | Package health (deps.dev/Scorecard), exposure detection, policy file | Stretch goals |

## Alternatives weighed

* **Let the LLM assign risk directly.** Rejected: it can't be explained or reproduced, and
  judges focused on trust will distrust it. The LLM only proposes bounded adjustments.
* **CVSS × EPSS formula only.** Rejected as the main decision: it ignores exposure and scope,
  and a single number hides why. Kept as the within-level score.
* **Grype's built-in risk score.** Useful input, but opaque and Grype-only. We show our own
  SSVC path and keep Grype's score as evidence.
* **One agent per finding.** Rejected: 258 calls for RailsGoat. Per package group gives the
  same coverage with about 23 batched calls.
