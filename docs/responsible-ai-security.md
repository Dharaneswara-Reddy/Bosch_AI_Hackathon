# Responsible AI & Security Note

This note covers four questions: where Guardian uses AI, how it keeps the AI from inventing facts, which actions need a person's approval, and how it protects source code, credentials and secrets.

## 1. Where AI is used, and where it is not

Guardian is a pipeline of fixed code steps with AI agents added at specific points. Every number that drives a decision comes from code: the risk level, the risk score, the confidence score and the fix candidates.

| Step | Done by | What it produces |
|---|---|---|
| Fetch, SBOM, dependency graph | Code (GitHub API, Syft) | Component inventory and dependency paths |
| Vulnerability and anomaly detection | Code (Grype, OSV-Scanner, rule-based detectors) | Findings, each with evidence records |
| Exploit intel, scope, reachability | Code (CISA KEV, EPSS, Gemfile groups, import scan) | Signals attached to each finding |
| Risk level and score | Code: the SSVC decision tree in `guardian/risk.py`, configured by `policy/risk.toml` | Critical / High / Medium / Low, a 0–100 score, and the reasons |
| Confidence score | Code (`guardian/confidence.py`) | A 0–1 score and whether a human must review the finding |
| Vulnerability analyst | **AI**, one parallel LangGraph branch per package | A plain-language explanation of each finding |
| Change & provenance analyst | **AI** | Why a suspicious change is suspicious |
| Risk analyst | **AI** | A suggestion to move a risk level up or down by one level, with cited evidence |
| Evidence validator | Code (`guardian/ai/validator.py`) | Accepts or rejects every AI claim |
| Risk critic | **AI**, a second model pass | Agrees or disagrees with the accepted claims and adjustments |
| Fix candidates | Code (`guardian/remediate/candidates.py`, `guardian/ai/remediation.py`) | The allowed actions and target versions |
| Remediation planner | **AI** | Chooses among the code-computed candidates and writes the rationale and rollback |
| Sandbox, build, tests, rescan, diff | Code, inside containers | Validation results and before-vs-after |

If the AI is switched off, or every model provider fails, the scan still completes. The risk levels stay the same, fixes are proposed by rule, and the run records `llm_status: unavailable` or `failed`.

## 2. How hallucinations are controlled

1. **No claim without evidence.** Every AI claim must cite evidence ids from the scan. The evidence validator rejects any claim that:
   - cites an unknown id, or
   - names a CVE, package, version or file that does not appear in the cited evidence.
   Rejected claims are kept with the reason for rejection, so a reviewer can see what the AI got wrong.
2. **Structured output only.** Agents reply in a strict JSON schema (`guardian/ai/schemas.py`). A malformed reply is rejected; it is never parsed loosely.
3. **Revision loop, then a critic.** A rejected claim goes back to its analyst once with the reason. A second AI pass (the risk critic) then reviews the accepted claims and risk adjustments. If the critic disagrees, the finding goes to human review.
4. **The AI cannot set the risk on its own.** The risk analyst can only suggest one-level changes, and code enforces limits on them:
   - a known-malicious package is never lowered;
   - a known-exploited vulnerability in production is never below High.
   Adjusted findings are labelled "AI adjusted: High → Medium" with the reason and the evidence.
5. **The AI cannot invent a fix.** The planner can only choose an action and target version from the list that code computed from scanner fix data.
6. **Verified evidence and AI inference are kept separate.** Claims are typed `evidence` (directly supported) or `inference` (reasoned). The UI and the report show them separately.
7. **Live hallucination test.** The UI option "inject a fabricated CVE claim" puts a made-up claim into the pipeline, and the validator visibly rejects it.

## 3. Actions that require human approval

| Action | Approval gate |
|---|---|
| Accepting an uncertain finding | Every finding with low confidence, an SSVC "Act" decision, an AI change across Critical, or a critic disagreement goes to the **Review queue**. A person confirms, dismisses (a note is required; this records an accepted risk) or escalates it. Decisions are stored with reviewer, note and time, and appear in the report. |
| Applying any fix | The fix workflow is a LangGraph graph that **pauses at an `interrupt`** until a person approves or rejects. Nothing is copied, edited, built or scanned before approval; tests check this. |
| Merging, pushing, deploying, publishing | **Never automated.** Guardian validates fixes in a throwaway sandbox and reports the result. A person applies the change to the real repository. |

## 4. How source code, credentials and secrets are protected

- **Minimal fetch.** A scan downloads only dependency manifests, lockfiles, Dockerfiles and CI workflow files, through the GitHub API. Full source is fetched only after a fix is approved, and only into that fix's sandbox, so tests can run there.
- **What the AI sees.** The models receive finding facts (package, version, advisory, path, scope, signals) and short evidence excerpts from scanner output. They do not receive the application's source code. Before any text is sent:
  - it passes through `guardian/ai/guardrails.py`, which redacts anything that looks like a private key, cloud key, GitHub token, API key, JWT or password assignment;
  - it is cut to a fixed length;
  - it is scanned for prompt-injection phrases (reported, never obeyed);
  - it is wrapped as `<untrusted>` data.
- **Model providers.** The providers are Groq first, then Gemini as fallback. These are third-party services, so treat anything sent to them as leaving the machine. Set `GUARDIAN_LLM_PROVIDER=none` for a fully offline run.
- **Keys.**
  - All keys load from `.env` (git-ignored) and are checked at startup.
  - They are never written to reports, logs or API responses, and never sent to the browser.
  - Provider error messages are passed through with any key text removed.
  - `GITHUB_TOKEN` is optional and stays in the backend.
- **No repository code on the host.** Install scripts are always disabled (`--ignore-scripts`). Builds and tests run only in a container with:
  - no network (`--network none`);
  - a read-only source mount;
  - all Linux capabilities dropped;
  - CPU, memory, process and time limits.
  A Ruby `Gemfile` that contains anything beyond the declarative DSL is refused, because evaluating it would run code.
- **Out-of-scope actions are not possible.** Guardian has no code path that publishes packages, pushes to a registry, opens a pull request automatically, or scans systems other than the given public repository.
- **Audit trail.**
  - Every scanner output is stored with a SHA-256 fingerprint (`guardian/evidence.py`).
  - Every agent step is in the agent trace, with the provider that answered.
  - Every human decision and fix run is saved to disk.
  - The final `report.html` and `report.json` merge all of these into one timeline.

## 5. Known limits of these controls

- Secret redaction is pattern-based. An unusual secret format could pass through, which is one more reason the AI never receives source files.
- The validator checks that a claim's facts are supported by evidence. It cannot prove that an explanation is complete or that the reasoning is good; the critic and the human review queue cover that gap.
- Scanner results are only as current as the vulnerability databases. The report records each database's date.
- Container isolation depends on the local Docker or Podman setup. Guardian applies the restrictions above but does not harden the container engine itself.
