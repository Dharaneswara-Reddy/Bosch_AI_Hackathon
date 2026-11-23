# P4: Multi-agent AI review, validation and evaluation (handoff)

Full description: [`guardian/ai/README.md`](../guardian/ai/README.md). This page covers what other team
members need to know.

## What changed (multi-agent rework)

The single "explain" step was replaced by a **LangGraph** graph of specialised agents with typed,
evidence-cited hand-offs:

```
triage (code) -> vuln_analyst -> change_analyst -> evidence_validator (code)
   -> [analyst_revision -> evidence_validator]  (once, only if claims were rejected)
   -> risk_critic (independent reviewer) -> remediation_candidates (code)
   -> remediation_planner -> report_writer
```

- **Fix recommendations** now exist: code computes which actions and target versions are allowed per
  finding; the planner chooses and explains; a code validator rejects anything outside those options.
  Every proposal requires human approval.
- **Two validation layers:** the code evidence validator (unchanged checks) plus an independent critic
  agent whose verdicts can only downgrade or reject.
- **Self-correction:** rejected analyst claims go back to the analyst once, with the rejection reasons.
- Groq is now called through **LangChain** (`langchain-groq` `ChatGroq`), still with strict structured
  outputs and no SDK retries.

## Relevance (code) and agent trace

- Runner stages `scope` (after inventory) and `relevance` (after risk) attach a `Relevance` to
  every vulnerability and malicious finding: verdict, reachability, introduced-by direct
  dependency, path labels and signals with evidence IDs. See `guardian/relevance.py`.
- The AI graph now runs `triage -> relevance -> analysts ...`; the validator rejects relevance
  statements that contradict the signals.
- `run_review(result, settings, injected)` returns `(claims, llm_status, agent_trace)`; the
  runner stores `agent_trace` in `findings.json`, the report and the UI show it.

## Wiring

`guardian/runner.py` keeps calling `guardian.ai.review.run_review(result, settings, injected)` and gets
`(claims, llm_status)`. Fix proposals are included in `claims` as `remediation_planner` claims, so the
report shows them in the existing accepted / inference / rejected sections.

Optional follow-up for P5: `run_ai_review(...)` also returns `proposals` (structured
`RemediationProposal`s for Day 2's approval flow) and `trace` (one `AgentTrace` per agent: consumed,
produced, accepted, rejected, LLM calls, error). Writing them to `remediation.json` and `agents.json`
needs a small runner change.

## Dependencies (`pyproject.toml`)

Added: `langgraph>=1.0`, `langchain-core>=1.0`, `langchain-groq>=1.0`. Re-run
`python -m pip install -e '.[dev]'`.

## Settings (`.env`)

```
GUARDIAN_LLM_PROVIDER=groq          # none | groq | openai_compatible
GUARDIAN_LLM_API_KEY=gsk_...        # Groq key
GUARDIAN_LLM_MODEL=                 # optional, default openai/gpt-oss-120b
```

`--no-llm` still works: code-only agents run, `--inject-claim` claims are still validated and rejected,
`llm_status = unavailable`.

## What the AI package reads from `guardian/models.py`

`Component`, `Evidence`, `Finding` (incl. `purl`, `fixed_versions`, `dependency_path` as component IDs,
`source_file` on the component), `AgentClaim`, `ClaimKind`, `LlmStatus`. No model changes were needed.

## Holdout scenarios

Five planted cases live in `holdout-scenarios/`. Detector authors should not open that folder.
