# P4: AI review, validator and evaluation (handoff)

What P4 built, how P5 wires it in, and what it assumes about `guardian/models.py`.

## Files

| File | Purpose |
|---|---|
| `guardian/ai/llm.py` | `LLMClient.complete(system, user, schema, timeout) -> dict`; `NoneClient`; `OpenAICompatibleClient` (OpenAI, Ollama, vLLM, Groq, ...); `build_client(provider, model, api_key, base_url)` |
| `guardian/ai/schemas.py` | `LLMReply` / `LLMClaim`: the only shape the model may return (`extra="forbid"`, max 8 claims, max 600 chars) |
| `guardian/ai/prompts.py` | System rules + per-step tasks (`explain_vulns`, `explain_changes`, `inventory_note`, `summarize`) |
| `guardian/ai/guardrails.py` | `wrap_untrusted` (escapes delimiter look-alikes), `redact_secrets`, `find_injection_markers` |
| `guardian/ai/context.py` | `ReviewContext`: read-only view of findings, evidence, components |
| `guardian/ai/validator.py` | Plain-code claim validator (the 5 design checks + "never safe" + severity must match) |
| `guardian/ai/steps.py` | `run_ai_review(...)`: top-20 only, 30 s deadline per call, retry once on bad schema, circuit breaker; `load_injected_claims(...)` for `--inject-claim` |
| `guardian/eval/scorer.py` | `run_eval(scenarios_dir, base, scan_fn)`: per-scenario pass/fail + per-detector precision/recall |
| `holdout-scenarios/hs-01..05` | Planted cases (P3 must not read) |
| `tests/fixtures/fake_cve_claim.json` | Demo file for `--inject-claim` |

## Wiring for P5 (`runner.py` / `cli.py`)

```python
from guardian.ai import ReviewContext, build_client, load_injected_claims, run_ai_review

ctx = ReviewContext.build(findings, evidence, components, project_text=readme_first_2000_chars)
client = build_client("none" if no_llm else settings.llm_provider, settings.llm_model,
                      settings.llm_api_key, settings.llm_base_url)
injected = load_injected_claims(inject_claim_path, ctx) if inject_claim_path else []
result = run_ai_review(ctx, client, injected=injected, timeout=settings.llm_timeout_s)
# findings.json   <- result.claims (accepted, inference and rejected; rejected_reason shown in report)
# run.json        <- result.llm_status, result.llm_calls (next to component count), result.step_errors,
#                    result.injection_markers, result.secrets_redacted
# Scan.status is never changed by the AI step.
```

`--inject-claim` works with `--no-llm` too, so the fabricated-CVE rejection can be demoed without an API key.
In the claim file, `"@top-finding"` cites the top finding's first evidence ID, so the rejection reason is
"advisory CVE-2026-31337 is not in the cited findings" rather than only "evidence ID not found".

`guardian eval`: build `scan_fn(target_dir) -> list[ObservedFinding]` that runs the scan against the clean
baseline and returns `(kind, anomaly_type, component purl)` per finding, then call `run_eval(...)`.

`.env` (for `.env.example`): `GUARDIAN_LLM_PROVIDER=none|openai_compatible`, `GUARDIAN_LLM_MODEL=`,
`GUARDIAN_LLM_API_KEY=`, `GUARDIAN_LLM_BASE_URL=` (e.g. `http://localhost:11434/v1` for Ollama),
`GUARDIAN_LLM_TIMEOUT_S=30`.

## What the AI package reads from `guardian/models.py`

Exactly the design's data model table: `Component(component_id, purl, name, version, ecosystem)`,
`Evidence(evidence_id, tool, file, pointer, url)`, `Finding(finding_id, kind, component_id, advisory_id,
aliases, anomaly_type, source_severity, fixed_versions, dependency_path, path_count, evidence_ids, state,
risk_level, risk_rule_id)` and `AgentClaim(claim_id, step, text, evidence_ids, kind, validated,
rejected_reason, uncertainty)`. Enums are fine (values are read as strings). `dependency_path` holds
component IDs. Checked against P5's `guardian/models.py` and P2's Grype/OSV fixtures.

`llm_status` is P5's `LlmStatus`: `ok` (at least one step produced claims; failed steps are listed in
`result.step_errors`), `failed` (every attempted step failed) or `unavailable` (no provider).

**Needed in `pyproject.toml` (P5):** `pyyaml` in `dependencies` (the design already lists it; the scorer
reads `scenario.yaml`) and `types-PyYAML` in the `dev` extras so `mypy --strict` passes.

## Holdout scenarios

Five planted cases live in `holdout-scenarios/`. Detector authors should not open that folder, so they are
not described here.
