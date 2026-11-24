# Software Supply Chain Guardian

Guardian takes a repository from discovery to verified remediation: SBOM and dependency graph → known vulnerabilities and suspicious changes → explainable risk with a confidence score → AI explanations checked against evidence → human review → an approved fix that is built, tested and rescanned in a sandbox → an evidence-based report.

![Guardian architecture](docs/architecture-v2.png)

- [Responsible AI & Security note](docs/responsible-ai-security.md): where AI is used, how hallucinations are controlled, what needs human approval, how secrets are protected.
- [Architecture v2 design](docs/designs/guardian-v2-architecture.md): the reasoning behind the risk engine, confidence score and agents.

## Web UI quick start

You need Python 3.11+, Node.js 20+, Docker or Podman (scanner images and the fix sandbox), and npm.

```sh
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]' -r Bosch_Guardian_Clean/backend/requirements.txt
bash scripts/prefetch.sh                # scanner images and the Grype database
cp .env.example .env                    # then fill in the keys you have (see below)

cd Bosch_Guardian_Clean/backend && python -m uvicorn app.main:app --port 8000
# second terminal
cd Bosch_Guardian_Clean/frontend && npm install && npm run dev   # http://127.0.0.1:5173
```

| Setting in `.env` | Purpose |
|---|---|
| `GUARDIAN_LLM_PROVIDER` | `groq`, or `none` for a fully offline run (the risk engine and rule-based fixes still work) |
| `GUARDIAN_LLM_API_KEY` | Key for the primary provider |
| `GUARDIAN_LLM_FALLBACKS`, `GEMINI_API_KEY` | Fallback chain, e.g. `gemini`, used when the primary fails or is rate-limited |
| `GITHUB_TOKEN` | Optional; raises the GitHub API limit from 60 requests per hour. Stays in the backend |
| `GUARDIAN_SCAN_DIR` | Where scans, decisions and fix runs are stored |
| `GUARDIAN_SANDBOX_DNS` | Optional DNS server (e.g. `1.1.1.1`) for the sandbox's package-install container. Set it when containers cannot resolve hosts, as on hosts that use systemd-resolved's `127.0.0.53` |
| `GUARDIAN_AI_MIN_RISK`, `GUARDIAN_LLM_CONCURRENCY` | Lowest risk level sent to the AI (default `medium`) and the number of parallel AI branches (default 4) |

### Demo walkthrough (Day 2 flow)

1. **Scan.** Click **Scan the built-in demo app** (local, no network), or paste a public GitHub URL. Fill in **Compare with** to see what changed since an older tag.
2. **Prioritize.** The findings are ranked Critical → Low. Click one to see **Why this risk?**: exploitation, scope, attack vector, impact, the SSVC decision, the confidence score and any AI adjustment.
3. **Review.** The **Review queue** tab lists the uncertain findings. Confirm, dismiss (records an accepted risk, so a note is required) or escalate each one.
4. **Fix.** The **Fixes** tab shows each proposed fix with its expected risk reduction, rollback and compatibility risk. Click **Approve**: the LangGraph workflow resumes from its pause, applies the fix in a sandbox, builds, runs the tests in a no-network container, rescans and shows before vs. after.
5. **Report.** **Open full report** (`report.html`) or download `report.json`. Both cover the original findings and evidence, the approved actions, the validation results, the remaining and accepted risks, and the audit trail.

With the demo app:
- Approving **lodash 4.17.4 → 4.18.0** gives Build ✓, Tests ✓ (7 of 7) and Rescan ✓. It fixes 9 CVEs and reports the one new CVE that 4.18.0 brings in.
- Approving **express-jwt 0.1.3 → 6.0.0** fails 4 of 7 tests because of a real breaking API change. The fix is marked "not safe to apply", and the rescan results are still shown.

## Known limitations

- **Ecosystems.** Fixes can be applied for npm, pip (`requirements*.txt`) and Bundler (`Gemfile`).
  - Packages pulled in by another package (transitive) can only be fixed for npm, by upgrading the parent or adding an `overrides` entry.
  - Poetry/pyproject, yarn and pnpm are not handled.
  - The lockfile-integrity detector reads npm `package-lock.json` only.
- **Build and tests.**
  - They run in a `node:20-slim` container, so this works for npm projects only.
  - The source mount is read-only, so a build that writes into the source tree (for example `dist/`) fails.
  - If the container install step fails, build and tests show "not run" with the reason; the fix is not marked failed.
- **Running the fixed app.**
  - After the tests pass, a project with a `Dockerfile` is built into `guardian-fix-<proposal id>:latest` and started on `127.0.0.1` (ephemeral port, read-only, capabilities dropped, CPU/memory/pid limits). Guardian waits for `GET /health` to return 2xx, then removes the container. If it never answers, the fix is marked failed ("App did not start").
  - The built image is exported with `docker save` and scanned by the pinned Grype offline; findings that are not in the source rescan are listed as image-only (counts and the top 10 ids).
  - The port is taken from the `Dockerfile` `EXPOSE` line (default 3000); the app must listen on `0.0.0.0` inside the container. Override the route with `GUARDIAN_APP_HEALTH_PATH` (default `/health`).
  - `docker build` has no `--dns` flag, so when `GUARDIAN_SANDBOX_DNS` is set the build uses the host network. Built images are kept; remove them with `docker rmi`.
- **GitHub scans.**
  - Full source is cloned only after a fix is approved: shallow clone, 150 MB cap, public repositories only.
  - If the clone fails, the fix is validated from manifests alone and says "tests not run" with the git error.
- **"Compare with"** runs a second scan of the older version. The result is cached per repository and commit, with a time limit set by `GUARDIAN_BASELINE_TIMEOUT` (default 600 s).
- **AI quota.**
  - On free tiers, Groq and Gemini rate limits can run out mid-scan.
  - The fix planner gets its own retry budget (`GUARDIAN_LLM_PLANNER_TIMEOUT`) and retries the providers.
  - If it still fails, the UI says "AI planner unavailable (rate limited) — rule-based fixes shown".
  - Only Groq waits for the provider's Retry-After header.
- **Persistence.** Scans, review decisions, fix runs and pending approvals survive a backend restart only when `GUARDIAN_SCAN_DIR` points to a permanent folder. The default is a temporary folder.
- **Scores.** The final confidence for a verified fix is a simple rule: tests passed, and no new findings. The expected risk reduction is calculated from scanner fix data; the rescan gives the actual result.
- **Reachability** needs source code, so it is "unknown" for GitHub scans, which fetch manifests only.

## Setup

Use Python 3.11 or later and Docker for live scanner stages.

```sh
python -m pip install -e '.[dev]'
python -m pytest
python -m scripts.generate_schemas
```

The demo targets in the team plan are Juice Shop (`c9f9922`) and RailsGoat (`f5951f1`). The scanner versions verified by the team are Grype `0.122.1` and OSV-Scanner `2.7.1`.

Copy `.env.example` to `.env` for local settings. Run `bash scripts/prefetch.sh` for the pinned images and Grype database. OSV queries its advisory service during scans. See [scanner setup](docs/scanners.md) for details. The report records the tool metadata from each run. Leave the AI provider as `none` for an offline demo.

## Run a local scan

```sh
guardian scan targets/juice-shop --out artifacts/juice-shop --no-llm
guardian scan targets/railsgoat --out artifacts/second-target --no-llm
```

Open `report.html` inside each output folder. The same folder contains the JSON artifacts and the Markdown report. Exit codes are 0 for complete, 2 for partial, and 1 for failed. Review the scan header for any missing stages.

## Relevance, entry paths and the demo app

Every vulnerability is traced from the application to the vulnerable package (each hop, the
direct dependency that introduces it, number of paths, production or dev scope) and given a
relevance verdict from recorded signals: relevant, likely relevant, unknown or low relevance.
The verdict never says "safe". `demo/vulnerable-app` is a local, deliberately vulnerable app
with a synthetic malicious-style package for the live demo:

```sh
guardian scan demo/vulnerable-app --out artifacts/demo --no-llm
```

Safety rules, the open-source inventory and the changelog: [demo app](demo/vulnerable-app/README.md),
[open-source components](docs/open-source.md), [changes](docs/changes.md).

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
