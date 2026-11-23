# Open-source components

Everything the Software Supply Chain Guardian uses, what it is for, and what we changed.
"Tested" is the version the test suite ran against on 2026-11-23; "required" is the range
declared in the project files. Check the linked release pages before upgrading any pin.

## Scanners (run as pinned Docker images)

| Tool | Version | License | Used for | Pin (image digest) | Our changes / configuration |
|---|---|---|---|---|---|
| [Syft](https://github.com/anchore/syft) | 1.57.2 | Apache-2.0 | CycloneDX SBOM of the target | `anchore/syft@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a` | None to the tool. We add our lockfile-resolver edges to its SBOM as `guardian:resolver-edge` properties (`guardian/sbom.py`). |
| [Grype](https://github.com/anchore/grype) | 0.122.1 (DB schema v6.1.10) | Apache-2.0 | Known vulnerabilities from the SBOM; affected version ranges, fixed versions | `anchore/grype@sha256:661583704a253c0448ed63998b5ea2cd9d5a76ee71eedc4aed439b8ce3e93a1c` | Run with `--entrypoint /grype` and an offline database volume (`scripts/prefetch.sh`). Database build date is recorded in `run.json` (`GUARDIAN_GRYPE_DB_BUILT_AT`). |
| [OSV-Scanner](https://github.com/google/osv-scanner) | 2.7.1 | Apache-2.0 | Second vulnerability opinion and `MAL-` malicious-package entries | `ghcr.io/google/osv-scanner@sha256:a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde` | Run with `--network host` (DNS issue in default networking). Queries `api.osv.dev` live; the query time is recorded as its database date. |

Advisory data: [OSV.dev](https://osv.dev) (CC-BY 4.0 for most sources) and the Grype
vulnerability database (Anchore, built from NVD, GitHub Security Advisories and others).

## Python (package `guardian`, `pyproject.toml`)

| Library | Required | Tested | License | Used for |
|---|---|---|---|---|
| [Pydantic](https://github.com/pydantic/pydantic) | >=2 | 2.13.5 | MIT | Data contract (`guardian/models.py`), validation of every input and LLM reply |
| [NetworkX](https://github.com/networkx/networkx) | >=3 | 3.7 | BSD-3-Clause | Dependency graph, shortest paths, path counts |
| [Jinja2](https://github.com/pallets/jinja) | >=3.1 | 3.1.6 | BSD-3-Clause | `report.html` / `report.md` templates |
| [PyYAML](https://github.com/yaml/pyyaml) | >=6 | 6.0.3 | MIT | Holdout `scenario.yaml` files |
| [RapidFuzz](https://github.com/rapidfuzz/RapidFuzz) | >=3 | 3.14.6 | MIT | Edit distance for the typosquat detector |
| [LangGraph](https://github.com/langchain-ai/langgraph) | >=1.0 | 1.2.24 | MIT | Orchestration of the AI agents (`guardian/ai/graph.py`) |
| [LangChain Core](https://github.com/langchain-ai/langchain) | >=1.0 | 1.8.4 | MIT | Chat-model interface used by the LLM adapter |
| [langchain-groq](https://github.com/langchain-ai/langchain) | >=1.0 | 1.2.1 | MIT | Groq chat model (`ChatGroq`) |
| [groq](https://github.com/groq/groq-python) (pulled in by langchain-groq) | – | 1.7.0 | Apache-2.0 | HTTP client for the Groq API |

Development tools: [pytest](https://github.com/pytest-dev/pytest) 9.1.1 (MIT),
[Ruff](https://github.com/astral-sh/ruff) 0.17.6 (MIT), [mypy](https://github.com/python/mypy)
2.3.1 (MIT), types-PyYAML 6.0.12 (Apache-2.0).

## UI backend (`Bosch_Guardian_Clean/backend`)

| Library | Required | Tested | License | Used for |
|---|---|---|---|---|
| [FastAPI](https://github.com/fastapi/fastapi) | >=0.115,<1 | 0.165.0 | MIT | Scan API |
| [Uvicorn](https://github.com/encode/uvicorn) | >=0.30,<1 | 0.54.0 | BSD-3-Clause | ASGI server |
| [HTTPX](https://github.com/encode/httpx) | >=0.27,<1 | 0.28.1 | BSD-3-Clause | GitHub API client, test client |

## UI frontend (`Bosch_Guardian_Clean/frontend`)

| Library | Required | Locked | License | Used for |
|---|---|---|---|---|
| [React](https://github.com/facebook/react) / react-dom | ^18.3.1 | 18.3.1 | MIT | UI |
| [React Flow](https://github.com/xyflow/xyflow) (`@xyflow/react`) | ^12.8.0 | 12.12.1 | MIT | Dependency graph view and path highlighting |
| [Lucide](https://github.com/lucide-icons/lucide) (`lucide-react`) | ^0.468.0 | 0.468.0 | ISC | Icons |
| [Vite](https://github.com/vitejs/vite) + `@vitejs/plugin-react` | ^6.0.5 / ^4.3.4 | 6.4.6 / 4.7.0 | MIT | Dev server and build |

## Other tools and data

| Item | License | Used for | Notes |
|---|---|---|---|
| [npm](https://github.com/npm/cli) (with Node.js) | Artistic-2.0 | Generating missing lockfiles | Always `--package-lock-only --ignore-scripts`: install scripts never run |
| [Docker](https://www.docker.com/) | Apache-2.0 (Engine) | Running the pinned scanner images | Local only |
| [npm-high-impact](https://github.com/wooorm/npm-high-impact) 1.13.0 | MIT | `data/popular/npm.txt` (top 5,000 names) for the typosquat detector | Names only, unmodified; captured 2026-11-23 |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) @ `c9f99228` | MIT | Demo target and holdout base | Scanned locally; never attacked |
| [OWASP RailsGoat](https://github.com/OWASP/railsgoat) @ `f5951f13` | MIT | Second-language demo target | Scanned locally |
| npm registry packages in `demo/vulnerable-app` (express-jwt 0.1.3, lodash 4.17.4, minimist 0.0.8 and their dependencies) | MIT | Known-vulnerable versions for the demo app | Lockfile only; never installed or run by the Guardian |

## AI model (service, not bundled)

| Item | License | Used for | Notes |
|---|---|---|---|
| `openai/gpt-oss-120b` on [Groq](https://console.groq.com) | Apache-2.0 (model weights) | LLM agents (analysts, critic, planner, report writer) | Called over Groq's API with strict structured outputs; API key from `.env` only. Optional: every scan works without it. |

## What we modified

We did not modify the source code of any third-party tool. Our own work is the
Guardian code around them; see [changes.md](changes.md) for what we built and why.
