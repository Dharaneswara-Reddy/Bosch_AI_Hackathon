# Bosch Guardian — Clean UI + API

A single full-stack prototype: React/Vite frontend and FastAPI backend. White and green design, public GitHub URL scanning, evidence-based dependency inventory, OSV vulnerability matching, graph visualization, and CycloneDX 1.5 SBOM export.

## Requirements

- Python 3.11+ (3.12 recommended)
- Node.js 20+
- Internet connection for public GitHub API and OSV

## Quick start (macOS / Linux)

**Terminal 1 — API**

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

API docs: http://127.0.0.1:8000/docs

**Terminal 2 — frontend**

```bash
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173

The frontend uses a Vite `/api` proxy, so no environment variable or separate CORS setup is needed for local development.

## Workflow

1. Enter a public GitHub URL such as `https://github.com/expressjs/express`.
2. The backend pins the selected ref to a commit SHA, retrieves a Git tree, and fetches **only supported manifests/lockfiles** (not the full repository).
3. Parse npm lockfile/package.json and Python requirements/pyproject declarations; unresolved versions are clearly marked.
4. Optionally check *exact resolved versions* using OSV's batch API.
5. Review inventory, dependency graph, advisories, evidence, and download CycloneDX JSON.

## Current scope and honest limitations

- **No autonomous LLM agent is implemented.** `/scan/{id}/recommendations` provides advisory-linked, rule-based review actions. The backend separates this so an agentic layer can be added without replacing the UI.
- **No source-code reachability analysis**; advisory matches do not prove exploitability.
- npm `package-lock.json` v2/v3 `packages` map is supported. Graph edges may be incomplete for complex nested/hoisted dependency layouts. No Maven/Gradle/Poetry support in this version.
- npm package.json-only dependencies and unpinned Python dependencies are not assumed to have resolved versions.
- GitHub public repositories only. No arbitrary remote URL fetching, private repo access, or code execution.
- GitHub API unauthenticated rate limits apply. Optionally export `GITHUB_TOKEN` in the backend shell. Never put the token in the frontend.
- Scan state is in memory and is lost when the API restarts; for deployment add persistence and a job queue.
- This is a fresh implementation based on the described workflow, **not a verified merge of earlier local folders**.

## Test

```bash
cd backend
python -m pytest -q
```

## API

- `GET /health`
- `POST /scan` JSON `{ "url": "https://github.com/expressjs/express", "ref": "", "check_vulnerabilities": true }`
- `GET /scan/{id}`
- `GET /scan/{id}/inventory`
- `GET /scan/{id}/graph`
- `GET /scan/{id}/sbom`
- `GET /scan/{id}/recommendations`

## Next iteration

Integrate the original scanner modules (if available), add Maven/Gradle and lockfile parsers, persist scans, fetch OSV advisory details, and introduce a tool-using remediation agent with human approval and test validation. Avoid sending whole repositories into an LLM.
