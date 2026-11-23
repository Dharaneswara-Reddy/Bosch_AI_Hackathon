# Bosch Guardian - UI + API

React/Vite frontend and FastAPI backend on top of the team's `guardian` scan pipeline.
Enter a public GitHub URL, the backend fetches only dependency files through the GitHub API
(no `git clone`), generates missing npm lockfiles safely, then runs `guardian.runner.scan`
and the UI shows its real results.

## Requirements

- Python 3.11+, Node.js 20+, Docker (Syft, Grype and OSV-Scanner images, see `scripts/prefetch.sh`), npm
- `GITHUB_TOKEN` is recommended: unauthenticated GitHub API calls are limited to 60 per hour.
  Read from the environment by the backend only; it is never sent to the browser.

## Run

The backend imports the `guardian` package, so install the repository root in editable mode
into the same virtualenv as the API:

```bash
# from the repository root
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" -r Bosch_Guardian_Clean/backend/requirements.txt
export GITHUB_TOKEN=...            # optional but recommended
cd Bosch_Guardian_Clean/backend
python -m uvicorn app.main:app --port 8000
```

In a second terminal:

```bash
cd Bosch_Guardian_Clean/frontend
npm install
npm run dev        # http://127.0.0.1:5173, proxies /api to port 8000
```

Tests: `pytest` from the repository root (guardian) and from `Bosch_Guardian_Clean/backend` (API).

## Pipeline

`POST /scan {url, ref}` returns 202 and runs in a background thread:

1. `guardian.fetch.fetch_repo_files`: resolve ref to a commit SHA, read the git tree, download
   only manifests, lockfiles, Dockerfiles and workflow files into a per-scan directory,
   and write `fetch-manifest.json` (commit, paths, sha256, `repo` vs `generated`).
2. `guardian.prepare.generate_npm_lockfiles`: for npm folders without a lockfile run
   `npm install --package-lock-only --ignore-scripts` (retry with `--legacy-peer-deps`).
3. `guardian.runner.scan(repo_dir, out_dir, use_llm=False)`.

Scans live in `GUARDIAN_SCAN_DIR` (default: a fresh temporary directory). Each scan keeps a
`record.json`, and pending fix approvals are checkpointed in `checkpoints.sqlite` next to the scan
folders; both are reloaded on restart (a scan that was still running is marked failed). With the
default temporary directory nothing survives a restart, so set `GUARDIAN_SCAN_DIR` to keep state.

## API

| Endpoint | Purpose |
|---|---|
| `GET /scan/{id}` | status: `running`, `complete`, `partial` or `failed` (guardian's own status), stage, errors |
| `GET /scan/{id}/result` | findings, evidence, coverage, scan metadata, fetch manifest summary |
| `GET /scan/{id}/graph` | `graph.json` |
| `GET /scan/{id}/sbom` | CycloneDX SBOM download |
| `GET /scan/{id}/report` | full `report.html` |

## Limitations

- `git_diff` style checks that need history are not available: there is no clone.
- Only selected files are fetched, so source-level checks do not apply.
- Advisory matches are not proof of exploitability.
