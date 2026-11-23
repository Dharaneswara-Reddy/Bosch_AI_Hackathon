#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${ROOT}/targets/juice-shop"
DEMO="${ROOT}/targets/juice-shop-suspicious"
OUT="${ROOT}/out"
PATCH="${ROOT}/demo/suspicious-change.patch"
GUARDIAN="${GUARDIAN:-python -m guardian.cli}"

demo_git() {
  git -C "${DEMO}" -c user.name="Guardian Demo" -c user.email="demo@example.invalid" "$@"
}

if [ ! -f "${SOURCE}/package-lock.json" ]; then
  echo "Run scripts/fetch_targets.sh first" >&2
  exit 1
fi
if [ -d "${DEMO}" ]; then
  echo "${DEMO} already exists; remove it to rebuild the demo" >&2
  exit 1
fi

echo "Copying Juice Shop to ${DEMO}"
cp -a "${SOURCE}" "${DEMO}"
demo_git checkout -q -b demo
demo_git add -f package-lock.json frontend/package-lock.json
demo_git commit -q -m "clean baseline: add generated lockfiles"

echo "Scanning the clean baseline"
${GUARDIAN} scan "${DEMO}" --out "${OUT}/demo-clean" --no-llm

echo "Applying the suspicious change"
demo_git apply "${PATCH}"
(cd "${DEMO}" && npm install --package-lock-only --ignore-scripts --package-lock=true)
demo_git add -A
demo_git commit -q -m "chore: add release helper, core-js dependency, bump base image"

echo "Scanning the suspicious commit against the baseline"
${GUARDIAN} scan "${DEMO}" --out "${OUT}/demo-suspicious" --baseline "${OUT}/demo-clean" --no-llm

echo "Diff:   git -C ${DEMO} show --stat HEAD"
echo "Report: ${OUT}/demo-suspicious/report.html"
