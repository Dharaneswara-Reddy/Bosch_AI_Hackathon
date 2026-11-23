#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGETS="${ROOT}/targets"
JUICE_URL="https://github.com/juice-shop/juice-shop.git"
JUICE_SHA="c9f9922"
RAILS_URL="https://github.com/OWASP/railsgoat.git"
RAILS_SHA="f5951f13089d85c979de09e7da3c8c0fb982f94a"

clone_at() {
  local url="$1" sha="$2" dir="$3"
  if [ -d "${dir}/.git" ]; then
    echo "Skipping ${dir}: already present"
    return
  fi
  echo "Cloning ${url} into ${dir}"
  git clone --filter=blob:none "${url}" "${dir}"
  git -C "${dir}" checkout "${sha}"
}

generate_lockfile() {
  local dir="$1"
  shift
  if [ -f "${dir}/package-lock.json" ]; then
    echo "Skipping ${dir}: package-lock.json already present"
    return
  fi
  echo "Generating package-lock.json in ${dir} (no install scripts run)"
  (cd "${dir}" && npm install --package-lock-only --ignore-scripts --package-lock=true "$@")
}

mkdir -p "${TARGETS}"
clone_at "${JUICE_URL}" "${JUICE_SHA}" "${TARGETS}/juice-shop"
clone_at "${RAILS_URL}" "${RAILS_SHA}" "${TARGETS}/railsgoat"
generate_lockfile "${TARGETS}/juice-shop"
generate_lockfile "${TARGETS}/juice-shop/frontend" --legacy-peer-deps
echo "fetch_targets complete: ${TARGETS}"
