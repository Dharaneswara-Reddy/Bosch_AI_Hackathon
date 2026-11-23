#!/usr/bin/env bash
set -euo pipefail

GRYPE_IMAGE="${GRYPE_IMAGE:-anchore/grype@sha256:661583704a253c0448ed63998b5ea2cd9d5a76ee71eedc4aed439b8ce3e93a1c}"
OSV_IMAGE="${OSV_IMAGE:-ghcr.io/google/osv-scanner@sha256:a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a}"
GRYPE_DB_VOLUME="guardian-grype-db"

pull_image() {
  local image="$1"
  echo "Pulling ${image}"
  if ! docker pull "${image}"; then
    echo "ERROR: could not pull ${image}. Check network access and Docker login, then retry." >&2
    exit 1
  fi
}

update_grype_db() {
  # Without GRYPE_DB_CACHE_DIR, grype writes to $HOME of the image, not the volume.
  docker run --rm --network host --entrypoint /grype \
    -e GRYPE_DB_CACHE_DIR=/root/.cache/grype \
    -v "${GRYPE_DB_VOLUME}:/root/.cache/grype" "${GRYPE_IMAGE}" db update
  docker run --rm --network host --entrypoint /grype \
    -e GRYPE_DB_CACHE_DIR=/root/.cache/grype \
    -v "${GRYPE_DB_VOLUME}:/root/.cache/grype" "${GRYPE_IMAGE}" db status
}

print_digests() {
  local image
  for image in "${GRYPE_IMAGE}" "${OSV_IMAGE}" "${SYFT_IMAGE}"; do
    echo "Digest: $(docker image inspect --format '{{index .RepoDigests 0}}' "${image}")"
  done
}

print_versions() {
  docker run --rm --network host --entrypoint /grype "${GRYPE_IMAGE}" version
  docker run --rm --network host "${OSV_IMAGE}" --version
}

for image in "${GRYPE_IMAGE}" "${OSV_IMAGE}" "${SYFT_IMAGE}"; do
  pull_image "${image}"
done

echo "Downloading Grype vulnerability database into volume ${GRYPE_DB_VOLUME}"
update_grype_db

echo "Image digests:"
print_digests

echo "Tool versions:"
print_versions

echo "prefetch complete"
