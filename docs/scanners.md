# Scanners

## What the scanners do

- **Grype** checks the SBOM (the list of packages in the project) against a local copy of known-vulnerability data. It reports known CVEs in those packages.
- **OSV-Scanner** is a second opinion. It checks the same packages against the OSV database and also flags known malicious packages, whose IDs start with `MAL-`.
- **Syft** builds the SBOM that Grype reads. It runs as a Docker image, so no local install is needed.

## Setup

Run `scripts/prefetch.sh` once before the demo. It needs internet access once, to pull the Docker images and download the Grype vulnerability database. The database is cached in the Docker volume `guardian-grype-db`, so later runs do not need the download. The first download takes about 2 minutes 40 seconds.

OSV-Scanner has no local database. It queries `api.osv.dev` for each package at scan time, so the demo machine needs network access during scans too.

## Pinned versions

Images are pinned by digest, not by tag. Tag pulls can fail locally with a Docker credential-helper error.

| Image | Version | Digest |
|---|---|---|
| `anchore/grype` | 0.122.1 (DB schema v6.1.10) | `sha256:661583704a253c0448ed63998b5ea2cd9d5a76ee71eedc4aed439b8ce3e93a1c` |
| `ghcr.io/google/osv-scanner` | 2.7.1 | `sha256:a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde` |
| `anchore/syft` | 1.57.2 | `sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a` |

Each image can be overridden with the `GRYPE_IMAGE`, `OSV_IMAGE`, or `SYFT_IMAGE` environment variables.

## Gotchas

- **`--network host` is required on every `docker run`.** Without it, OSV-Scanner silently reports zero vulnerabilities.
- **The Grype image needs `--entrypoint /grype`.** Its default entrypoint is not the binary the script calls.
- **Grype needs `GRYPE_DB_CACHE_DIR=/root/.cache/grype`.** Without it, Grype writes the database to the container's home directory, not the volume, and `db status` reports that no database exists.
- **OSV-Scanner exits with code 1 when it finds vulnerabilities.** That is a normal result, not an error. Do not treat a non-zero exit as a crash.
- **Zero results are not proof of safety.** Zero findings can mean the scan failed, for example from a missing `--network host` or no network. Check that the scanner ran and produced output before reporting "no vulnerabilities".
