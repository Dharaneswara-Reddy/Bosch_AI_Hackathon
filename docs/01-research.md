# Research: Existing Tools for the Supply Chain Guardian

Date: 2026-11-23. Method: `/search-first` (adopt before build). Problem statement: [00-problem-statement.md](00-problem-statement.md).

**Caveat:** web sources disagreed on several version numbers. Before pinning any tool, check its GitHub releases page. "(unverified)" marks a claim that wasn't confirmed against a primary source.

## Design rule this research supports

The core must not depend on any one ecosystem. Every input gets converted to a **CycloneDX SBOM**, with each component named by a **package URL (purl)**. Checks then run on that common model. Ecosystem-specific logic lives only in plugins.

## Local environment (checked)

- Installed: Docker 28.5, Podman 5.6, Python 3.11, Node 22 / npm 10, Go, Java 21, `gh` (logged in), ripgrep.
- Missing: syft, grype, trivy, osv-scanner, cdxgen, Maven, cosign, OPA, Conftest. All are available as Docker images or single binaries.

## Recommended stack (adopt)

| Capability | Tool | Why | Notes |
|---|---|---|---|
| SBOM, containers and OS packages | **Syft** (Apache-2.0) | Broad ecosystem and image coverage; outputs CycloneDX/SPDX | Issue anchore/syft#2832: CycloneDX JSON may omit dependency edges. Verify on the sample repo |
| SBOM, source repo with full graph | **cdxgen** (Apache-2.0) | Widest source-repo coverage (npm, PyPI, Maven/Gradle, Go, Cargo, NuGet, Ruby, Composer, Conan); emits CycloneDX `dependencies` | npm package renamed `@cdxgen/cdxgen` in v13 |
| Vulnerabilities from SBOM | **Grype** (Apache-2.0) | Reads CycloneDX; gives fixed versions and CVSS; EPSS/KEV ratings since v0.96 | Needs one online `grype db update`. Download the database before the demo |
| Malicious packages, second opinion | **OSV-Scanner** + **ossf/malicious-packages** | Reads CycloneDX (v2.4+); full offline mode; malicious DB covers typosquats and account takeovers across ecosystems | Check the data license before redistributing |
| npm/PyPI heuristics (install scripts, etc.) | **GuardDog** (DataDog) | Heuristics for install scripts and suspicious code; v3 adds YARA rules | npm and PyPI only. Pin to the version you test |
| CI/CD workflow risk | **zizmor** | Catches unpinned actions, `pull_request_target`, template injection, credential persistence; SARIF/JSON output | Poutine is a second opinion for GitLab CI |
| Dockerfile / image config | **hadolint** + **Trivy config** | DL3007 (`latest` tag) and misconfiguration checks | hadolint is GPL-3.0: run it as a separate CLI, never link it in. Digest-pinning check not confirmed, so write a small rule for it |
| SBOM diff (before/after, lockfile change) | **sbom-tools** or **cyclonedx-cli diff** | Works on any ecosystem: diffs added, removed and changed components | Versions unverified |
| Graph view | **Cytoscape.js** | Renders the CycloneDX `dependencies` graph | We build a thin renderer |

Skipped for Day 1: Dependency-Track (5.x needs PostgreSQL), Socket CLI (needs an API token, not offline), OpenSSF Package Analysis (heavy infrastructure), Microsoft sbom-tool (SPDX only), actionlint (not a security tool), Phylum (commercial).

## Gaps no tool fills (we build these)

1. Malicious-package and install-script checks outside npm and PyPI.
2. Typosquat detection for each ecosystem beyond the OSV database and GuardDog (needs a list of popular package names per registry).
3. Dependency-path explanation: walk from the root to the vulnerable component, even when an SBOM's graph is partial.
4. One explainable risk score combining CVSS, EPSS, KEV, malicious flags and scope (dev or prod), with a confidence level.
5. C/C++ (Conan, vcpkg, vendored code) and standalone binaries, where Syft and Trivy coverage is partial.
6. A per-ecosystem coverage table: which checks ran and which were skipped, reported honestly.

## Pitfalls

- **Reported Trivy compromise (unverified):** a malicious v0.69.4 is reported for March 2026 (CVE-2026-33634), with tampered `trivy-action` tags. If using Trivy, pin an exact verified version (≥0.70.0), check checksums, and pin actions by SHA. A supply-chain guardian whose own scanners aren't pinned and verified fails its own trust test.
- Vulnerability databases need internet on first use. Download them and freeze them for a reproducible demo.
- NVD API limits only matter if NVD is queried directly. Grype and OSV use local databases.
- deps.dev quota is unverified. Cache its responses.
- The sample repo (OWASP Juice Shop) commits no lockfile. Generate one and freeze it as the baseline, or SBOMs will change from run to run.

## Sources

- Syft: https://github.com/anchore/syft · https://github.com/anchore/syft/issues/2832
- cdxgen: https://github.com/CycloneDX/cdxgen
- Grype: https://github.com/anchore/grype
- OSV-Scanner: https://github.com/google/osv-scanner · https://google.github.io/osv-scanner/usage/offline-mode
- ossf/malicious-packages: https://github.com/ossf/malicious-packages
- GuardDog: https://github.com/DataDog/guarddog
- zizmor: https://github.com/zizmorcore/zizmor
- Poutine: https://github.com/boostsecurityio/poutine
- OpenSSF Scorecard: https://github.com/ossf/scorecard
- hadolint: https://github.com/hadolint/hadolint
- Dependency-Track: https://docs.dependencytrack.org
- deps.dev: https://docs.deps.dev/api/
- sbom-tools: https://docs.rs/crate/sbom-tools/latest
- Socket rate limits: https://docs.socket.dev/reference/rate-limits
