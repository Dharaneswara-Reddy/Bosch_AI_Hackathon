# Holdout scenarios (P4 only)

Planted test cases for measuring the anomaly detectors fairly. **Detector authors (P3) must not read this folder**;
use `dev-scenarios/` for tuning instead.

Each scenario: `scenario.yaml` (description, base target, author), `overlay/` (files copied over a temporary copy of
the base target) and `expected.json` (the anomaly findings the overlay must produce, matched on kind, anomaly type and
package name; versions are ignored).

Run: `guardian eval holdout-scenarios --base targets/juice-shop`

Each scenario was checked by resolving the real lockfile (`npm install --package-lock-only --ignore-scripts`) for the
clean base (Juice Shop `c9f99228`) and for the scenario: every overlay changes exactly the planted package and
nothing else in the 1,250-package tree.
