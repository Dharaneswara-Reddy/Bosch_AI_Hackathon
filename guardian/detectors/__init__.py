"""Detector registry and public result type."""

from guardian.detectors import ci_pin, git_diff, image_pin, install_script, sbom_diff, typosquat
from guardian.detectors._common import DetectionResult

DETECTORS = {
    "any": {
        "sbom_diff": sbom_diff.detect,
        "git_diff": git_diff.detect,
        "image_pin": image_pin.detect,
        "ci_pin": ci_pin.detect,
    },
    "npm": {
        "typosquat": typosquat.detect,
        "install_script": install_script.detect,
    },
}

__all__ = ["DETECTORS", "DetectionResult"]
