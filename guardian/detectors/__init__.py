"""Ecosystem-aware detector registry and public result type."""

from guardian.detectors._common import DetectionResult
from guardian.detectors.plugins import (
    DetectorPlugin,
    _run_ci_pin,
    _run_git_diff,
    _run_image_pin,
    _run_install_script,
    _run_sbom_diff,
    _run_typosquat,
    _run_unverified_source,
)

DETECTORS: dict[str, list[DetectorPlugin]] = {
    "any": [
        DetectorPlugin("sbom_diff", _run_sbom_diff),
        DetectorPlugin("git_diff", _run_git_diff),
        DetectorPlugin("image_pin", _run_image_pin),
        DetectorPlugin("ci_pin", _run_ci_pin),
    ],
    "npm": [
        DetectorPlugin("typosquat", _run_typosquat),
        DetectorPlugin("install_script", _run_install_script),
        DetectorPlugin("unverified_source", _run_unverified_source),
    ],
}

__all__ = ["DETECTORS", "DetectionResult", "DetectorPlugin"]
