"""Command-line entry point for Guardian's scan and evaluation commands."""

import argparse
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

import yaml

from guardian.eval.scorer import ObservedFinding, run_eval
from guardian.models import ScanStatus
from guardian.runner import scan

EXIT_CODES = {ScanStatus.COMPLETE: 0, ScanStatus.PARTIAL: 2, ScanStatus.FAILED: 1}


def _eval_scan(target: Path) -> list[ObservedFinding]:
    with tempfile.TemporaryDirectory(prefix="guardian-eval-") as out:
        result = scan(target, Path(out) / "run", use_llm=False)
    return [
        ObservedFinding(kind=f.kind.value, anomaly_type=f.anomaly_type, purl=f.purl)
        for f in result.findings
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="Analyze a local repo or pinned image.")
    scan_parser.add_argument("target")
    scan_parser.add_argument("--out", type=Path, required=True)
    scan_parser.add_argument("--baseline", type=Path)
    scan_parser.add_argument("--no-llm", action="store_true")
    scan_parser.add_argument("--inject-claim", type=Path)
    evaluate = commands.add_parser("eval", help="Evaluate holdout detector scenarios.")
    evaluate.add_argument("scenarios_dir", type=Path)
    evaluate.add_argument("--base", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "eval":
            return run_eval(args.scenarios_dir, args.base, _eval_scan)
        result = scan(
            args.target, args.out, args.baseline, not args.no_llm, inject_claim=args.inject_claim,
        )
    except (OSError, ValueError, RuntimeError, ImportError, yaml.YAMLError) as error:
        print(f"guardian: {error}", file=sys.stderr)
        return 1
    report = args.out / "report.html"
    destination = report if report.is_file() and "report" not in result.scan.errors else args.out
    print(f"{result.scan.status}: {destination}")
    for stage, reason in result.scan.errors.items():
        print(f"{stage}: {reason}", file=sys.stderr)
    return EXIT_CODES[result.scan.status]


if __name__ == "__main__":
    raise SystemExit(main())
