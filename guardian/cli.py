"""Command-line entry point for Guardian's scan and evaluation commands."""

import argparse
import sys
from collections.abc import Sequence
from importlib import import_module
from pathlib import Path

from guardian.models import ScanStatus
from guardian.runner import scan

EXIT_CODES = {ScanStatus.COMPLETE: 0, ScanStatus.PARTIAL: 2, ScanStatus.FAILED: 1}


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
            status = import_module("guardian.eval.scorer").evaluate(args.scenarios_dir, args.base)
            return int(status)
        result = scan(
            args.target, args.out, args.baseline, not args.no_llm, inject_claim=args.inject_claim,
        )
    except (OSError, ValueError, RuntimeError, ImportError) as error:
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
