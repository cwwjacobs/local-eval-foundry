"""Command-line entrypoint for explicit EvalFoundry benchmark runs."""

from __future__ import annotations

import argparse
import json
import sys

from .benchmark import run_benchmark, write_benchmark_report
from .cli import (
    _add_archive_argument,
    _add_model_arguments,
    _add_state_argument,
    _client_from_args,
    _signer_from_args,
    _vault_from_args,
)
from .errors import BudgetExceeded, EvalFoundryError
from .receipts import ReceiptStore
from .runner import RunEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evalfoundry-benchmark",
        description="Run a deterministic EvalFoundry subset or full split and write an aggregate receipt.",
    )
    _add_archive_argument(parser)
    _add_model_arguments(parser)
    _add_state_argument(parser)
    parser.add_argument("--split", choices=("eval", "challenge"), required=True)
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Number of cases. Omit to request the entire split.",
    )
    parser.add_argument(
        "--selection-seed",
        default="evalfoundry-benchmark-v1",
        help="Stable seed controlling deterministic case order.",
    )
    parser.add_argument(
        "--max-calls",
        type=int,
        required=True,
        help="Hard call budget. Must exactly equal the selected case count.",
    )
    parser.add_argument(
        "--confirm-full-split",
        action="store_true",
        help="Required when the requested count covers the complete split.",
    )
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--report", required=True, help="New JSON report path; never overwritten.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        vault = _vault_from_args(args)
        available = vault.split_sizes[args.split]
        requested = available if args.count is None else args.count
        if requested == available and not args.confirm_full_split:
            raise BudgetExceeded(
                f"Full split contains {available} model calls. Re-run with --confirm-full-split."
            )
        store = ReceiptStore(args.state_dir, signer=_signer_from_args(args))
        engine = RunEngine(vault, store, _client_from_args(args))
        report = run_benchmark(
            vault,
            engine,
            split=args.split,
            count=args.count,
            selection_seed=args.selection_seed,
            max_calls=args.max_calls,
            fail_fast=args.fail_fast,
        )
        report_path = write_benchmark_report(report, args.report)
        print(json.dumps(report | {"report_path": str(report_path)}, indent=2, sort_keys=True))
        return 0 if report["attempted_count"] == report["requested_count"] else 1
    except (EvalFoundryError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
