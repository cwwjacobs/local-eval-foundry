"""Command-line entrypoints for the UI-independent EvalFoundry core."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .errors import EvalFoundryError
from .http_api import ApiContext, serve
from .model_client import OpenAICompatibleClient
from .models import ModelConfig
from .receipts import ReceiptStore
from .runner import RunEngine
from .training import build_trace_sft
from .vault import (
    APPROVED_AGENT_OPS_PUBLIC_V1_SHA256,
    APPROVED_FROZEN_ARCHIVE_SHA256,
    APPROVED_POLICY_GATE_PUBLIC_V1_SHA256,
    APPROVED_TOOL_CONTRACT_PUBLIC_V1_SHA256,
    PACK_KIND_AGENT_OPS,
    PACK_KIND_POLICY_GATE,
    PACK_KIND_TOOL_CONTRACT,
    DatasetVault,
)


def _json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _add_archive_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--archive",
        required=True,
        help="Path to a frozen evaluation ZIP (NVD V1 or agent-ops-public-v1).",
    )
    parser.add_argument(
        "--expected-sha256",
        default=None,
        help=(
            "Approved archive SHA-256. Defaults to the NVD frozen V1 pin, or the "
            "agent-ops public pin when --pack agent_ops is set."
        ),
    )
    parser.add_argument(
        "--pack",
        choices=("nvd", "agent_ops", "policy_gate", "tool_contract", "auto"),
        default="auto",
        help="Pack family hint for default SHA pin (default: auto from archive contract).",
    )
    parser.add_argument(
        "--allow-unpinned-archive",
        action="store_true",
        help="Allow a different self-consistent archive. Its receipt will be marked unpinned.",
    )


def _add_model_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model-endpoint", required=True, help="Local model-provider base URL.")
    parser.add_argument("--model", required=True, help="Loaded local model identifier.")
    parser.add_argument(
        "--model-transport",
        choices=("openai_compatible", "lm_studio_chat"),
        default="openai_compatible",
        help="Explicit provider transport (default: openai_compatible).",
    )
    parser.add_argument("--max-tokens", type=int, default=220)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout-seconds", type=int, default=45)
    parser.add_argument("--seed", type=int, default=None, help="Optional provider sampling seed.")
    parser.add_argument(
        "--allow-remote-model",
        action="store_true",
        help="Explicitly permit a non-loopback model endpoint. Disabled by default.",
    )


def _add_state_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state-dir",
        default="state",
        help="Directory for SQLite state and JSON receipts (default: ./state).",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evalfoundry",
        description="Local, split-safe CVE evaluation engine with receipts.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify", help="Verify archive integrity and all rubric traces.")
    _add_archive_argument(verify)
    verify.add_argument("--fast", action="store_true", help="Skip the 10,000-record rubric replay.")

    select = subparsers.add_parser("select", help="Select blind diagnostic cases deterministically.")
    _add_archive_argument(select)
    select.add_argument("--split", choices=("eval", "challenge"), required=True)
    select.add_argument("--count", type=int, default=1)
    select.add_argument("--selection-seed", default=None)

    case = subparsers.add_parser("case", help="Print one blind, model-safe case.")
    _add_archive_argument(case)
    case.add_argument("--split", choices=("eval", "challenge"), required=True)
    case.add_argument("--case-id", required=True)

    trace_sft = subparsers.add_parser(
        "build-trace-sft", help="Explicitly derive structured trace SFT from train records only."
    )
    _add_archive_argument(trace_sft)
    trace_sft.add_argument(
        "--output",
        required=True,
        help="New .jsonl path; EvalFoundry refuses to overwrite an existing artifact.",
    )

    run = subparsers.add_parser("run", help="Make one explicit local-model call and save a receipt.")
    _add_archive_argument(run)
    _add_model_arguments(run)
    _add_state_argument(run)
    run.add_argument("--split", choices=("eval", "challenge"), required=True)
    run.add_argument("--case-id", required=True)
    run.add_argument("--selection-seed", default=None)

    server = subparsers.add_parser("serve", help="Start the loopback JSON API for any UI.")
    _add_archive_argument(server)
    _add_model_arguments(server)
    _add_state_argument(server)
    server.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "localhost"))
    server.add_argument("--port", type=int, default=8765)
    server.add_argument(
        "--allow-origin",
        default=None,
        help="Optional exact browser origin for CORS. Omit when the UI is served with this app.",
    )
    return parser


def _client_from_args(args: argparse.Namespace) -> OpenAICompatibleClient:
    return OpenAICompatibleClient(
        ModelConfig(
            endpoint=args.model_endpoint,
            model=args.model,
            timeout_seconds=args.timeout_seconds,
            max_tokens=args.max_tokens,
            temperature=args.temperature,
            seed=args.seed,
            allow_remote=args.allow_remote_model,
            transport=args.model_transport,
        )
    )


def _sniff_pack_kind(archive_path: str) -> str:
    """Read PACK_CONTRACT.json if present; otherwise treat as NVD-shaped."""
    import zipfile

    path = Path(archive_path)
    try:
        with zipfile.ZipFile(path) as zf:
            matches = [n for n in zf.namelist() if n.endswith("reports/PACK_CONTRACT.json")]
            if len(matches) != 1:
                return "nvd_source_priority_v1"
            contract = json.loads(zf.read(matches[0]).decode("utf-8"))
            return str(contract.get("pack_kind") or "nvd_source_priority_v1")
    except Exception:
        return "nvd_source_priority_v1"


def _vault_from_args(args: argparse.Namespace) -> DatasetVault:
    pack_flag = getattr(args, "pack", "auto")
    sniffed = _sniff_pack_kind(args.archive)

    if args.allow_unpinned_archive:
        expected = None
    elif args.expected_sha256:
        expected = args.expected_sha256
    elif pack_flag == "tool_contract" or sniffed == PACK_KIND_TOOL_CONTRACT:
        expected = APPROVED_TOOL_CONTRACT_PUBLIC_V1_SHA256 or None
    elif pack_flag == "policy_gate" or sniffed == PACK_KIND_POLICY_GATE:
        expected = APPROVED_POLICY_GATE_PUBLIC_V1_SHA256 or None
    elif pack_flag == "agent_ops" or sniffed == PACK_KIND_AGENT_OPS:
        expected = APPROVED_AGENT_OPS_PUBLIC_V1_SHA256 or None
    elif pack_flag == "nvd":
        expected = APPROVED_FROZEN_ARCHIVE_SHA256
    else:
        expected = APPROVED_FROZEN_ARCHIVE_SHA256

    vault = DatasetVault(args.archive, expected_sha256=expected, strict_contract=True)
    if pack_flag == "agent_ops" and vault.pack_kind != PACK_KIND_AGENT_OPS:
        raise EvalFoundryError(
            f"--pack agent_ops requires an agent_ops archive; got pack_kind={vault.pack_kind!r}"
        )
    if pack_flag == "policy_gate" and vault.pack_kind != PACK_KIND_POLICY_GATE:
        raise EvalFoundryError(
            f"--pack policy_gate requires a policy_gate archive; got pack_kind={vault.pack_kind!r}"
        )
    if pack_flag == "tool_contract" and vault.pack_kind != PACK_KIND_TOOL_CONTRACT:
        raise EvalFoundryError(
            f"--pack tool_contract requires a tool_contract archive; got pack_kind={vault.pack_kind!r}"
        )
    if pack_flag == "nvd" and vault.pack_kind in (
        PACK_KIND_AGENT_OPS,
        PACK_KIND_POLICY_GATE,
        PACK_KIND_TOOL_CONTRACT,
    ):
        raise EvalFoundryError(f"--pack nvd was set but archive is {vault.pack_kind}")
    return vault


def _engine_from_args(args: argparse.Namespace) -> tuple[DatasetVault, ReceiptStore, RunEngine]:
    vault = _vault_from_args(args)
    store = ReceiptStore(args.state_dir)
    engine = RunEngine(vault, store, _client_from_args(args))
    return vault, store, engine


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "verify":
            vault = _vault_from_args(args)
            if args.fast or vault.pack_kind in (
                PACK_KIND_AGENT_OPS,
                PACK_KIND_POLICY_GATE,
                PACK_KIND_TOOL_CONTRACT,
            ):
                # contract packs have no 10k full canonical; load-time revalidated.
                _json(
                    {
                        "status": "PASS",
                        "pack_kind": vault.pack_kind,
                        "public_safe": bool((vault.pack_contract or {}).get("public_safe")),
                        "archive_sha256": vault.archive_sha256,
                        "manifest_entries_verified": len(vault._manifest),
                        "record_counts": vault.split_sizes,
                        "rubric_alignment": "load_time"
                        if vault.pack_kind
                        in (
                            PACK_KIND_AGENT_OPS,
                            PACK_KIND_POLICY_GATE,
                            PACK_KIND_TOOL_CONTRACT,
                        )
                        else "not_run",
                    }
                )
            else:
                _json(vault.verify_deep().as_dict())
            return 0

        if args.command == "select":
            vault = _vault_from_args(args)
            seed, cases = vault.select_cases(args.split, args.count, args.selection_seed)
            _json(
                {
                    "scope": "diagnostic",
                    "split": args.split,
                    "selection_seed": seed,
                    "full_split_size": vault.split_sizes[args.split],
                    "cases": [case.model_payload() for case in cases],
                }
            )
            return 0

        if args.command == "case":
            vault = _vault_from_args(args)
            case = vault.get_case(args.split, args.case_id)
            _json(case.model_payload() | {"split": case.split})
            return 0

        if args.command == "build-trace-sft":
            vault = _vault_from_args(args)
            _json(build_trace_sft(vault, args.output))
            return 0

        if args.command == "run":
            _, _, engine = _engine_from_args(args)
            _json(
                engine.run_case(
                    split=args.split,
                    case_id=args.case_id,
                    selection_seed=args.selection_seed,
                )
            )
            return 0

        if args.command == "serve":
            vault, store, engine = _engine_from_args(args)
            context = ApiContext(vault, engine, store, allow_origin=args.allow_origin)
            httpd = serve(context, host=args.host, port=args.port)
            print(f"EvalFoundry listening on http://{args.host}:{args.port}")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nEvalFoundry stopped.")
            finally:
                httpd.server_close()
            return 0
    except EvalFoundryError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    raise AssertionError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
