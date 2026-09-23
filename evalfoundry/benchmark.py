"""Explicit multi-case benchmark execution and aggregate receipts.

The benchmark runner reuses the single-case RunEngine. It never introduces
parallel model calls, hidden retries, or alternate scoring paths.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from .errors import ArchiveValidationError, BudgetExceeded
from .receipts import utc_now
from .runner import RunEngine
from .vault import DatasetVault


def run_benchmark(
    vault: DatasetVault,
    engine: RunEngine,
    *,
    split: str,
    count: int | None = None,
    selection_seed: str = "evalfoundry-benchmark-v1",
    max_calls: int,
    fail_fast: bool = False,
) -> dict[str, Any]:
    """Run an explicit deterministic subset or full split and aggregate receipts.

    ``max_calls`` is a hard operator-provided budget. It must exactly cover the
    selected case count so a typo cannot silently expand model usage.
    """
    if vault.archive_sha256 != engine.vault.archive_sha256:
        raise ArchiveValidationError(
            "Benchmark vault archive does not match the RunEngine vault archive."
        )

    # Selection, execution, metadata, and reporting all use the engine-owned
    # vault after the caller-supplied vault has been verified as the same pack.
    run_vault = engine.vault
    available = run_vault.split_sizes.get(split, 0)
    selected_count = available if count is None else count
    if selected_count < 1 or selected_count > available:
        raise BudgetExceeded(f"count must be between 1 and {available} for {split}.")
    if max_calls != selected_count:
        raise BudgetExceeded(
            f"max_calls must equal the selected case count ({selected_count}); got {max_calls}."
        )

    resolved_seed, cases = run_vault.select_cases(split, selected_count, selection_seed)
    started_at = utc_now()
    receipts: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    task_counts: Counter[str] = Counter()
    task_accepted: Counter[str] = Counter()
    error_counts: Counter[str] = Counter()
    calls_used = 0

    for case in cases:
        receipt = engine.run_case(split=split, case_id=case.case_id)
        receipts.append(receipt)
        calls_used += int(receipt.get("calls_used") or 0)
        status = str(receipt.get("status") or "UNKNOWN")
        status_counts[status] += 1
        task_counts[case.task] += 1

        validation = receipt.get("validation")
        accepted = bool(isinstance(validation, dict) and validation.get("accepted"))
        if accepted:
            task_accepted[case.task] += 1
        elif isinstance(validation, dict):
            for error in validation.get("errors") or []:
                error_counts[str(error)] += 1
        elif receipt.get("error"):
            error_counts[str(receipt["error"])] += 1

        if fail_fast and status != "SCORED":
            break

    completed_at = utc_now()
    attempted = len(receipts)
    accepted_total = sum(task_accepted.values())
    by_task = {
        task: {
            "attempted": task_counts[task],
            "accepted": task_accepted[task],
            "accuracy": (
                task_accepted[task] / task_counts[task] if task_counts[task] else None
            ),
        }
        for task in sorted(task_counts)
    }

    return {
        "report_version": "evalfoundry-benchmark-v1",
        "started_at": started_at,
        "completed_at": completed_at,
        "archive_sha256": run_vault.archive_sha256,
        "archive_provenance_pinned": run_vault.provenance_pinned,
        "pack_kind": run_vault.pack_kind,
        "claim_boundary": engine._claim_boundary(),
        "model": engine.client.public_config,
        "split": split,
        "selection_seed": resolved_seed,
        "requested_count": selected_count,
        "attempted_count": attempted,
        "full_split_size": available,
        "is_full_split": selected_count == available,
        "max_calls": max_calls,
        "calls_used": calls_used,
        "fail_fast": fail_fast,
        "status_counts": dict(sorted(status_counts.items())),
        "accepted": accepted_total,
        "accuracy": accepted_total / attempted if attempted else None,
        "by_task": by_task,
        "error_counts": dict(error_counts.most_common()),
        "run_ids": [str(receipt.get("run_id")) for receipt in receipts],
    }


def write_benchmark_report(report: dict[str, Any], destination: str | Path) -> Path:
    """Write a benchmark report atomically without overwriting prior evidence."""
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
        ) as temporary:
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        try:
            # A hard link publishes the fully written temporary file atomically
            # and fails if another writer already claimed the destination.
            os.link(temporary_path, path)
        except FileExistsError as error:
            raise FileExistsError(
                f"Refusing to overwrite benchmark report: {path}"
            ) from error
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return path
