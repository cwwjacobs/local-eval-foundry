"""Explicit, deterministic derived SFT construction from the train split only."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .model_client import build_messages
from .rubric import CLAIM_BOUNDARY
from .vault import DatasetVault

DERIVATION_VERSION = "evalfoundry-trace-sft-v1"


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_trace_sft(vault: DatasetVault, output_path: str | Path) -> dict[str, Any]:
    """Build a new structured-trace SFT artifact only when explicitly invoked.

    The frozen archive remains read-only. The derived artifact contains no eval
    or challenge record and no model-authored rationale.
    """
    output = Path(output_path).expanduser().resolve()
    if output.suffix.lower() != ".jsonl":
        raise ValueError("Trace SFT output must use a .jsonl extension.")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite an existing derived artifact: {output}")

    count = 0
    ids: list[str] = []
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", dir=output.parent, delete=False, suffix=".tmp"
    ) as temporary:
        temporary_path = Path(temporary.name)
        for case, label, trace in vault.iter_train_trace_records():
            messages = build_messages(case)
            assistant = {"triage_priority": label, "rubric_trace": trace}
            row = {
                "id": case.case_id,
                "source_id": case.source_id,
                "split": "train",
                "derivation_version": DERIVATION_VERSION,
                "messages": messages + [
                    {
                        "role": "assistant",
                        "content": json.dumps(assistant, ensure_ascii=False, separators=(",", ":")),
                    }
                ],
            }
            temporary.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
            ids.append(case.case_id)
    os.replace(temporary_path, output)

    ordered_ids_digest = hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest()
    receipt = {
        "derivation_version": DERIVATION_VERSION,
        "status": "PASS",
        "archive_sha256": vault.archive_sha256,
        "expected_archive_sha256": vault.expected_archive_sha256,
        "archive_provenance_pinned": vault.provenance_pinned,
        "input_entry": "canonical/train_8000.canonical.jsonl",
        "output_records": count,
        "ordered_canonical_ids_sha256": ordered_ids_digest,
        "output_sha256": _sha256_path(output),
        "contains_eval_or_challenge_rows": False,
        "contains_model_authored_rationale": False,
        "claim_boundary": CLAIM_BOUNDARY,
    }
    receipt_path = output.with_suffix(output.suffix + ".receipt.json")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", dir=output.parent, delete=False, suffix=".tmp"
    ) as temporary:
        receipt_temp_path = Path(temporary.name)
        json.dump(receipt, temporary, ensure_ascii=False, indent=2, sort_keys=True)
        temporary.write("\n")
    os.replace(receipt_temp_path, receipt_path)
    return receipt | {"output_path": str(output), "receipt_path": str(receipt_path)}
