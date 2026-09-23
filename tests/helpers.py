from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path


ROOT = "nvd-modern-10k-cve-source-priority/"


def evidence() -> dict:
    return {
        "description": "A test record for deterministic source-priority scoring.",
        "cvss_score": 7.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_version": "3.1",
        "cwe_ids": ["CWE-20"],
        "cpe_matches": [],
        "known_exploited": False,
        "vendor_advisory": False,
        "public_exploit_reference": False,
        "requires_authentication": False,
        "published": "2026-01-01T00:00:00.000",
        "last_modified": "2026-01-01T00:00:00.000",
    }


def blind(case_id: str) -> dict:
    return {
        "id": case_id,
        "source_id": case_id.replace("nvd-modern-", "").upper().replace("CVE2026", "CVE-2026-"),
        "task": "Predict deterministic source-based CVE triage priority from the provided NVD-derived fields.",
        "input": evidence(),
    }


def canonical(case_id: str, split: str) -> dict:
    row = blind(case_id)
    row.update(
        {
            "source": "NVD",
            "target": {"triage_priority": "high"},
            "auxiliary": {},
            "provenance": {},
            "rubric_trace": {
                "rubric_version": "source-priority-v2.0",
                "base_points": 5,
                "urgency_signals": ["NETWORK", "NO_AUTH"],
                "dampening_signals": [],
                "final_points": 7,
                "assigned_triage_priority": "high",
            },
            "split": split,
        }
    )
    return row


def _jsonl(rows: list[dict]) -> bytes:
    return ("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n").encode("utf-8")


def make_fixture_archive(destination: Path) -> Path:
    """Create a complete small-shape archive with real eval/challenge cardinalities."""
    train_id = "nvd-modern-cve202600001"
    eval_rows = [blind(f"nvd-modern-cve202610{index:04d}") for index in range(1000)]
    challenge_rows = [blind(f"nvd-modern-cve202620{index:04d}") for index in range(750)]
    preview_rows = [canonical(f"nvd-modern-cve202630{index:04d}", "preview") for index in range(250)]
    payloads = {
        "canonical/train_8000.canonical.jsonl": _jsonl([canonical(train_id, "train")]),
        "answers/eval_1000.answers.jsonl": _jsonl(
            [{"id": row["id"], "triage_priority": "high"} for row in eval_rows]
        ),
        "answers/challenge_750.answers.jsonl": _jsonl(
            [{"id": row["id"], "triage_priority": "high"} for row in challenge_rows]
        ),
        "export/eval_1000.inputs.jsonl": _jsonl(eval_rows),
        "export/challenge_750.inputs.jsonl": _jsonl(challenge_rows),
        "export/preview_250.jsonl": _jsonl(preview_rows),
        "export/train_8000.sft_messages.jsonl": _jsonl(
            [
                {
                    "id": blind(train_id)["source_id"],
                    "messages": [
                        {"role": "system", "content": "output JSON"},
                        {"role": "user", "content": "{}"},
                        {"role": "assistant", "content": '{"triage_priority":"high"}'},
                    ],
                }
            ]
        ),
    }
    manifest_lines = ["path\tbytes\tsha256"]
    for relative, data in sorted(payloads.items()):
        manifest_lines.append(f"{relative}\t{len(data)}\t{hashlib.sha256(data).hexdigest()}")
    payloads["reports/FILE_MANIFEST.tsv"] = ("\n".join(manifest_lines) + "\n").encode("utf-8")

    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, data in payloads.items():
            archive.writestr(ROOT + relative, data)
    return destination
