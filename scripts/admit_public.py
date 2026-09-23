#!/usr/bin/env python3
"""Admit public feedstock into atom store (EVAL_BASELINE G0–G5).

Usage:
  python3 scripts/admit_public.py \\
    --input feedstock/t2_policy_public/sources.jsonl \\
    --output atoms/t2_policy_public/atoms.jsonl \\
    --lexicon t2
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evalfoundry.atoms import (  # noqa: E402
    T2_POLICY_LEXICON,
    T3_TOOL_LEXICON,
    admit_text,
    write_atoms_jsonl,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Admit public feedstock to atoms (G0–G5).")
    parser.add_argument("--input", required=True, help="JSONL with text + provenance fields")
    parser.add_argument("--output", required=True, help="Output atoms JSONL path")
    parser.add_argument("--lexicon", choices=("t2", "t3"), default="t2")
    parser.add_argument("--allow-single-deep", action="store_true", default=True)
    args = parser.parse_args()

    lex = T3_TOOL_LEXICON if args.lexicon == "t3" else T2_POLICY_LEXICON
    admitted = []
    rejected = []
    for line_no, line in enumerate(Path(args.input).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        atom, reasons = admit_text(
            text=row["text"],
            source_url=row["source_url"],
            source_title=row["source_title"],
            license_id=row.get("license") or row.get("license_id") or "",
            public=bool(row.get("public", True)),
            lexicon=lex,
            meta={
                "source_id": row.get("source_id"),
                "control_id": row.get("control_id"),
                "feedstock_line": line_no,
            },
            require_multi=True,
            atom_id=row.get("atom_id") or (f"atom-{row.get('source_id')}" if row.get("source_id") else None),
        )
        if atom is None:
            rejected.append({"line": line_no, "source_id": row.get("source_id"), "reasons": reasons})
        else:
            admitted.append(atom)

    n = write_atoms_jsonl(args.output, admitted)
    report = {
        "admitted": n,
        "rejected": len(rejected),
        "reject_samples": rejected[:20],
        "output": str(Path(args.output).resolve()),
    }
    print(json.dumps(report, indent=2))
    return 0 if n else 1


if __name__ == "__main__":
    raise SystemExit(main())
