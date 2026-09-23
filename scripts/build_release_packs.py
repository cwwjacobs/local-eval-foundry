"""Build and canonicalize the EvalFoundry v0.2 release packs."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evalfoundry.archive import canonicalize_zip  # noqa: E402

import build_t2_policy_gate_v1 as policy_gate  # noqa: E402
import build_t3_tool_contract_v1 as tool_contract  # noqa: E402


def _write_pin(path: Path, digest: str) -> None:
    path.write_text(digest + "\n", encoding="utf-8")


def build_release_packs() -> dict[str, object]:
    """Build only the release-grade v0.2 reference packs.

    Agent Ops remains a synthetic plumbing demonstration and is intentionally
    outside the release reproducibility claim.
    """
    reports: dict[str, dict[str, object]] = {}

    policy_report = policy_gate.build()
    policy_digest = canonicalize_zip(policy_gate.ZIP_PATH)
    _write_pin(ROOT / "packs" / "policy-gate-public-v1.SHA256", policy_digest)
    policy_report["sha256"] = policy_digest
    policy_report["archive_format"] = "canonical-zip-stored-v1"
    reports["policy_gate"] = policy_report

    tool_report = tool_contract.build()
    tool_digest = canonicalize_zip(tool_contract.ZIP_PATH)
    _write_pin(ROOT / "packs" / "tool-contract-public-v1.SHA256", tool_digest)
    tool_report["sha256"] = tool_digest
    tool_report["archive_format"] = "canonical-zip-stored-v1"
    reports["tool_contract"] = tool_report

    return {
        "status": "PASS",
        "archive_format": "canonical-zip-stored-v1",
        "release_packs": ["policy_gate", "tool_contract"],
        "packs": reports,
    }


if __name__ == "__main__":
    print(json.dumps(build_release_packs(), indent=2, sort_keys=True))
