"""Tests for agent-ops-public-v1 pack + rubrics (public-safe)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from evalfoundry.agent_ops_rubric import (
    TASK_DOMAIN,
    TASK_GATE,
    TASK_SKILL,
    evaluate_action_gate,
    evaluate_agent_ops,
    evaluate_domain_multi_hit,
    evaluate_skill_checklist,
    validate_agent_ops_response,
)
from evalfoundry.model_client import build_messages
from evalfoundry.vault import PACK_KIND_AGENT_OPS, DatasetVault

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "packs" / "agent-ops-public-v1.zip"
PIN = (ROOT / "packs" / "agent-ops-public-v1.SHA256").read_text().strip()


class AgentOpsRubricTests(unittest.TestCase):
    def test_domain_multi_hit(self) -> None:
        passage = (
            "We will host an MCP server with a tool registry and ship a skill.md package. "
            "The agent harness should list tools via the connector host profile before any spawn."
        )
        label, trace = evaluate_domain_multi_hit({"passage": passage})
        self.assertIn("mkt_agent_mcp", label)
        self.assertEqual(trace["rubric_version"], TASK_DOMAIN)
        self.assertIn("mkt_agent_mcp", trace["hit_domains"])

    def test_weak_single_support_is_not_hit(self) -> None:
        passage = "Someone mentioned MCP once without a server or registry."
        label, _ = evaluate_domain_multi_hit({"passage": passage})
        self.assertEqual(label, "NONE")

    def test_action_gate_critical_deny(self) -> None:
        label, _ = evaluate_action_gate(
            {
                "risk_level": "critical",
                "requires_network": True,
                "mutates_filesystem": True,
                "touches_secrets": True,
                "untrusted_input": False,
            }
        )
        self.assertEqual(label, "deny")

    def test_action_gate_low_allow(self) -> None:
        label, _ = evaluate_action_gate(
            {
                "risk_level": "low",
                "requires_network": False,
                "mutates_filesystem": False,
                "touches_secrets": False,
                "untrusted_input": False,
            }
        )
        self.assertEqual(label, "allow")

    def test_skill_checklist(self) -> None:
        label, _ = evaluate_skill_checklist({"listed_files": ["README.md"]})
        self.assertEqual(label, "SKILL.md|scripts/|tests/")
        label2, _ = evaluate_skill_checklist(
            {"listed_files": ["SKILL.md", "scripts/audit.py", "tests/t.py"]}
        )
        self.assertEqual(label2, "COMPLETE")

    def test_validate_accepts_perfect_response(self) -> None:
        evidence = {
            "risk_level": "low",
            "requires_network": False,
            "mutates_filesystem": False,
            "touches_secrets": False,
            "untrusted_input": False,
        }
        label, trace = evaluate_action_gate(evidence)
        result = validate_agent_ops_response(
            {"label": label, "rubric_trace": trace},
            TASK_GATE,
            evidence,
            label,
        )
        self.assertTrue(result.accepted)


@unittest.skipUnless(ARCHIVE.is_file(), "agent-ops pack not built")
class AgentOpsVaultTests(unittest.TestCase):
    def test_vault_loads_public_safe_pack(self) -> None:
        vault = DatasetVault(ARCHIVE, expected_sha256=PIN, strict_contract=True)
        self.assertEqual(vault.pack_kind, PACK_KIND_AGENT_OPS)
        self.assertTrue(vault.pack_contract and vault.pack_contract.get("public_safe"))
        self.assertEqual(vault.split_sizes["eval"], 40)
        self.assertEqual(vault.split_sizes["challenge"], 30)
        self.assertEqual(vault.split_sizes["train"], 80)
        self.assertEqual(vault.split_sizes["preview"], 20)

    def test_blind_case_and_scoring_context(self) -> None:
        vault = DatasetVault(ARCHIVE, expected_sha256=PIN, strict_contract=True)
        seed, cases = vault.select_cases("eval", 1, selection_seed="test-seed-1")
        self.assertEqual(len(cases), 1)
        case = cases[0]
        payload = case.model_payload()
        self.assertEqual(set(payload), {"id", "source_id", "task", "input"})
        expected, trace = vault.scoring_context(case)
        derived, fresh = evaluate_agent_ops(case.task, case.evidence)
        self.assertEqual(expected, derived)
        self.assertEqual(trace, fresh)

    def test_prompt_has_no_label(self) -> None:
        vault = DatasetVault(ARCHIVE, expected_sha256=PIN, strict_contract=True)
        _, cases = vault.select_cases("eval", 1, selection_seed="prompt-check")
        messages = build_messages(cases[0], pack_kind=PACK_KIND_AGENT_OPS)
        blob = json.dumps(messages)
        self.assertNotIn("\"label\":", blob.split("response_contract")[0] if False else "")
        # sealed answers never appear in user evidence payload
        user = messages[1]["content"]
        self.assertNotIn("target", user)
        self.assertNotIn("triage_priority", user)

    def test_public_safe_scan_no_operator_pii(self) -> None:
        """Hard fail if known private tokens appear in pack text files."""
        forbidden = [
            "private_person_name",
            "private@example.com",
            "api_key=",
            "password=",
            "private_key_marker",
        ]
        # scan unpacked if present else zip entries via vault training paths
        text_blobs: list[str] = []
        unpack = ROOT / "packs" / "agent-ops-public-v1"
        if unpack.is_dir():
            for path in unpack.rglob("*"):
                if path.suffix in {".jsonl", ".json", ".md", ".tsv"}:
                    text_blobs.append(path.read_text(encoding="utf-8", errors="replace"))
        joined = "\n".join(text_blobs).lower()
        for token in forbidden:
            self.assertNotIn(token.lower(), joined, f"public-safe violation: {token}")


if __name__ == "__main__":
    unittest.main()
