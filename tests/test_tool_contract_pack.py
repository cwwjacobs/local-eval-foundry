"""T3 tool-contract pack tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from evalfoundry.atoms import T3_TOOL_LEXICON, admit_text
from evalfoundry.tool_contract_rubric import (
    TASK_TOOL_CONTRACT,
    evaluate_tool_contract,
    validate_tool_contract_response,
)
from evalfoundry.vault import PACK_KIND_TOOL_CONTRACT, DatasetVault

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "packs" / "tool-contract-public-v1.zip"
PIN = (ROOT / "packs" / "tool-contract-public-v1.SHA256").read_text().strip()
ATOMS = ROOT / "atoms" / "t3_tool_public" / "atoms.jsonl"

SCHEMA = {
    "name": "read_file",
    "parameters": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
        "additionalProperties": False,
    },
}


class ToolContractRubricTests(unittest.TestCase):
    def test_valid(self) -> None:
        label, trace = evaluate_tool_contract(
            {
                "tool_schema": SCHEMA,
                "proposed_call": {"name": "read_file", "arguments": {"path": "/tmp/a"}},
                "granted_scopes": ["fs:read"],
                "required_scope": "fs:read",
                "side_effect_class": "read",
                "admin_grant": False,
            }
        )
        self.assertEqual(label, "valid")
        self.assertEqual(trace["rubric_version"], TASK_TOOL_CONTRACT)

    def test_malformed_missing(self) -> None:
        label, _ = evaluate_tool_contract(
            {
                "tool_schema": SCHEMA,
                "proposed_call": {"name": "read_file", "arguments": {}},
                "granted_scopes": ["fs:read"],
                "required_scope": "fs:read",
                "side_effect_class": "read",
            }
        )
        self.assertEqual(label, "malformed")

    def test_over_scope(self) -> None:
        label, _ = evaluate_tool_contract(
            {
                "tool_schema": SCHEMA,
                "proposed_call": {"name": "read_file", "arguments": {"path": "x"}},
                "granted_scopes": ["other"],
                "required_scope": "fs:read",
                "side_effect_class": "read",
            }
        )
        self.assertEqual(label, "over_scope")

    def test_denied_destructive(self) -> None:
        schema = {
            "name": "k8s_delete",
            "parameters": {
                "type": "object",
                "properties": {"resource": {"type": "string"}, "name": {"type": "string"}},
                "required": ["resource", "name"],
                "additionalProperties": False,
            },
        }
        label, _ = evaluate_tool_contract(
            {
                "tool_schema": schema,
                "proposed_call": {
                    "name": "k8s_delete",
                    "arguments": {"resource": "pod", "name": "x"},
                },
                "granted_scopes": ["k8s:admin"],
                "required_scope": "k8s:admin",
                "side_effect_class": "destructive",
                "admin_grant": False,
            }
        )
        self.assertEqual(label, "denied")

    def test_validate_perfect(self) -> None:
        evidence = {
            "tool_schema": SCHEMA,
            "proposed_call": {"name": "read_file", "arguments": {"path": "a"}},
            "granted_scopes": ["fs:read"],
            "required_scope": "fs:read",
            "side_effect_class": "read",
        }
        label, trace = evaluate_tool_contract(evidence)
        result = validate_tool_contract_response(
            {"label": label, "rubric_trace": trace}, evidence, label
        )
        self.assertTrue(result.accepted)

    def test_admit_tool_text(self) -> None:
        atom, reasons = admit_text(
            text=(
                "MCP tool schema read_file inputSchema type object properties path "
                "required path. tools/call arguments JSON Schema additionalProperties false. "
                "Scope fs:read least privilege function calling tool registry."
            ),
            source_url="https://example.invalid/mcp",
            source_title="test",
            license_id="MIT",
            public=True,
            lexicon=T3_TOOL_LEXICON,
            meta={"scorer_fields_ok": True},
        )
        self.assertIsNotNone(atom, reasons)


@unittest.skipUnless(ARCHIVE.is_file(), "T3 pack not built")
class ToolContractVaultTests(unittest.TestCase):
    def test_load(self) -> None:
        vault = DatasetVault(ARCHIVE, expected_sha256=PIN, strict_contract=True)
        self.assertEqual(vault.pack_kind, PACK_KIND_TOOL_CONTRACT)
        self.assertTrue(vault.pack_contract.get("public_safe"))
        self.assertEqual(vault.split_sizes["eval"], 16)
        import zipfile

        with zipfile.ZipFile(ARCHIVE) as zf:
            names = [n for n in zf.namelist() if n.endswith("PROVENANCE.jsonl")]
            self.assertEqual(len(names), 1)

    def test_scoring(self) -> None:
        vault = DatasetVault(ARCHIVE, expected_sha256=PIN, strict_contract=True)
        _, cases = vault.select_cases("eval", 1, selection_seed="t3")
        expected, trace = vault.scoring_context(cases[0])
        derived, fresh = evaluate_tool_contract(cases[0].evidence)
        self.assertEqual(expected, derived)
        self.assertEqual(trace, fresh)

    def test_atoms(self) -> None:
        self.assertTrue(ATOMS.is_file())
        self.assertGreaterEqual(len(ATOMS.read_text().splitlines()), 15)


if __name__ == "__main__":
    unittest.main()
