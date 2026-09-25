from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evalfoundry.cli import main as cli_main
from evalfoundry.errors import SigningError
from evalfoundry.models import Completion
from evalfoundry.receipts import ReceiptStore
from evalfoundry.runner import RunEngine
from evalfoundry.signing import (
    ALGORITHM,
    CANONICALIZATION,
    Keyring,
    ReceiptSigner,
    canonical_receipt_bytes,
    verify_receipt,
)
from evalfoundry.vault import DatasetVault

from tests.helpers import make_fixture_archive


class GoodClient:
    public_config = {"endpoint": "http://127.0.0.1:1234/v1/chat/completions", "model": "fake"}

    def complete(self, _case, *, pack_kind=None):
        trace = {
            "rubric_version": "source-priority-v2.0",
            "base_points": 5,
            "urgency_signals": ["NETWORK", "NO_AUTH"],
            "dampening_signals": [],
            "final_points": 7,
            "assigned_triage_priority": "high",
        }
        parsed = {"triage_priority": "high", "rubric_trace": trace}
        return Completion(json.dumps(parsed), parsed, {}, "fake-1"), []


def sample_receipt() -> dict:
    return {
        "run_id": "11111111-2222-3333-4444-555555555555",
        "created_at": "2026-09-24T00:00:00Z",
        "status": "SCORED",
        "scope": "diagnostic",
        "archive_sha256": "ab" * 32,
        "case": {"id": "case-1", "split": "eval", "task": "t", "input": {"note": "café"}},
        "model": {"model": "fake", "endpoint": "http://127.0.0.1:1234"},
        "prompt_sha256": "cd" * 32,
        "validation": {"accepted": True, "errors": []},
        "calls_used": 1,
    }


class CanonicalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.keyring = Keyring.create(Path(self.temp.name) / "keyring.json", key_id="k1")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_member_order_does_not_change_canonical_bytes(self) -> None:
        first = sample_receipt()
        second = dict(reversed(list(first.items())))
        second["case"] = dict(reversed(list(first["case"].items())))
        self.assertEqual(canonical_receipt_bytes(first), canonical_receipt_bytes(second))

    def test_canonical_form_is_compact_sorted_ascii(self) -> None:
        encoded = canonical_receipt_bytes({"b": "café", "a": {"y": 1, "x": 2}})
        self.assertEqual(b'{"a":{"x":2,"y":1},"b":"caf\\u00e9"}', encoded)

    def test_signature_member_is_excluded_from_signed_bytes(self) -> None:
        receipt = sample_receipt()
        signed = ReceiptSigner(self.keyring).sign(receipt)
        self.assertEqual(canonical_receipt_bytes(receipt), canonical_receipt_bytes(signed))

    def test_reformatted_json_files_verify_identically(self) -> None:
        signed = ReceiptSigner(self.keyring).sign(sample_receipt())
        compact = json.dumps(signed, separators=(",", ":"), sort_keys=True)
        shuffled = dict(reversed(list(signed.items())))
        verbose = json.dumps(shuffled, indent=4, ensure_ascii=False)
        for text in (compact, verbose):
            result = verify_receipt(json.loads(text), self.keyring)
            self.assertTrue(result.ok, result.detail)


class KeyringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_create_refuses_to_overwrite(self) -> None:
        path = self.base / "keyring.json"
        Keyring.create(path, key_id="k1")
        original = path.read_bytes()
        with self.assertRaises(SigningError):
            Keyring.create(path, key_id="k2")
        self.assertEqual(original, path.read_bytes())
        self.assertEqual([], list(self.base.glob("*.tmp")))

    def test_competing_creator_wins_without_being_overwritten(self) -> None:
        path = self.base / "keyring.json"
        original_link = os.link
        winner = None

        def competing_publish(source, destination):
            nonlocal winner
            # Another creator publishes at the exact race boundary.
            with patch("evalfoundry.signing.os.link", original_link):
                Keyring.create(path, key_id="winner")
            winner = path.read_bytes()
            original_link(source, destination)

        with patch("evalfoundry.signing.os.link", side_effect=competing_publish):
            with self.assertRaises(SigningError):
                Keyring.create(path, key_id="loser")
        self.assertEqual(winner, path.read_bytes())
        self.assertEqual("winner", Keyring.load(path).current_key_id)
        self.assertEqual([], list(self.base.glob("*.tmp")))

    def test_dangling_symlink_is_not_replaced(self) -> None:
        path = self.base / "keyring.json"
        target = self.base / "missing.json"
        path.symlink_to(target)
        with self.assertRaises(SigningError):
            Keyring.create(path, key_id="k1")
        self.assertTrue(path.is_symlink())
        self.assertFalse(target.exists())
        self.assertEqual([], list(self.base.glob("*.tmp")))

    def test_unsupported_publication_fails_closed_and_cleans_up(self) -> None:
        path = self.base / "keyring.json"
        with patch("evalfoundry.signing.os.link", side_effect=OSError("unsupported")):
            with self.assertRaises(SigningError):
                Keyring.create(path, key_id="k1")
        self.assertFalse(path.exists())
        self.assertEqual([], list(self.base.glob("*.tmp")))

    def test_keyring_file_is_owner_only(self) -> None:
        import stat

        path = self.base / "keyring.json"
        Keyring.create(path, key_id="k1")
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_duplicate_and_blank_key_ids_are_rejected(self) -> None:
        keyring = Keyring.create(self.base / "keyring.json", key_id="k1")
        with self.assertRaises(SigningError):
            keyring.add_key("k1")
        with self.assertRaises(SigningError):
            keyring.add_key("  ")

    def test_retired_current_key_cannot_sign(self) -> None:
        keyring = Keyring.create(self.base / "keyring.json", key_id="k1")
        keyring.retire("k1")
        with self.assertRaises(SigningError):
            keyring.signing_key()
        with self.assertRaises(SigningError):
            ReceiptSigner(keyring).sign(sample_receipt())

    def test_malformed_keyring_is_rejected(self) -> None:
        path = self.base / "keyring.json"
        path.write_text('{"version": 1, "current": "ghost", "keys": {}}', encoding="utf-8")
        with self.assertRaises(SigningError):
            Keyring.load(path)
        missing = self.base / "missing.json"
        with self.assertRaises(SigningError):
            Keyring.load(missing)


class SignatureVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.keyring = Keyring.create(self.base / "keyring.json", key_id="k1")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _signed(self) -> dict:
        return ReceiptSigner(self.keyring).sign(sample_receipt())

    def test_valid_signature_roundtrips_with_signer_identity(self) -> None:
        result = verify_receipt(self._signed(), self.keyring)
        self.assertTrue(result.ok)
        self.assertEqual("valid", result.status)
        self.assertEqual("k1", result.key_id)

    def test_content_mutation_is_detected(self) -> None:
        signed = self._signed()
        signed["status"] = "HOLD"
        result = verify_receipt(signed, self.keyring)
        self.assertEqual("invalid_signature", result.status)
        self.assertFalse(result.ok)

    def test_nested_content_mutation_is_detected(self) -> None:
        signed = self._signed()
        signed["validation"]["accepted"] = False
        self.assertEqual("invalid_signature", verify_receipt(signed, self.keyring).status)

    def test_signature_value_tampering_is_detected(self) -> None:
        signed = self._signed()
        value = signed["signature"]["value"]
        signed["signature"]["value"] = ("0" if value[0] != "0" else "1") + value[1:]
        self.assertEqual("invalid_signature", verify_receipt(signed, self.keyring).status)

    def test_wrong_key_material_under_same_id_is_invalid_signature(self) -> None:
        other = Keyring.create(self.base / "other.json", key_id="k1")
        result = verify_receipt(self._signed(), other)
        self.assertEqual("invalid_signature", result.status)

    def test_unknown_key_id_is_rejected_distinctly(self) -> None:
        other = Keyring.create(self.base / "other.json", key_id="k2")
        result = verify_receipt(self._signed(), other)
        self.assertEqual("unknown_key_id", result.status)
        self.assertNotEqual("invalid_signature", result.status)
        self.assertFalse(result.ok)

    def test_forged_key_id_is_rejected_as_unknown(self) -> None:
        signed = self._signed()
        signed["signature"]["key_id"] = "attacker-key"
        self.assertEqual("unknown_key_id", verify_receipt(signed, self.keyring).status)

    def test_unsigned_receipt_is_distinct_from_invalid(self) -> None:
        result = verify_receipt(sample_receipt(), self.keyring)
        self.assertEqual("unsigned_receipt", result.status)
        self.assertFalse(result.ok)

    def test_signature_envelope_fields_are_checked(self) -> None:
        signed = self._signed()
        self.assertEqual(ALGORITHM, signed["signature"]["algorithm"])
        self.assertEqual(CANONICALIZATION, signed["signature"]["canonicalization"])
        signed["signature"]["algorithm"] = "HMAC-SHA1"
        self.assertEqual("invalid_signature", verify_receipt(signed, self.keyring).status)

    def test_signing_replaces_stale_signature(self) -> None:
        signed_once = self._signed()
        mutated = signed_once | {"status": "HOLD"}
        resigned = ReceiptSigner(self.keyring).sign(mutated)
        self.assertTrue(verify_receipt(resigned, self.keyring).ok)

    def test_rotation_keeps_old_receipts_verifiable(self) -> None:
        old_receipt = self._signed()
        previous = self.keyring.rotate("k2")
        self.assertEqual("k1", previous)
        self.assertEqual("k2", self.keyring.current_key_id)
        self.assertEqual("retired", self.keyring.key_state("k1"))

        new_receipt = ReceiptSigner(self.keyring).sign(sample_receipt() | {"run_id": "r-2"})
        self.assertEqual("k2", new_receipt["signature"]["key_id"])

        persisted = self.base / "keyring.json"
        self.keyring.save(persisted)
        reloaded = Keyring.load(persisted)
        old_result = verify_receipt(old_receipt, reloaded)
        new_result = verify_receipt(new_receipt, reloaded)
        self.assertTrue(old_result.ok, old_result.detail)
        self.assertEqual("k1", old_result.key_id)
        self.assertTrue(new_result.ok, new_result.detail)
        self.assertEqual("k2", new_result.key_id)


class SignedReceiptStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.vault = DatasetVault(make_fixture_archive(base / "fixture.zip"))
        self.keyring = Keyring.create(base / "keyring.json", key_id="runner-key")
        self.case_id = "nvd-modern-cve2026100000"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_engine_receipt_is_signed_and_verifiable(self) -> None:
        store = ReceiptStore(Path(self.temp.name) / "state", signer=ReceiptSigner(self.keyring))
        engine = RunEngine(self.vault, store, GoodClient())
        receipt = engine.run_case(split="eval", case_id=self.case_id)
        self.assertEqual("SCORED", receipt["status"])

        stored = store.get(receipt["run_id"])
        self.assertEqual("runner-key", stored["signature"]["key_id"])
        self.assertTrue(verify_receipt(stored, self.keyring).ok)

        on_disk = json.loads((store.receipt_dir / f"{receipt['run_id']}.json").read_text(encoding="utf-8"))
        self.assertTrue(verify_receipt(on_disk, self.keyring).ok)

    def test_stored_signed_receipt_mutation_is_detected(self) -> None:
        store = ReceiptStore(Path(self.temp.name) / "state", signer=ReceiptSigner(self.keyring))
        engine = RunEngine(self.vault, store, GoodClient())
        receipt = engine.run_case(split="eval", case_id=self.case_id)
        stored = store.get(receipt["run_id"])
        stored["validation"]["accepted"] = False
        self.assertEqual("invalid_signature", verify_receipt(stored, self.keyring).status)

    def test_unsigned_store_keeps_previous_behavior(self) -> None:
        store = ReceiptStore(Path(self.temp.name) / "state")
        engine = RunEngine(self.vault, store, GoodClient())
        receipt = engine.run_case(split="eval", case_id=self.case_id)
        self.assertEqual("SCORED", receipt["status"])
        self.assertNotIn("signature", store.get(receipt["run_id"]))
        self.assertEqual("unsigned_receipt", verify_receipt(receipt, self.keyring).status)


class SigningCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.keyring_path = str(self.base / "keyring.json")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _run_cli(self, argv: list[str]) -> tuple[int, dict]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli_main(argv)
        return code, json.loads(buffer.getvalue())

    def test_keygen_rotate_verify_roundtrip(self) -> None:
        code, created = self._run_cli(["keygen", "--keyring", self.keyring_path, "--key-id", "k1"])
        self.assertEqual(0, code)
        self.assertEqual("k1", created["current_key_id"])

        keyring = Keyring.load(self.keyring_path)
        receipt_path = self.base / "receipt.json"
        receipt_path.write_text(
            json.dumps(ReceiptSigner(keyring).sign(sample_receipt())), encoding="utf-8"
        )

        code, verdict = self._run_cli(
            ["verify-receipt", "--receipt", str(receipt_path), "--keyring", self.keyring_path]
        )
        self.assertEqual(0, code)
        self.assertEqual("valid", verdict["status"])

        code, rotated = self._run_cli(
            ["rotate-key", "--keyring", self.keyring_path, "--new-key-id", "k2"]
        )
        self.assertEqual(0, code)
        self.assertEqual("k2", rotated["current_key_id"])
        self.assertEqual("k1", rotated["retired_key_id"])

        code, verdict = self._run_cli(
            ["verify-receipt", "--receipt", str(receipt_path), "--keyring", self.keyring_path]
        )
        self.assertEqual(0, code)
        self.assertEqual("k1", verdict["key_id"])

    def test_verify_receipt_rejects_mutation_with_nonzero_exit(self) -> None:
        self._run_cli(["keygen", "--keyring", self.keyring_path, "--key-id", "k1"])
        keyring = Keyring.load(self.keyring_path)
        signed = ReceiptSigner(keyring).sign(sample_receipt())
        signed["status"] = "HOLD"
        receipt_path = self.base / "receipt.json"
        receipt_path.write_text(json.dumps(signed), encoding="utf-8")

        code, verdict = self._run_cli(
            ["verify-receipt", "--receipt", str(receipt_path), "--keyring", self.keyring_path]
        )
        self.assertEqual(1, code)
        self.assertEqual("invalid_signature", verdict["status"])

    def test_verify_receipt_unknown_key_id_with_nonzero_exit(self) -> None:
        self._run_cli(["keygen", "--keyring", self.keyring_path, "--key-id", "k1"])
        other_path = str(self.base / "other.json")
        self._run_cli(["keygen", "--keyring", other_path, "--key-id", "k2"])
        signed = ReceiptSigner(Keyring.load(other_path)).sign(sample_receipt())
        receipt_path = self.base / "receipt.json"
        receipt_path.write_text(json.dumps(signed), encoding="utf-8")

        code, verdict = self._run_cli(
            ["verify-receipt", "--receipt", str(receipt_path), "--keyring", self.keyring_path]
        )
        self.assertEqual(1, code)
        self.assertEqual("unknown_key_id", verdict["status"])


if __name__ == "__main__":
    unittest.main()
