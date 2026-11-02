"""Malformed external signing inputs must produce explicit rejection verdicts."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from evalfoundry.cli import main as cli_main
from evalfoundry.errors import SigningError
from evalfoundry.signing import Keyring, ReceiptSigner, verify_receipt


class MalformedSigningInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.keyring_path = self.root / "keyring.json"
        self.keyring = Keyring.create(self.keyring_path, key_id="k1")

    def test_whitespace_cannot_disguise_short_or_empty_key(self):
        raw = json.loads(self.keyring_path.read_text())
        for value in (" " * 64, "ab" * 31 + "  ", "ab" * 32 + " "):
            with self.subTest(value=value):
                raw["keys"]["k1"]["key_hex"] = value
                self.keyring_path.write_text(json.dumps(raw))
                with self.assertRaises(SigningError):
                    Keyring.load(self.keyring_path)

    def test_invalid_signature_encodings_produce_verdict(self):
        for value in ("é" * 64, " " * 64, "g" * 64, "a" * 63, "a" * 65):
            with self.subTest(value=value):
                receipt = ReceiptSigner(self.keyring).sign({"status": "SCORED"})
                receipt["signature"]["value"] = value
                result = verify_receipt(receipt, self.keyring)
                self.assertFalse(result.ok)
                self.assertEqual(result.status, "invalid_signature")

    def test_uppercase_hex_signature_remains_valid(self):
        receipt = ReceiptSigner(self.keyring).sign({"status": "SCORED"})
        receipt["signature"]["value"] = receipt["signature"]["value"].upper()
        self.assertTrue(verify_receipt(receipt, self.keyring).ok)

    def test_nonfinite_payload_produces_invalid_verdict(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                receipt = ReceiptSigner(self.keyring).sign({"score": 1.0})
                receipt["score"] = value
                result = verify_receipt(receipt, self.keyring)
                self.assertEqual(result.status, "invalid_signature")

    def test_nonobject_receipt_produces_invalid_verdict(self):
        for value in ([], None, "receipt", 42):
            with self.subTest(value=value):
                self.assertEqual(verify_receipt(value, self.keyring).status, "invalid_signature")

    def test_cli_rejects_nonascii_signature_without_traceback(self):
        receipt = ReceiptSigner(self.keyring).sign({"status": "SCORED"})
        receipt["signature"]["value"] = "é" * 64
        path = self.root / "receipt.json"
        path.write_text(json.dumps(receipt))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli_main(["verify-receipt", "--receipt", str(path), "--keyring", str(self.keyring_path)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "invalid_signature")
