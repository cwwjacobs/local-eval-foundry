from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from evalfoundry.errors import ArchiveValidationError, SplitAccessError
from evalfoundry.vault import DatasetVault

from tests.helpers import make_fixture_archive


class VaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.archive = make_fixture_archive(Path(self.temp.name) / "fixture.zip")
        self.vault = DatasetVault(self.archive)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_eval_case_is_blind(self) -> None:
        case = self.vault.get_case("eval", "nvd-modern-cve2026100000")
        payload = case.model_payload()
        self.assertEqual({"id", "source_id", "task", "input"}, set(payload))
        self.assertNotIn("target", payload)
        self.assertNotIn("rubric_trace", payload)

    def test_selection_is_stable_and_bounded(self) -> None:
        first_seed, first = self.vault.select_cases("challenge", 3, "same-seed")
        second_seed, second = self.vault.select_cases("challenge", 3, "same-seed")
        self.assertEqual("same-seed", first_seed)
        self.assertEqual(first_seed, second_seed)
        self.assertEqual([item.case_id for item in first], [item.case_id for item in second])
        self.assertEqual(3, len(first))

    def test_preview_cannot_be_run(self) -> None:
        with self.assertRaises(SplitAccessError):
            self.vault.get_case("preview", "anything")

    def test_train_cannot_be_run(self) -> None:
        with self.assertRaises(SplitAccessError):
            self.vault.get_case("train", "nvd-modern-cve202600001")
        with self.assertRaises(SplitAccessError):
            self.vault.select_cases("train", 1, "no-live-train")

    def test_public_case_is_defensively_copied(self) -> None:
        case = self.vault.get_case("eval", "nvd-modern-cve2026100000")
        case.evidence["description"] = "mutated"
        untouched = self.vault.get_case("eval", "nvd-modern-cve2026100000")
        self.assertNotEqual("mutated", untouched.evidence["description"])

    def test_expected_archive_hash_fails_closed(self) -> None:
        with self.assertRaises(ArchiveValidationError):
            DatasetVault(self.archive, expected_sha256="0" * 64)

    def test_training_metadata_does_not_stream_labels(self) -> None:
        metadata = self.vault.training_artifact()
        self.assertEqual("CVE source_id, not canonical prediction id", metadata["id_semantics"])
        self.assertNotIn("messages", metadata)
