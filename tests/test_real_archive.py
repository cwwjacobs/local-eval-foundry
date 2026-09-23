from __future__ import annotations

import os
import unittest

from evalfoundry.vault import APPROVED_FROZEN_ARCHIVE_SHA256, DatasetVault


ARCHIVE = os.environ.get("EVALFOUNDRY_ARCHIVE")


@unittest.skipUnless(ARCHIVE, "Set EVALFOUNDRY_ARCHIVE to run frozen-package integration validation.")
class RealArchiveTests(unittest.TestCase):
    def test_frozen_archive_contract(self) -> None:
        report = DatasetVault(
            ARCHIVE, expected_sha256=APPROVED_FROZEN_ARCHIVE_SHA256, strict_contract=True
        ).verify_deep()
        self.assertEqual(APPROVED_FROZEN_ARCHIVE_SHA256, report.archive_sha256)
        self.assertTrue(report.provenance_pinned)
        self.assertEqual(24, report.manifest_entries_verified)
        self.assertEqual(
            {"train": 8000, "eval": 1000, "challenge": 750, "preview": 250}, report.record_counts
        )
        self.assertEqual(0, report.rubric_alignment_failures)
