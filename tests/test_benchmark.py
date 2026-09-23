from __future__ import annotations

import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from evalfoundry.benchmark import run_benchmark, write_benchmark_report
from evalfoundry.errors import ArchiveValidationError, BudgetExceeded
from evalfoundry.model_client import build_messages
from evalfoundry.models import Completion
from evalfoundry.receipts import ReceiptStore
from evalfoundry.rubric import evaluate_rubric
from evalfoundry.runner import RunEngine
from evalfoundry.vault import DatasetVault

from tests.helpers import make_fixture_archive


class RubricClient:
    public_config = {
        "endpoint": "http://127.0.0.1:1234/v1/chat/completions",
        "model": "rubric-fixture",
        "transport": "test",
    }

    def complete(self, case, *, pack_kind=None):
        label, trace = evaluate_rubric(case.evidence)
        parsed = {"triage_priority": label, "rubric_trace": trace}
        return Completion(json.dumps(parsed), parsed, {}, "fixture"), build_messages(
            case, pack_kind=pack_kind
        )


class BenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.archive = make_fixture_archive(self.base / "fixture.zip")
        self.vault = DatasetVault(self.archive)
        self.store = ReceiptStore(self.base / "state")
        self.engine = RunEngine(self.vault, self.store, RubricClient())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_subset_report_is_deterministic_and_aggregated(self) -> None:
        report = run_benchmark(
            self.vault,
            self.engine,
            split="eval",
            count=2,
            selection_seed="stable-order",
            max_calls=2,
        )
        self.assertEqual(2, report["requested_count"])
        self.assertEqual(2, report["attempted_count"])
        self.assertEqual(2, report["calls_used"])
        self.assertEqual(2, report["accepted"])
        self.assertEqual(1.0, report["accuracy"])
        self.assertFalse(report["is_full_split"])
        self.assertEqual(2, len(report["run_ids"]))
        self.assertEqual(self.engine.vault.archive_sha256, report["archive_sha256"])

    def test_call_budget_must_exactly_match_selection(self) -> None:
        with self.assertRaises(BudgetExceeded):
            run_benchmark(
                self.vault,
                self.engine,
                split="eval",
                count=2,
                max_calls=3,
            )

    def test_rejects_vault_that_does_not_match_engine(self) -> None:
        other_archive = self.base / "other.zip"
        shutil.copy2(self.archive, other_archive)
        with zipfile.ZipFile(other_archive, "a") as archive:
            archive.comment = b"different archive identity"
        other_vault = DatasetVault(other_archive)
        self.assertNotEqual(self.vault.archive_sha256, other_vault.archive_sha256)

        with self.assertRaises(ArchiveValidationError):
            run_benchmark(
                other_vault,
                self.engine,
                split="eval",
                count=1,
                max_calls=1,
            )

    def test_report_writer_refuses_overwrite_without_mutating_original(self) -> None:
        path = self.base / "report.json"
        write_benchmark_report({"status": "PASS"}, path)
        original = path.read_bytes()
        with self.assertRaises(FileExistsError):
            write_benchmark_report({"status": "REPLACED"}, path)
        self.assertEqual(original, path.read_bytes())
        self.assertEqual({"status": "PASS"}, json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main()
