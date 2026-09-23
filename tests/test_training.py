from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from evalfoundry.training import build_trace_sft
from evalfoundry.vault import DatasetVault

from tests.helpers import make_fixture_archive


class TrainingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.vault = DatasetVault(make_fixture_archive(base / "fixture.zip"))
        self.output = base / "derived.jsonl"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_train_only_trace_derivative_has_exact_target_and_receipt(self) -> None:
        report = build_trace_sft(self.vault, self.output)
        rows = [json.loads(line) for line in self.output.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(1, report["output_records"])
        self.assertEqual(1, len(rows))
        self.assertEqual("train", rows[0]["split"])
        assistant = json.loads(rows[0]["messages"][-1]["content"])
        self.assertEqual("high", assistant["triage_priority"])
        self.assertEqual(7, assistant["rubric_trace"]["final_points"])
        self.assertFalse(report["contains_eval_or_challenge_rows"])
        self.assertTrue((self.output.with_suffix(".jsonl.receipt.json")).is_file())

    def test_train_derivative_never_overwrites(self) -> None:
        build_trace_sft(self.vault, self.output)
        with self.assertRaises(FileExistsError):
            build_trace_sft(self.vault, self.output)
