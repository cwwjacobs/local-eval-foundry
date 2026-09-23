from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from evalfoundry.errors import BudgetExceeded, ModelBusy, ModelProtocolError
from evalfoundry.models import Completion
from evalfoundry.receipts import ReceiptStore
from evalfoundry.runner import RunEngine
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


class StatsClient(GoodClient):
    def complete(self, _case, *, pack_kind=None):
        completion, messages = super().complete(_case, pack_kind=pack_kind)
        return Completion(
            completion.raw_content,
            completion.parsed,
            completion.usage,
            completion.provider_request_id,
            {"input_tokens": 17, "total_output_tokens": 2},
        ), messages


class FailedClient(GoodClient):
    def complete(self, _case, *, pack_kind=None):
        raise ModelProtocolError("offline")


class SensitiveFieldClient(GoodClient):
    def complete(self, _case, *, pack_kind=None):
        parsed = {"triage_priority": "high", "api_key": "do-not-persist"}
        return Completion(json.dumps(parsed), parsed, {}, "fake-secret"), []


class BlockingClient(GoodClient):
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def complete(self, _case, *, pack_kind=None):
        self.started.set()
        self.release.wait(timeout=5)
        return super().complete(_case, pack_kind=pack_kind)


class RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.vault = DatasetVault(make_fixture_archive(base / "fixture.zip"))
        self.store = ReceiptStore(base / "state")
        self.case_id = "nvd-modern-cve2026100000"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_scores_one_explicit_call_and_persists_receipt(self) -> None:
        engine = RunEngine(self.vault, self.store, GoodClient())
        receipt = engine.run_case(split="eval", case_id=self.case_id)
        self.assertEqual("SCORED", receipt["status"])
        self.assertEqual(1, receipt["calls_used"])
        self.assertFalse(receipt["metadata"]["fallback_used"])
        self.assertEqual("high", receipt["validation"]["expected_priority"])
        self.assertIsNotNone(self.store.get(receipt["run_id"]))

    def test_provider_stats_are_persisted_in_receipt(self) -> None:
        engine = RunEngine(self.vault, self.store, StatsClient())
        receipt = engine.run_case(split="eval", case_id=self.case_id)
        self.assertEqual(
            {"input_tokens": 17, "total_output_tokens": 2},
            receipt["completion"]["stats"],
        )
        self.assertTrue(receipt["metadata"]["provider_usage_reported"])

    def test_failure_records_no_fabricated_prediction(self) -> None:
        engine = RunEngine(self.vault, self.store, FailedClient())
        receipt = engine.run_case(split="eval", case_id=self.case_id)
        self.assertEqual("FAILED", receipt["status"])
        self.assertIsNone(receipt["completion"])
        self.assertEqual("not_opened", receipt["metadata"]["answer_access"])

    def test_model_created_sensitive_field_is_redacted_not_lost(self) -> None:
        engine = RunEngine(self.vault, self.store, SensitiveFieldClient())
        receipt = engine.run_case(split="eval", case_id=self.case_id)
        self.assertEqual("HOLD", receipt["status"])
        self.assertEqual("[REDACTED]", receipt["completion"]["parsed"]["api_key"])
        self.assertIn("[REDACTED]", receipt["completion"]["raw_content"])

    def test_selection_seed_must_match_case(self) -> None:
        seed, selected = self.vault.select_cases("eval", 1, "receipt-seed")
        engine = RunEngine(self.vault, self.store, GoodClient())
        with self.assertRaises(BudgetExceeded):
            engine.run_case(
                split="eval",
                case_id="nvd-modern-cve2026100000"
                if selected[0].case_id != "nvd-modern-cve2026100000"
                else "nvd-modern-cve2026100001",
                selection_seed=seed,
            )

    def test_busy_call_is_rejected(self) -> None:
        client = BlockingClient()
        engine = RunEngine(self.vault, self.store, client)
        thread = threading.Thread(target=lambda: engine.run_case(split="eval", case_id=self.case_id))
        thread.start()
        self.assertTrue(client.started.wait(timeout=2))
        with self.assertRaises(ModelBusy):
            engine.run_case(split="eval", case_id="nvd-modern-cve2026100001")
        client.release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
