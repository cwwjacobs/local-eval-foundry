from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from evalfoundry.http_api import ApiContext, serve
from evalfoundry.receipts import ReceiptStore
from evalfoundry.runner import RunEngine
from evalfoundry.vault import DatasetVault

from tests.helpers import make_fixture_archive
from tests.test_runner import GoodClient


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        vault = DatasetVault(make_fixture_archive(base / "fixture.zip"))
        store = ReceiptStore(base / "state")
        self.server = serve(ApiContext(vault, RunEngine(vault, store, GoodClient()), store), port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def _get(self, path: str) -> dict:
        with urlopen(self.base_url + path, timeout=5) as response:
            return json.loads(response.read())

    def test_root_and_status_routes_describe_api(self) -> None:
        root = self._get("/")
        self.assertEqual("EvalFoundry", root["service"])
        self.assertEqual("none", root["ui"])
        self.assertEqual("/api/runs", root["routes"]["runs"])
        self.assertEqual("ok", root["status"]["status"])

        status = self._get("/status")
        self.assertEqual("ok", status["status"])
        self.assertIn("archive_sha256", status)

    def test_case_endpoint_is_blind_and_post_run_is_scored(self) -> None:
        contract = self._get("/api/contract")
        self.assertEqual(["eval", "challenge"], contract["runnable_splits"])
        self.assertNotIn("train", contract["runnable_splits"])
        selected = self._get("/api/cases?split=eval&count=1&seed=api-test")
        case = selected["cases"][0]
        self.assertEqual({"id", "source_id", "task", "input"}, set(case))
        self.assertNotIn("target", case)

        body = json.dumps({"split": "eval", "case_id": case["id"]}).encode("utf-8")
        request = Request(
            self.base_url + "/api/runs",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            receipt = json.loads(response.read())
        self.assertEqual("SCORED", receipt["status"])
        self.assertEqual("post_response_only", receipt["metadata"]["answer_access"])
