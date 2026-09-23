from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

from evalfoundry.http_api import ApiContext, serve
from evalfoundry.model_client import OpenAICompatibleClient
from evalfoundry.models import ModelConfig
from evalfoundry.receipts import ReceiptStore
from evalfoundry.rubric import evaluate_rubric
from evalfoundry.runner import RunEngine
from evalfoundry.vault import APPROVED_FROZEN_ARCHIVE_SHA256, DatasetVault


ARCHIVE = os.environ.get("EVALFOUNDRY_ARCHIVE")


class _TruthfulLocalModel(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        prompt = json.loads(body["messages"][1]["content"])
        label, trace = evaluate_rubric(prompt["evidence"]["input"])
        self.server.captured = {"headers": dict(self.headers), "prompt": prompt}  # type: ignore[attr-defined]
        response = json.dumps(
            {
                "id": "truthful-local-model",
                "choices": [
                    {"message": {"content": json.dumps({"triage_priority": label, "rubric_trace": trace})}}
                ],
                "usage": {"completion_tokens": 30, "total_tokens": 400},
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args) -> None:
        pass


@unittest.skipUnless(ARCHIVE, "Set EVALFOUNDRY_ARCHIVE to run real archive API integration.")
class RealHttpArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.provider = ThreadingHTTPServer(("127.0.0.1", 0), _TruthfulLocalModel)
        self.provider_thread = threading.Thread(target=self.provider.serve_forever, daemon=True)
        self.provider_thread.start()

        vault = DatasetVault(
            ARCHIVE, expected_sha256=APPROVED_FROZEN_ARCHIVE_SHA256, strict_contract=True
        )
        store = ReceiptStore(Path(self.temp.name) / "state")
        client = OpenAICompatibleClient(
            ModelConfig(endpoint=f"http://127.0.0.1:{self.provider.server_port}", model="test-local")
        )
        self.engine_server = serve(ApiContext(vault, RunEngine(vault, store, client), store), port=0)
        self.engine_thread = threading.Thread(target=self.engine_server.serve_forever, daemon=True)
        self.engine_thread.start()
        self.base_url = f"http://127.0.0.1:{self.engine_server.server_port}"

    def tearDown(self) -> None:
        self.engine_server.shutdown()
        self.engine_server.server_close()
        self.engine_thread.join(timeout=3)
        self.provider.shutdown()
        self.provider.server_close()
        self.provider_thread.join(timeout=3)
        self.temp.cleanup()

    def test_real_archive_case_stays_blind_through_local_model(self) -> None:
        with urlopen(self.base_url + "/api/cases?split=eval&count=1&seed=real-api", timeout=10) as response:
            selected = json.loads(response.read())
        case = selected["cases"][0]
        request = Request(
            self.base_url + "/api/runs",
            data=json.dumps({"split": "eval", "case_id": case["id"]}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=10) as response:
            receipt = json.loads(response.read())
        captured = self.provider.captured  # type: ignore[attr-defined]
        self.assertEqual("SCORED", receipt["status"])
        self.assertEqual({"source_id", "task", "input"}, set(captured["prompt"]["evidence"]))
        self.assertNotIn("target", captured["prompt"]["evidence"])
        self.assertNotIn("Authorization", captured["headers"])
        self.assertTrue(receipt["metadata"]["archive_provenance_pinned"])
