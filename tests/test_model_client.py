from __future__ import annotations

import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from evalfoundry.errors import ModelProtocolError, UnsupportedEndpoint
from evalfoundry.model_client import OpenAICompatibleClient, completion_url
from evalfoundry.models import CaseRecord, ModelConfig

from tests.helpers import evidence


class _ProviderHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        if getattr(self.server, "redirect", False):  # type: ignore[attr-defined]
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/")
            self.end_headers()
            return
        size = int(self.headers["Content-Length"])
        self.server.captured = {  # type: ignore[attr-defined]
            "path": self.path,
            "headers": dict(self.headers),
            "body": json.loads(self.rfile.read(size)),
        }
        if self.path == "/api/v1/chat":
            response_payload = {
                "output": [{"type": "message", "content": '{"triage_priority":"critical"}'}],
                "stats": {
                    "input_tokens": 17,
                    "total_output_tokens": 2,
                    "reasoning_output_tokens": 0,
                    "tokens_per_second": 76.7,
                    "time_to_first_token_seconds": 0.3678,
                },
            }
        else:
            response_payload = {
                "id": "local-test-1",
                "choices": [{"message": {"content": '{"triage_priority":"high"}'}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
            }
        response = json.dumps(response_payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args) -> None:
        pass


class ModelClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
        self.server.redirect = False  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def test_adapter_sends_only_blind_evidence(self) -> None:
        endpoint = f"http://127.0.0.1:{self.server.server_port}"
        client = OpenAICompatibleClient(ModelConfig(endpoint=endpoint, model="fake", seed=123))
        case = CaseRecord(
            case_id="nvd-modern-cve202600001",
            source_id="CVE-2026-00001",
            split="eval",
            task="classify",
            evidence=evidence(),
        )
        completion, _ = client.complete(case)
        captured = self.server.captured  # type: ignore[attr-defined]
        prompt = json.loads(captured["body"]["messages"][1]["content"])
        self.assertEqual("/v1/chat/completions", captured["path"])
        self.assertNotIn("Authorization", captured["headers"])
        self.assertEqual({"source_id", "task", "input"}, set(prompt["evidence"]))
        self.assertNotIn("target", prompt["evidence"])
        self.assertEqual(123, captured["body"]["seed"])
        self.assertEqual("high", completion.parsed["triage_priority"])
        self.assertEqual("openai_compatible", client.public_config["transport"])

    def test_lm_studio_native_chat_transport_and_stats(self) -> None:
        endpoint = f"http://127.0.0.1:{self.server.server_port}"
        client = OpenAICompatibleClient(
            ModelConfig(
                endpoint=endpoint,
                model="google/gemma-4-e2b",
                max_tokens=64,
                transport="lm_studio_chat",
            )
        )
        case = CaseRecord("id", "CVE-2026-1", "eval", "classify", evidence())

        completion, messages = client.complete(case)

        captured = self.server.captured  # type: ignore[attr-defined]
        self.assertEqual("/api/v1/chat", captured["path"])
        self.assertEqual(
            {
                "model": "google/gemma-4-e2b",
                "input": json.dumps(messages, ensure_ascii=False, separators=(",", ":")),
                "reasoning": "off",
                "temperature": 0.0,
                "max_output_tokens": 64,
                "store": False,
            },
            captured["body"],
        )
        self.assertEqual("critical", completion.parsed["triage_priority"])
        self.assertEqual(17, completion.provider_stats["input_tokens"])
        self.assertEqual(2, completion.provider_stats["total_output_tokens"])
        self.assertEqual("lm_studio_chat", client.public_config["transport"])

    def test_lm_studio_native_chat_rejects_seed(self) -> None:
        endpoint = f"http://127.0.0.1:{self.server.server_port}"
        with self.assertRaises(ModelProtocolError):
            OpenAICompatibleClient(
                ModelConfig(endpoint=endpoint, model="fake", seed=1, transport="lm_studio_chat")
            )

    def test_adapter_uses_lm_studio_token_from_environment(self) -> None:
        endpoint = f"http://127.0.0.1:{self.server.server_port}"
        original = os.environ.get("LM_API_TOKEN")
        os.environ["LM_API_TOKEN"] = "lmst-test-token"
        try:
            client = OpenAICompatibleClient(ModelConfig(endpoint=endpoint, model="fake"))
            case = CaseRecord("id", "CVE-2026-1", "eval", "classify", evidence())
            client.complete(case)
            captured = self.server.captured  # type: ignore[attr-defined]
            self.assertEqual("Bearer lmst-test-token", captured["headers"]["Authorization"])
            self.assertEqual("bearer_env", client.public_config["auth_mode"])
        finally:
            if original is None:
                os.environ.pop("LM_API_TOKEN", None)
            else:
                os.environ["LM_API_TOKEN"] = original

    def test_remote_endpoint_requires_explicit_override(self) -> None:
        with self.assertRaises(UnsupportedEndpoint):
            completion_url("https://example.com")

    def test_redirect_is_blocked(self) -> None:
        endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.server.redirect = True  # type: ignore[attr-defined]
        client = OpenAICompatibleClient(ModelConfig(endpoint=endpoint, model="fake"))
        case = CaseRecord("id", "CVE-2026-1", "eval", "classify", evidence())
        with self.assertRaises(ModelProtocolError) as raised:
            client.complete(case)
        self.assertIn("redirect blocked", str(raised.exception).lower())

    def test_proxy_environment_is_not_used_for_loopback_model(self) -> None:
        endpoint = f"http://127.0.0.1:{self.server.server_port}"
        original = os.environ.get("HTTP_PROXY")
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:1"
        try:
            client = OpenAICompatibleClient(ModelConfig(endpoint=endpoint, model="fake"))
            case = CaseRecord("id", "CVE-2026-1", "eval", "classify", evidence())
            completion, _ = client.complete(case)
            self.assertEqual("high", completion.parsed["triage_priority"])
        finally:
            if original is None:
                os.environ.pop("HTTP_PROXY", None)
            else:
                os.environ["HTTP_PROXY"] = original
