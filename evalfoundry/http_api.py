"""A narrow localhost JSON API for a separately owned UI."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .errors import BudgetExceeded, EvalFoundryError, ModelBusy, SplitAccessError
from .receipts import ReceiptStore
from .rubric import CLAIM_BOUNDARY, response_contract
from .runner import RunEngine
from .vault import DatasetVault


class ApiContext:
    def __init__(
        self,
        vault: DatasetVault,
        runner: RunEngine,
        store: ReceiptStore,
        *,
        allow_origin: str | None = None,
    ) -> None:
        self.vault = vault
        self.runner = runner
        self.store = store
        self.allow_origin = allow_origin


def make_handler(context: ApiContext) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "EvalFoundry/1.0.0"

        @staticmethod
        def _health_payload() -> dict[str, Any]:
            return {
                "status": "ok",
                "archive_sha256": context.vault.archive_sha256,
                "expected_archive_sha256": context.vault.expected_archive_sha256,
                "archive_provenance_pinned": context.vault.provenance_pinned,
                "split_sizes": context.vault.split_sizes,
                "training_artifact": context.vault.training_artifact(),
                "model": context.runner.client.public_config,
            }

        def log_message(self, format: str, *args: Any) -> None:
            # Keep logs useful without dumping evidence content or request bodies.
            message = format % args
            print(f"[EvalFoundry] {self.address_string()} {message}")

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            if context.allow_origin:
                self.send_header("Access-Control-Allow-Origin", context.allow_origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(raw)

        def _error(self, status: int, message: str) -> None:
            self._send_json(status, {"error": message})

        def _read_json(self) -> dict[str, Any]:
            length = self.headers.get("Content-Length")
            if length is None:
                raise ValueError("Content-Length is required.")
            try:
                size = int(length)
            except ValueError as error:
                raise ValueError("Content-Length must be an integer.") from error
            if size < 1 or size > 64 * 1024:
                raise ValueError("Request body must be between 1 byte and 64 KiB.")
            try:
                payload = json.loads(self.rfile.read(size).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("Request body must be a JSON object.") from error
            if not isinstance(payload, dict):
                raise ValueError("Request body must be a JSON object.")
            return payload

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(HTTPStatus.NO_CONTENT)
            if context.allow_origin:
                self.send_header("Access-Control-Allow-Origin", context.allow_origin)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.send_header("Vary", "Origin")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/":
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "service": "EvalFoundry",
                            "ui": "none",
                            "status": self._health_payload(),
                            "routes": {
                                "root": "/",
                                "health": "/health",
                                "status": "/status",
                                "contract": "/api/contract",
                                "cases": "/api/cases?split=eval&count=1&seed=demo-01",
                                "case": "/api/cases/{split}/{case_id}",
                                "runs": "/api/runs",
                                "run_receipt": "/api/runs/{run_id}",
                                "training": "/api/training",
                            },
                        },
                    )
                    return
                if parsed.path in {"/health", "/status"}:
                    self._send_json(HTTPStatus.OK, self._health_payload())
                    return
                if parsed.path == "/api/contract":
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "api_version": "v1",
                            "runnable_splits": ["eval", "challenge"],
                            "scope": "diagnostic",
                            "max_concurrency": 1,
                            "run_request": {
                                "type": "object",
                                "required": ["split", "case_id"],
                                "properties": {
                                    "split": {"enum": ["eval", "challenge"]},
                                    "case_id": {"type": "string"},
                                    "selection_seed": {"type": "string"},
                                },
                                "additionalProperties": False,
                            },
                            "model_response": response_contract(),
                            "claim_boundary": CLAIM_BOUNDARY,
                        },
                    )
                    return
                if parsed.path == "/api/cases":
                    query = parse_qs(parsed.query)
                    split = self._one(query, "split")
                    if split is None:
                        raise ValueError("Query parameter 'split' is required.")
                    count = int(self._one(query, "count", default="1"))
                    seed = self._one(query, "seed", default=None)
                    selection_seed, cases = context.vault.select_cases(split, count, seed)
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "scope": "diagnostic",
                            "split": split,
                            "selection_seed": selection_seed,
                            "full_split_size": context.vault.split_sizes[split],
                            "cases": [case.model_payload() for case in cases],
                        },
                    )
                    return
                if parsed.path.startswith("/api/cases/"):
                    pieces = parsed.path.split("/")
                    if len(pieces) != 5:
                        self._error(HTTPStatus.NOT_FOUND, "Unknown case route.")
                        return
                    split = unquote(pieces[3])
                    case_id = unquote(pieces[4])
                    case = context.vault.get_case(split, case_id)
                    self._send_json(HTTPStatus.OK, case.model_payload() | {"split": case.split})
                    return
                if parsed.path.startswith("/api/runs/"):
                    run_id = unquote(parsed.path.rsplit("/", 1)[-1])
                    receipt = context.store.get(run_id)
                    if receipt is None:
                        self._error(HTTPStatus.NOT_FOUND, "Run receipt not found.")
                    else:
                        self._send_json(HTTPStatus.OK, receipt)
                    return
                if parsed.path == "/api/runs":
                    query = parse_qs(parsed.query)
                    limit = int(self._one(query, "limit", default="20"))
                    self._send_json(HTTPStatus.OK, {"runs": context.store.recent(limit)})
                    return
                if parsed.path == "/api/training":
                    self._send_json(HTTPStatus.OK, context.vault.training_artifact())
                    return
                self._error(HTTPStatus.NOT_FOUND, "Unknown route.")
            except (ValueError, EvalFoundryError) as error:
                self._send_domain_error(error)

        def do_POST(self) -> None:  # noqa: N802
            if urlparse(self.path).path != "/api/runs":
                self._error(HTTPStatus.NOT_FOUND, "Unknown route.")
                return
            try:
                body = self._read_json()
                allowed = {"split", "case_id", "selection_seed"}
                extra = set(body) - allowed
                missing = {"split", "case_id"} - set(body)
                if extra or missing:
                    raise ValueError(
                        "Run requests require split and case_id and accept only optional selection_seed."
                    )
                result = context.runner.run_case(
                    split=str(body["split"]),
                    case_id=str(body["case_id"]),
                    selection_seed=(
                        str(body["selection_seed"]) if body.get("selection_seed") is not None else None
                    ),
                )
                self._send_json(HTTPStatus.OK, result)
            except (ValueError, EvalFoundryError) as error:
                self._send_domain_error(error)

        @staticmethod
        def _one(query: dict[str, list[str]], key: str, default: str | None = None) -> str | None:
            values = query.get(key)
            if not values:
                return default
            if len(values) != 1:
                raise ValueError(f"Query parameter {key!r} must occur once.")
            return values[0]

        def _send_domain_error(self, error: Exception) -> None:
            if isinstance(error, ModelBusy):
                status = HTTPStatus.CONFLICT
            elif isinstance(error, SplitAccessError):
                status = HTTPStatus.NOT_FOUND
            elif isinstance(error, BudgetExceeded):
                status = HTTPStatus.BAD_REQUEST
            else:
                status = HTTPStatus.BAD_REQUEST
            self._error(status, str(error))

    return Handler


def serve(
    context: ApiContext,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> ThreadingHTTPServer:
    """Create a loopback server. The caller owns serve_forever/shutdown."""
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("EvalFoundry only binds loopback addresses.")
    bind_host = "127.0.0.1" if host == "localhost" else host
    return ThreadingHTTPServer((bind_host, port), make_handler(context))
