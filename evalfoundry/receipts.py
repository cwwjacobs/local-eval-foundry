"""Durable local receipts without credentials, answer keys, or filesystem paths."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .models import RunReceipt

if TYPE_CHECKING:
    from .signing import ReceiptSigner

_SENSITIVE_RECEIPT_KEYS = frozenset(
    {"authorization", "api_key", "apikey", "password", "secret", "answer_key", "archive_path"}
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)([\"']?(?:api[_-]?key|authorization|password|secret|bearer)[\"']?\s*[:=]\s*)([\"'][^\"']*[\"']|[^\s,}]+)"
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _redact_text(value: str) -> str:
    return _SENSITIVE_ASSIGNMENT.sub(r"\1[REDACTED]", value)


def _sanitize_receipt(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if str(key).lower() in _SENSITIVE_RECEIPT_KEYS
            else _sanitize_receipt(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_receipt(child) for child in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


class ReceiptStore:
    """A SQLite index plus independently portable JSON receipts.

    When constructed with an optional ``ReceiptSigner``, every saved receipt
    is signed over its canonical bytes with the signer's current key ID. A
    signature proves integrity under that key only — never model or evaluator
    truthfulness. Without a signer, receipts are stored unsigned as before.
    """

    def __init__(self, state_dir: str | Path, signer: ReceiptSigner | None = None) -> None:
        self.signer = signer
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.receipt_dir = self.state_dir / "receipts"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.receipt_dir.mkdir(parents=True, exist_ok=True)
        self.database_path = self.state_dir / "evalfoundry.sqlite3"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self):
        """Commit and close every SQLite handle (important on Windows)."""
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    split TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    archive_sha256 TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    receipt_json TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs(created_at)")

    def save(self, receipt: RunReceipt) -> Path:
        payload = receipt.as_dict()
        payload = _sanitize_receipt(payload)
        if self.signer is not None:
            payload = self.signer.sign(payload)
        encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        destination = self.receipt_dir / f"{receipt.run_id}.json"
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.receipt_dir, delete=False, suffix=".tmp"
        ) as temporary:
            temporary.write(encoded)
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, destination)

        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO runs (
                    run_id, created_at, status, scope, split, case_id,
                    archive_sha256, model_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status=excluded.status,
                    receipt_json=excluded.receipt_json
                """,
                (
                    receipt.run_id,
                    receipt.created_at,
                    receipt.status,
                    receipt.scope,
                    receipt.case.split,
                    receipt.case.case_id,
                    receipt.archive_sha256,
                    str(receipt.model.get("model", "unknown")),
                    encoded,
                ),
            )
        return destination

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT receipt_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return json.loads(row["receipt_json"]) if row else None

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 100))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT receipt_json FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row["receipt_json"]) for row in rows]
