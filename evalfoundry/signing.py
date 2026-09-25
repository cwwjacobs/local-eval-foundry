"""Optional receipt signing over a canonical form, with explicit signer identity and key rotation.

A valid signature proves only integrity under a key: the canonical bytes of
the receipt matched a key held in the verifying keyring, under an explicit
signer key ID. It does NOT prove model or evaluator truthfulness — a wrong
or compromised scorer can still emit a well-signed false receipt. Signing is
opt-in; unsigned receipts remain valid engine output.

Canonical form ("json-sort-keys-compact-ascii"):

- UTF-8 JSON with every object key sorted recursively (``sort_keys=True``)
- compact separators ``,`` and ``:`` — no insignificant whitespace
- ``ensure_ascii=True`` so the signed bytes are locale-independent
- the top-level ``signature`` member is excluded from the signed payload
- non-finite floats are rejected (``allow_nan=False``)

Key model: symmetric 256-bit HMAC-SHA256 keys in a versioned JSON keyring.
EvalFoundry has no third-party crypto dependency, so signing uses the
standard-library ``hmac``/``hashlib`` primitives. Anyone holding a key can
sign as that key ID, so a keyring is a private artifact: keep it on the
signing host with owner-only permissions (created ``0600``). Key IDs are
explicit signer identities chosen by the operator, e.g. ``release-2026-09``.

Keyring format (version 1)::

    {
      "version": 1,
      "current": "release-2026-09",
      "keys": {
        "release-2026-09": {"key_hex": "<64 hex>", "state": "active",
                            "created_at": "<utc iso8601>"},
        "release-2026-06": {"key_hex": "<64 hex>", "state": "retired",
                            "created_at": "<utc iso8601>",
                            "retired_at": "<utc iso8601>"}
      }
    }

``current`` is the explicit current signer ID and the only key that signs.
Retired keys are retained so receipts they signed keep verifying; rotation
adds a new active key, makes it current, and retires the previous one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .errors import SigningError

CANONICALIZATION = "json-sort-keys-compact-ascii"
ALGORITHM = "HMAC-SHA256"
KEYRING_VERSION = 1
_KEY_BYTES = 32
_ACTIVE = "active"
_RETIRED = "retired"

STATUS_VALID = "valid"
STATUS_UNSIGNED = "unsigned_receipt"
STATUS_UNKNOWN_KEY = "unknown_key_id"
STATUS_INVALID = "invalid_signature"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def canonical_receipt_bytes(receipt: Mapping[str, Any]) -> bytes:
    """Serialize a receipt payload to its signed canonical bytes.

    The top-level ``signature`` member is excluded so a signed receipt
    verifies against the same bytes that were signed.
    """
    payload = {key: value for key, value in receipt.items() if key != "signature"}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying one receipt. ``status`` distinguishes the failure modes."""

    status: str
    key_id: str | None
    detail: str

    @property
    def ok(self) -> bool:
        return self.status == STATUS_VALID

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "ok": self.ok, "key_id": self.key_id, "detail": self.detail}


def _validate_key_id(key_id: Any) -> str:
    if not isinstance(key_id, str) or not key_id.strip() or key_id != key_id.strip():
        raise SigningError("A signer key ID must be a non-empty string without surrounding whitespace.")
    return key_id


class Keyring:
    """A versioned set of named HMAC keys with one explicit current signer."""

    def __init__(self, keys: dict[str, dict[str, Any]], current: str | None) -> None:
        self._keys = keys
        self._current = current

    @classmethod
    def create(cls, path: str | Path, *, key_id: str) -> "Keyring":
        """Create a new keyring file with one active key. Never overwrites."""
        destination = Path(path).expanduser()
        keyring = cls({}, None)
        keyring.add_key(key_id)
        keyring._current = key_id
        keyring._write(destination, overwrite=False)
        return keyring

    @classmethod
    def load(cls, path: str | Path) -> "Keyring":
        source = Path(path).expanduser()
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise SigningError(f"Keyring not found: {source}") from None
        except json.JSONDecodeError as error:
            raise SigningError(f"Keyring is not valid JSON: {source} ({error})") from None
        if not isinstance(raw, dict) or raw.get("version") != KEYRING_VERSION:
            raise SigningError(f"Unsupported keyring format in {source}; expected version {KEYRING_VERSION}.")
        keys = raw.get("keys")
        current = raw.get("current")
        if not isinstance(keys, dict) or not keys:
            raise SigningError(f"Keyring {source} has no keys.")
        for key_id, entry in keys.items():
            _validate_key_id(key_id)
            if not isinstance(entry, dict) or entry.get("state") not in (_ACTIVE, _RETIRED):
                raise SigningError(f"Keyring entry {key_id!r} must declare state 'active' or 'retired'.")
            key_hex = entry.get("key_hex")
            if not isinstance(key_hex, str) or len(key_hex) != _KEY_BYTES * 2:
                raise SigningError(f"Keyring entry {key_id!r} must hold a {_KEY_BYTES}-byte hex key.")
            try:
                bytes.fromhex(key_hex)
            except ValueError:
                raise SigningError(f"Keyring entry {key_id!r} holds non-hex key material.") from None
        if current is not None:
            _validate_key_id(current)
            if current not in keys:
                raise SigningError(f"Keyring current signer {current!r} has no key entry.")
        return cls(dict(keys), current)

    def save(self, path: str | Path) -> None:
        self._write(Path(path).expanduser(), overwrite=True)

    def _write(self, destination: Path, *, overwrite: bool) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(self.as_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=destination.parent, delete=False, suffix=".tmp"
            ) as temporary:
                temporary_path = Path(temporary.name)
                # NamedTemporaryFile creates this inode owner-only. Publish only
                # after all bytes have been written and the file is closed.
                temporary.write(encoded)
                temporary.flush()
                os.fsync(temporary.fileno())
            if overwrite:
                os.replace(temporary_path, destination)
            else:
                # Atomic no-clobber publication, including dangling symlinks.
                # Never fall back to replace on filesystems without hard links.
                os.link(temporary_path, destination)
        except FileExistsError:
            raise SigningError(
                f"Keyring already exists: {destination}. Existing keyrings are never overwritten."
            ) from None
        except OSError as error:
            raise SigningError(f"Cannot publish keyring {destination}: {error}") from error
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def as_dict(self) -> dict[str, Any]:
        return {"version": KEYRING_VERSION, "current": self._current, "keys": self._keys}

    @property
    def current_key_id(self) -> str | None:
        return self._current

    def key_ids(self) -> list[str]:
        return sorted(self._keys)

    def key_state(self, key_id: str) -> str | None:
        entry = self._keys.get(key_id)
        return entry["state"] if entry else None

    def add_key(self, key_id: str) -> None:
        """Generate a new active key under an explicit signer identity."""
        key_id = _validate_key_id(key_id)
        if key_id in self._keys:
            raise SigningError(f"Key ID {key_id!r} already exists in this keyring.")
        self._keys[key_id] = {
            "key_hex": secrets.token_hex(_KEY_BYTES),
            "state": _ACTIVE,
            "created_at": _utc_now(),
        }

    def retire(self, key_id: str) -> None:
        """Mark a key verify-only. Retained keys keep verifying old receipts."""
        entry = self._keys.get(key_id)
        if entry is None:
            raise SigningError(f"Cannot retire unknown key ID {key_id!r}.")
        if entry["state"] == _RETIRED:
            raise SigningError(f"Key ID {key_id!r} is already retired.")
        entry["state"] = _RETIRED
        entry["retired_at"] = _utc_now()

    def rotate(self, new_key_id: str) -> str | None:
        """Add a new current signer and retire the previous one. Returns the old signer ID."""
        previous = self._current
        self.add_key(new_key_id)
        self._current = new_key_id
        if previous is not None:
            self.retire(previous)
        return previous

    def signing_key(self) -> tuple[str, bytes]:
        """Return the current signer ID and key. Only an active current key may sign."""
        if self._current is None:
            raise SigningError("Keyring has no current signer; rotate in a new key before signing.")
        entry = self._keys[self._current]
        if entry["state"] != _ACTIVE:
            raise SigningError(
                f"Current signer {self._current!r} is retired; retired keys verify but never sign."
            )
        return self._current, bytes.fromhex(entry["key_hex"])

    def verification_key(self, key_id: str) -> bytes | None:
        """Return key material for any known ID, active or retired; None when unknown."""
        entry = self._keys.get(key_id)
        return bytes.fromhex(entry["key_hex"]) if entry else None


class ReceiptSigner:
    """Signs receipt payloads with the keyring's current active key."""

    def __init__(self, keyring: Keyring) -> None:
        self.keyring = keyring

    @property
    def key_id(self) -> str:
        key_id, _ = self.keyring.signing_key()
        return key_id

    def sign(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        """Return a copy of the receipt carrying a ``signature`` member.

        Any existing ``signature`` member is replaced: the signature always
        covers the current canonical content under the current signer ID.
        """
        key_id, key = self.keyring.signing_key()
        digest = hmac.new(key, canonical_receipt_bytes(receipt), hashlib.sha256).hexdigest()
        signed = {key_name: value for key_name, value in receipt.items() if key_name != "signature"}
        signed["signature"] = {
            "algorithm": ALGORITHM,
            "canonicalization": CANONICALIZATION,
            "key_id": key_id,
            "value": digest,
        }
        return signed


def verify_receipt(receipt: Mapping[str, Any], keyring: Keyring) -> VerificationResult:
    """Verify a receipt's signature against a keyring.

    The result status is deliberately distinct per failure mode:
    ``unsigned_receipt`` (no signature member), ``unknown_key_id`` (the
    claimed signer is not in the keyring — including wrong key IDs), and
    ``invalid_signature`` (the key is known but the HMAC does not match —
    content mutation or wrong key material).
    """
    signature = receipt.get("signature")
    if signature is None:
        return VerificationResult(STATUS_UNSIGNED, None, "Receipt carries no signature member.")
    if not isinstance(signature, dict):
        return VerificationResult(STATUS_INVALID, None, "Signature member is not an object.")
    key_id = signature.get("key_id")
    value = signature.get("value")
    if signature.get("algorithm") != ALGORITHM:
        return VerificationResult(STATUS_INVALID, key_id if isinstance(key_id, str) else None,
                                  f"Unsupported signature algorithm: {signature.get('algorithm')!r}.")
    if signature.get("canonicalization") != CANONICALIZATION:
        return VerificationResult(STATUS_INVALID, key_id if isinstance(key_id, str) else None,
                                  f"Unsupported canonicalization: {signature.get('canonicalization')!r}.")
    if not isinstance(key_id, str) or not isinstance(value, str):
        return VerificationResult(STATUS_INVALID, None, "Signature must carry string key_id and value.")
    key = keyring.verification_key(key_id)
    if key is None:
        return VerificationResult(STATUS_UNKNOWN_KEY, key_id,
                                  f"Signer key ID {key_id!r} is not in the keyring.")
    expected = hmac.new(key, canonical_receipt_bytes(receipt), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, value.lower()):
        return VerificationResult(STATUS_INVALID, key_id,
                                  "Signature does not match the canonical receipt bytes under this key.")
    return VerificationResult(STATUS_VALID, key_id, "Signature matches the canonical receipt bytes.")


def load_signer(keyring_path: str | Path) -> ReceiptSigner:
    """Load a keyring and return a signer over its current active key."""
    return ReceiptSigner(Keyring.load(keyring_path))
