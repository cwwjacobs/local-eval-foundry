# Receipt signing

EvalFoundry receipts are portable JSON documents. Optional signing makes them
tamper-evident for third-party verification. Signing is opt-in: engines and
stores work exactly as before unless a keyring is supplied, and unsigned
receipts remain valid output.

## Trust model — read this first

A valid signature proves **integrity under a key**: the canonical bytes of the
receipt matched a key in the verifying keyring, under an explicit signer key
ID. It does **not** prove model or evaluator truthfulness. A wrong, misled, or
compromised scorer can still produce a perfectly signed false receipt, and a
stolen key can be used to sign anything. Signing answers "was this receipt
modified after the signer wrote it?" — never "is this result true?"

Keys are symmetric 256-bit HMAC-SHA256 keys (Python standard-library
`hmac`/`hashlib`; the project deliberately has no third-party crypto
dependency). Verification requires the same key material as signing, so a
keyring is a **private artifact**: anyone holding a key can sign as that key
ID. Keep keyrings on the signing host, owner-only. EvalFoundry creates them
with mode `0600` and never overwrites an existing keyring.

## Canonical form

Every signature covers `canonical_receipt_bytes(receipt)`:

- UTF-8 JSON, every object key sorted recursively (`sort_keys=True`)
- compact separators `,` and `:` — no insignificant whitespace
- `ensure_ascii=True` — bytes are locale-independent
- the top-level `signature` member is excluded from the signed payload
- non-finite floats are rejected (`allow_nan=False`)

The identifier `json-sort-keys-compact-ascii` is recorded in each signature.
Because verification re-canonicalizes the parsed JSON, reformatting a receipt
file (indentation, member order) never changes what verifies.

A signed receipt adds one top-level member:

```json
"signature": {
  "algorithm": "HMAC-SHA256",
  "canonicalization": "json-sort-keys-compact-ascii",
  "key_id": "release-2026-09",
  "value": "<64 lowercase hex>"
}
```

## Keyring and rotation

A keyring is a versioned JSON document with named keys and one explicit
current signer:

```json
{
  "version": 1,
  "current": "release-2026-09",
  "keys": {
    "release-2026-09": {"key_hex": "<64 hex>", "state": "active",
                        "created_at": "2026-09-24T00:00:00Z"},
    "release-2026-06": {"key_hex": "<64 hex>", "state": "retired",
                        "created_at": "2026-06-01T00:00:00Z",
                        "retired_at": "2026-09-24T00:00:00Z"}
  }
}
```

- Key IDs are explicit signer identities chosen by the operator.
- Only the `current` key signs, and only while its state is `active`.
- `rotate-key` adds the new key as current and retires the previous one.
  Retired keys are **retained**: receipts they signed keep verifying, but a
  retired key can never sign again.
- Deleting a retired key from the keyring abandons verification of the
  receipts it signed — retain keys for as long as their receipts matter.

## Verification statuses

`evalfoundry verify-receipt` exits `0` only when the signature is valid. The
JSON verdict distinguishes the failure modes:

| status              | meaning                                                        |
|---------------------|----------------------------------------------------------------|
| `valid`             | canonical bytes match the named key                            |
| `unsigned_receipt`  | no `signature` member (not an error for opt-out flows)         |
| `unknown_key_id`    | the claimed signer ID is not in the keyring (wrong/forged IDs) |
| `invalid_signature` | key is known but the HMAC does not match (mutation/wrong key)  |

`unknown_key_id` and `invalid_signature` are deliberately distinct: an unknown
ID means the verifier has no key for that signer at all, while an invalid
signature means the identified key exists and the content does not match it.

## Commands

```bash
evalfoundry keygen --keyring keys/signing.json --key-id release-2026-09
evalfoundry rotate-key --keyring keys/signing.json --new-key-id release-2026-12
evalfoundry verify-receipt --receipt state/receipts/<run-id>.json --keyring keys/signing.json

# Opt any receipt-writing flow into signing:
evalfoundry run ... --keyring keys/signing.json
evalfoundry serve ... --keyring keys/signing.json
evalfoundry-benchmark ... --keyring keys/signing.json
```

When `--keyring` is set, `ReceiptStore` signs the sanitized receipt on every
save, so the persisted `UNSCORED` receipt and its final `SCORED`/`HOLD`/`FAILED`
update each verify against their own content. Nothing about sealing, blinding,
call budgets, or scoring changes.
