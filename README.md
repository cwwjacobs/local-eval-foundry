# Local EvalFoundry

**Local execution and verification for sealed, deterministic, provenance-bound AI evaluation packs.**

EvalFoundry runs blind evaluation cases against a local or explicitly approved
OpenAI-compatible model endpoint, stores the raw response before scoring, opens
sealed answers only after the response exists, recomputes gold labels from local
rubric code, and emits portable receipts.

It is not an LLM-as-judge dashboard. It is the small, strict layer underneath an
evaluation result that answers:

- Which exact pack was run?
- Was the pack manifest intact and pinned?
- What evidence did the model actually receive?
- Were labels and rubric traces withheld until after inference?
- Can the published answer be recomputed locally?
- What narrow claim does the score support?

## Core properties

- **Blind model surface:** only `id`, `source_id`, `task`, and `input` leave the vault.
- **Sealed scoring:** answer keys are opened only after the raw response is persisted.
- **Deterministic gold:** local rubric code, not another model, computes expected results.
- **Provenance and integrity:** pack manifests, source pins, archive SHA-256 values, and claim boundaries travel with the result.
- **Canonical archives:** release ZIPs use sorted paths, fixed metadata, and `ZIP_STORED` bytes for cross-platform reproducibility.
- **Local-first transport:** loopback model endpoints by default; redirects and inherited HTTP proxies are blocked.
- **No hidden retries:** a single-case run performs exactly one explicit model call.
- **Explicit benchmark budget:** subset and full-split runs require a call budget equal to the selected case count.

"Blind" and "sealed" describe what the model sees and the order in which the
engine reads files at run time. They do not mean the answers are secret: the
public packs in this repository include their answer files, so anyone
(including a model trained on public code) can read them. Treat the public
packs as reproducibility and integration references, not as
contamination-resistant benchmarks.

## Included public packs

| Pack | Task | Labels | Status |
|---|---|---|---|
| **Policy Gate v1** | Apply an explicit policy requirement to an agent action | `allow`, `human_gate`, `deny` | Release reference pack |
| **Tool Contract v1** | Check a proposed tool call against schema and granted scope | `valid`, `malformed`, `over_scope`, `denied` | Release reference pack |
| Agent Ops Public v1 | Synthetic agent-operations plumbing cases | task-specific | Demonstration pack, outside release reproducibility claim |

The legacy NVD source-priority pack remains supported as a reference vertical,
but it is not the product identity and it is not distributed in this
repository. Examples in `docs/` that mention `nvd-*` case IDs or
`train_8000` files refer to that pack.

## Install

Requires Python 3.11 or newer.

```bash
python -m pip install -e .
```

EvalFoundry has no runtime Python dependencies.

Pack ZIPs are build outputs and are not committed. Build them (next section)
before running `verify`, `select`, `run`, or the pack-dependent tests.

## Build canonical release packs

```bash
python scripts/build_release_packs.py
```

The release builder invokes the Policy Gate and Tool Contract builders and then
rewrites both ZIPs into the canonical `canonical-zip-stored-v1` representation.
SHA-256 sidecars are updated only after canonicalization.

CI performs this release build twice and rejects any hash drift. Agent Ops is
built once separately so its demonstration tests still run without expanding
the 1.0 release claim.

## Verify a release pack

```bash
evalfoundry verify \
  --archive packs/policy-gate-public-v1.zip \
  --pack policy_gate \
  --expected-sha256 "$(cat packs/policy-gate-public-v1.SHA256)"
```

Verification checks the ZIP, file manifest, supplied archive pin, blind split
shape, provenance contract, and recomputed rubric alignment.

## Inspect blind cases

```bash
evalfoundry select \
  --archive packs/policy-gate-public-v1.zip \
  --pack policy_gate \
  --expected-sha256 "$(cat packs/policy-gate-public-v1.SHA256)" \
  --split eval \
  --count 3 \
  --selection-seed demo-01
```

This route never returns train records, sealed answers, or canonical traces.

## Run one explicit case

```bash
evalfoundry run \
  --archive packs/policy-gate-public-v1.zip \
  --pack policy_gate \
  --expected-sha256 "$(cat packs/policy-gate-public-v1.SHA256)" \
  --model-endpoint http://127.0.0.1:1234 \
  --model local-model \
  --split eval \
  --case-id <case-id> \
  --state-dir state
```

The engine stores an `UNSCORED` receipt before opening the sealed answer, then
updates the receipt to `SCORED`, `HOLD`, or `FAILED`.

## Run a deterministic benchmark

A bounded subset:

```bash
evalfoundry-benchmark \
  --archive packs/policy-gate-public-v1.zip \
  --pack policy_gate \
  --expected-sha256 "$(cat packs/policy-gate-public-v1.SHA256)" \
  --model-endpoint http://127.0.0.1:1234 \
  --model local-model \
  --split eval \
  --count 5 \
  --selection-seed release-check \
  --max-calls 5 \
  --state-dir state \
  --report benchmark-reports/policy-gate-subset.json
```

The complete Policy Gate evaluation split currently contains 16 cases. A full
split requires an explicit confirmation and matching call budget:

```bash
evalfoundry-benchmark \
  --archive packs/policy-gate-public-v1.zip \
  --pack policy_gate \
  --expected-sha256 "$(cat packs/policy-gate-public-v1.SHA256)" \
  --model-endpoint http://127.0.0.1:1234 \
  --model local-model \
  --split eval \
  --max-calls 16 \
  --confirm-full-split \
  --state-dir state \
  --report benchmark-reports/policy-gate-full.json
```

Aggregate reports include pack SHA, pin status, model configuration, selection
seed, call budget and usage, status counts, overall accuracy, per-task accuracy,
error counts, claim boundary, and the individual run receipt IDs. Existing
reports are never overwritten.

## Pack contract

A pack contains:

```text
reports/PACK_CONTRACT.json
reports/FILE_MANIFEST.tsv
reports/PROVENANCE.jsonl
reports/PUBLIC_SAFE.md
canonical/train_N.canonical.jsonl
export/eval_N.inputs.jsonl
export/challenge_N.inputs.jsonl
export/preview_N.jsonl
answers/eval_N.answers.jsonl
answers/challenge_N.answers.jsonl
```

Model-facing evaluation and challenge rows contain only blind fields. Training
records are not runnable splits. Preview records cannot be scored. Sealed answer
files are private to the post-response scoring path.

See [`packs/README.md`](packs/README.md) for the public reference packs,
reproducibility notes, and verification commands.

## Claim boundary

EvalFoundry demonstrates whether a model applies a declared deterministic pack
contract to supplied evidence. It does **not** certify that a model is generally
safe, secure, truthful, or suitable for an undeclared environment.

Receipts are durable and portable. They are not yet cryptographically signed or
tamper-proof.

## Development

```bash
python -m unittest discover -s tests -v
```

CI runs the suite on Python 3.11, 3.12, and 3.13, rebuilds the two release packs
twice, builds the Agent Ops demonstration once, verifies byte-stable release
hashes, and rejects known repository contamination paths.

## License

The EvalFoundry software is licensed under the **Apache License 2.0**.
Benchmark data and pack artifacts use the terms described in
[`DATA_LICENSE.md`](DATA_LICENSE.md); third-party source material retains its
original licensing and provenance.

Project site: **GTDataworks** — https://gtdataworks.com
