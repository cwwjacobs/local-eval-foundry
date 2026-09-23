# EvalFoundry local API

The engine binds to loopback only. It owns dataset access, split enforcement,
model invocation, scoring, and receipts. A UI owns presentation only.

## Safety and data boundary

- The engine sends one blind case per `POST /api/runs` request.
- Only one model call can be active at a time; a second request receives `409`.
- No timer, auto-hop, fallback label, retry, or batch worker exists.
- Eval/challenge answer keys are read only after raw model output is persisted.
- All runs are `diagnostic 1/N`; the engine does not call a partial result a
  benchmark score.
- `SCORED` requires both the sealed priority and the complete structured rubric
  trace to match a fresh local computation. Any optional explanation is shown
  as unverified model-authored text, never as ground truth.

## Endpoints

### `GET /health`

Returns engine readiness, archive hash, split sizes, training-artifact metadata,
and non-secret model configuration.

### `GET /api/contract`

Returns the versioned request/response contract a UI should render against;
it includes only runnable split names and never dataset labels.

### `GET /api/cases?split=eval&count=1&seed=demo-01`

Returns deterministic blind cases. The response includes `selection_seed` so a
UI can reproduce selection. It never includes `target`, `rubric_trace`,
provenance, or answer data.

### `GET /api/cases/{split}/{case_id}`

Returns one blind case from `eval` or `challenge`. Training is intentionally
available only as a fine-tuning artifact, never as a live model-run route.

### `POST /api/runs`

Runs exactly one local-model request.

```json
{
  "split": "eval",
  "case_id": "nvd-modern-cve20262075",
  "selection_seed": "optional-ui-selection-seed"
}
```

The response is a receipt. Its status is:

- `SCORED` — valid JSON, matching sealed answer, and matching rubric trace;
- `HOLD` — a response was saved but is malformed or does not match;
- `FAILED` — the local provider failed before a response artifact existed.

### `GET /api/runs/{run_id}` and `GET /api/runs?limit=20`

Retrieve stored receipts.

### `GET /api/training`

Returns metadata for the only fine-tuning source:
`export/train_8000.sft_messages.jsonl`. It does not stream labels into a live
model run.

## UI integration rules

1. Ask for a case, render evidence, and have the person explicitly start the
   one model call.
2. Do not calculate, decorate, or invent a score client-side.
3. Render an engine receipt verbatim enough to distinguish `SCORED`, `HOLD`,
   and `FAILED`.
4. Never send model credentials through the UI. The engine reads an optional
   `LM_API_TOKEN` environment variable and, when it is set, sends it to the
   configured model endpoint as `Authorization: Bearer <token>`. When it is
   unset, no credential is sent.
5. If UI and engine are not same-origin, start the engine with the exact
   `--allow-origin` value rather than opening CORS broadly by default.
