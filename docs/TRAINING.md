# Train-only structured trace SFT

`build-trace-sft` creates a new JSONL artifact from only
`canonical/train_8000.canonical.jsonl`.

Each row uses the exact prompt contract sent during a local evaluation and an
assistant target containing:

```json
{
  "triage_priority": "high",
  "rubric_trace": {
    "rubric_version": "source-priority-v2.0",
    "base_points": 5,
    "urgency_signals": ["NETWORK", "NO_AUTH"],
    "dampening_signals": [],
    "final_points": 7,
    "assigned_triage_priority": "high"
  }
}
```

The trace is recomputed locally from the frozen evidence before it is written.
It is not an LLM-produced explanation. Optional explanation text from a model
at evaluation time remains unverified model-authored text.

The command requires an explicit new output path and writes a companion receipt
with archive hash, ordered-ID digest, output hash, record count, and claim
boundary. It never overwrites an existing artifact and never uses eval,
challenge, preview, answer, or full-canonical rows.
