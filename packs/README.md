# EvalFoundry packs

## tool-contract-public-v1 (T3 — DAP fruit)

| | |
|--|--|
| **ZIP** | `tool-contract-public-v1.zip` |
| **SHA-256** | see `tool-contract-public-v1.SHA256` |
| **Kind** | `tool_contract_public_v1` |
| **Task** | `tool-contract-v1` → `valid` \| `malformed` \| `over_scope` \| `denied` |
| **Public-safe** | Yes — public API/MCP/OpenAPI/RFC doc patterns |
| **Provenance** | `reports/PROVENANCE.jsonl` (required) |
| **Atoms** | `../atoms/t3_tool_public/atoms.jsonl` |

Splits: train 24 · eval 16 · challenge 12 · preview 8 (60 total).

```bash
python3 scripts/admit_public.py \
  --input feedstock/t3_tool_public/sources.jsonl \
  --output atoms/t3_tool_public/atoms.jsonl \
  --lexicon t3

python3 scripts/build_t3_tool_contract_v1.py
python3 -m evalfoundry verify --archive packs/tool-contract-public-v1.zip --pack tool_contract
```

---

## policy-gate-public-v1 (T2 — DAP fruit)

| | |
|--|--|
| **ZIP** | `policy-gate-public-v1.zip` |
| **SHA-256** | see `policy-gate-public-v1.SHA256` |
| **Kind** | `policy_gate_public_v1` |
| **Task** | `policy-shall-gate-v1` |
| **Public-safe** | Yes — US gov public control summaries + structured actions |
| **Provenance** | `reports/PROVENANCE.jsonl` (required) |
| **Atoms** | `../atoms/t2_policy_public/atoms.jsonl` |

Splits: train 24 · eval 16 · challenge 12 · preview 8 (60 total).

```bash
python3 scripts/admit_public.py \
  --input feedstock/t2_policy_public/sources.jsonl \
  --output atoms/t2_policy_public/atoms.jsonl

python3 scripts/build_t2_policy_gate_v1.py
python3 -m evalfoundry verify --archive packs/policy-gate-public-v1.zip --pack policy_gate
```


---

## agent-ops-public-v1 (public-safe plumbing; not T2 bar-setter)

| | |
|--|--|
| **ZIP** | `agent-ops-public-v1.zip` |
| **SHA-256** | see `agent-ops-public-v1.SHA256` (also pinned in `evalfoundry/vault.py`) |
| **Kind** | `agent_ops_public_v1` |
| **Public-safe** | **Yes** — synthetic only |

### Splits

| Split | N |
|-------|--:|
| train | 80 |
| eval | 40 |
| challenge | 30 |
| preview | 20 |

### Tasks

1. **`agent-domain-multi-hit-v1`** — multi-hit market domain labels (`|` joined or `NONE`)
2. **`action-gate-v1`** — `allow` \| `human_gate` \| `deny`
3. **`skill-pack-checklist-v1`** — missing required paths or `COMPLETE`

### CLI

```bash
python3 -m evalfoundry verify --archive packs/agent-ops-public-v1.zip --pack agent_ops
python3 -m evalfoundry select --archive packs/agent-ops-public-v1.zip --pack agent_ops --split eval --count 5
python3 -m evalfoundry case --archive packs/agent-ops-public-v1.zip --pack agent_ops --split eval --case-id <id>
```

### Rebuild

```bash
python3 scripts/build_agent_ops_public_v1.py
# then update APPROVED_AGENT_OPS_PUBLIC_V1_SHA256 in evalfoundry/vault.py if hash changes
```

### Public-safe rules

- No personal identifiers, emails, or account handles
- No private conversation content
- No credentials, secrets, or private filesystem paths

Attestation: `agent-ops-public-v1/reports/PUBLIC_SAFE.md`

---

## Frozen digests (v0.2.0 canonical release packs)

| Pack | SHA-256 |
|------|---------|
| agent-ops-public-v1 | `f3ca97b715f93c2134121911f12b76ee3298af26cb1d65c1673377aada117941` |
| policy-gate-public-v1 | `c5efe1c896b89edded410c42f63707544e5a0a4a0d0739f6760d549c4f24f1ec` |
| tool-contract-public-v1 | `09a67fca45ad04ddaaa06f101be24607371a66da531480972a4246cb6ed2a8c0` |

Pinned in `evalfoundry/vault.py` as `APPROVED_*_PUBLIC_V1_SHA256` and in the
`packs/*.SHA256` sidecars; CI fails if a rebuild, the sidecars, and the
`vault.py` pins disagree. The Agent Ops digest is for the demonstration pack,
which is outside the byte-reproducibility claim.
