"""Admitted atom store — EVAL_BASELINE G0–G5.

Canonical unit of provenanced eval feedstock after surgical admit.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

EXTRACT_VERSION = "atom-v1"
ATOM_SCHEMA_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Denylist (G1) — public-safe floor
# ---------------------------------------------------------------------------

DENY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.I)
    for p in (
        r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",  # emails
        r"\bsk-[a-zA-Z0-9]{10,}\b",
        r"\bapi[_-]?key\b\s*[:=]",
        r"\b(password|passwd|secret)\s*[:=]\s*\S+",
        r"\b(onlyfans|nsfw)\b",
        r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----",
    )
]

# T3 admit lexicon (tools / schemas / MCP / OpenAPI)
T3_TOOL_LEXICON: Dict[str, Dict[str, List[str]]] = {
    "tool_schema": {
        "anchors": [
            "openapi",
            "json schema",
            "tool schema",
            "function calling",
            "mcp tool",
        ],
        "supports": [
            "parameters",
            "required",
            "properties",
            "arguments",
            "inputschema",
            "input_schema",
            "additionalproperties",
            "type",
            "object",
            "string",
            "integer",
            "boolean",
            "array",
        ],
    },
    "mcp_protocol": {
        "anchors": [
            "model context protocol",
            "mcp server",
            "tools/call",
            "tools/list",
            "tool registry",
        ],
        "supports": [
            "mcp",
            "tool_call",
            "list_tools",
            "call_tool",
            "capability",
            "connector",
            "host",
            "client",
            "server",
        ],
    },
    "scope_authz": {
        "anchors": [
            "least privilege",
            "oauth scope",
            "permission scope",
            "granted scopes",
        ],
        "supports": [
            "scope",
            "authorize",
            "permission",
            "rbac",
            "grant",
            "deny",
            "allowlist",
            "read",
            "write",
            "admin",
        ],
    },
}

# T2 admit lexicon (policy / authority / security) — seam for this vertical
T2_POLICY_LEXICON: Dict[str, Dict[str, List[str]]] = {
    "policy_authority": {
        "anchors": [
            "shall ",
            "must ",
            "authorization",
            "prior approval",
            "access control",
            "least privilege",
        ],
        "supports": [
            "authenticate",
            "authorize",
            "permission",
            "role",
            "privilege",
            "approve",
            "approval",
            "rbac",
            "policy",
            "compliance",
            "audit",
            "shall not",
            "prohibited",
            "human",
            "operator",
        ],
    },
    "security_ops": {
        "anchors": [
            "privileged access",
            "secrets",
            "credential",
            "encryption",
            "incident response",
        ],
        "supports": [
            "confidential",
            "integrity",
            "sandbox",
            "network",
            "exfil",
            "logging",
            "monitor",
            "multi-factor",
            "mfa",
            "token",
            "key management",
        ],
    },
    "agent_tooling": {
        "anchors": [
            "automated agent",
            "tool invocation",
            "system command",
            "remote execution",
        ],
        "supports": [
            "script",
            "api call",
            "pipeline",
            "workflow",
            "service account",
            "machine identity",
            "bot",
            "automation",
        ],
    },
}


@dataclass
class Atom:
    """One admitted, provenanced feedstock unit (G0–G5)."""

    atom_id: str
    schema_version: str
    extract_version: str
    text: str
    source_url: str
    source_title: str
    source_hash: str  # hash of text or source payload
    license: str
    public: bool
    domains: Dict[str, str]  # name -> HIT|DEEP|WEAK|MISS (MISS omitted in compact form)
    domain_hits: List[str]  # HIT/DEEP only
    composition: str
    structure: str  # claim|fields|prose
    admitted_at: str
    gates_passed: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def denylist_hits(text: str) -> list[str]:
    hits = []
    for pat in DENY_PATTERNS:
        if pat.search(text):
            hits.append(pat.pattern)
    return hits


def multi_hit_status(
    text: str, lexicon: Mapping[str, Mapping[str, Sequence[str]]]
) -> tuple[Dict[str, str], List[str], str]:
    """Shared multi-hit engine. Returns (status_map, hit_list, composition)."""
    tl = text.lower()
    # pad so word-boundary-ish anchors like "shall " work at EOL
    tl_pad = f" {tl} "
    statuses: Dict[str, str] = {}
    for name, spec in lexicon.items():
        anchors = [a for a in spec.get("anchors", []) if a.lower() in tl_pad or a.lower() in tl]
        supports = [s for s in spec.get("supports", []) if s.lower() in tl]
        n_a, n_s = len(anchors), len(supports)
        if n_a == 0 and n_s == 0:
            st = "MISS"
        elif n_a == 0 and n_s == 1:
            st = "WEAK"
        elif n_a >= 2 or (n_a >= 1 and n_s >= 2) or n_s >= 4:
            st = "DEEP"
        elif n_a >= 1 or n_s >= 2:
            st = "HIT"
        else:
            st = "WEAK"
        statuses[name] = st

    hits = sorted(d for d, s in statuses.items() if s in ("HIT", "DEEP"))
    n_hit = sum(1 for s in statuses.values() if s == "HIT")
    n_deep = sum(1 for s in statuses.values() if s == "DEEP")
    n = n_hit + n_deep
    if n == 0:
        composition = "NONE"
    elif n >= 3:
        composition = "MULTI_3+"
    elif n == 2:
        composition = "MULTI_2"
    elif n_deep == 1 and n_hit == 0:
        composition = "SINGLE_DEEP"
    else:
        composition = "SINGLE"
    active = {d: s for d, s in statuses.items() if s != "MISS"}
    return active, hits, composition


def structure_grade(text: str) -> str:
    if re.search(r"\b(shall|must|shall not|must not)\b", text, re.I):
        return "claim"
    if re.search(r"^\s*[\w.-]+\s*[:=]", text, re.M) or text.strip().startswith("{"):
        return "fields"
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) >= 2 and len(text) >= 80:
        return "claim"
    return "prose"


def admit_text(
    *,
    text: str,
    source_url: str,
    source_title: str,
    license_id: str,
    public: bool = True,
    lexicon: Optional[Mapping[str, Mapping[str, Sequence[str]]]] = None,
    meta: Optional[Dict[str, Any]] = None,
    require_multi: bool = True,
    atom_id: Optional[str] = None,
) -> tuple[Optional[Atom], list[str]]:
    """
    Apply G0–G5. Returns (Atom|None, reasons).
    G0: public+license recorded (caller responsibility for truthfulness)
    """
    reasons: list[str] = []
    text = (text or "").strip()
    if len(text) < 40:
        return None, ["G2: text too short"]
    if not source_url or not source_title:
        return None, ["G5: source_url and source_title required"]
    if not license_id:
        return None, ["G0: license required"]
    if not public:
        return None, ["G0: public=false not admitted by admit_public path"]

    deny = denylist_hits(text + "\n" + source_url + "\n" + source_title)
    if deny:
        return None, [f"G1: denylist {deny[0][:40]}"]

    struct = structure_grade(text)
    if struct == "prose" and len(text) < 120:
        return None, ["G2: insufficient structure"]

    lex = lexicon or T2_POLICY_LEXICON
    domains, hits, composition = multi_hit_status(text, lex)
    if require_multi and composition == "NONE":
        return None, ["G3: no domain multi-hit"]
    if require_multi and composition == "SINGLE":
        # plain SINGLE (one HIT only) rejected; SINGLE_DEEP and MULTI_* pass
        return None, ["G3: need MULTI_2+ or SINGLE_DEEP"]

    # G4: scorer-feasible — normative policy language OR schema/tool fields (T3)
    meta = meta or {}
    has_normative = any(
        k in text.lower() for k in ("shall ", "must ", "shall not", "must not")
    )
    has_schema_shape = bool(
        re.search(
            r"\b(properties|required|parameters|inputschema|\"type\"\s*:)",
            text,
            re.I,
        )
    )
    if not has_normative and not has_schema_shape and not meta.get("scorer_fields_ok"):
        return None, ["G4: not scorer-feasible (no shall/must and no schema shape)"]

    body_hash = sha256_text(text)
    aid = atom_id or f"atom-{body_hash[:16]}"
    atom = Atom(
        atom_id=aid,
        schema_version=ATOM_SCHEMA_VERSION,
        extract_version=EXTRACT_VERSION,
        text=text,
        source_url=source_url,
        source_title=source_title,
        source_hash=body_hash,
        license=license_id,
        public=public,
        domains=domains,
        domain_hits=hits,
        composition=composition,
        structure=struct,
        admitted_at=utc_now(),
        gates_passed=["G0", "G1", "G2", "G3", "G4", "G5"],
        meta=meta or {},
    )
    return atom, ["admitted"]


def write_atoms_jsonl(path: str | Any, atoms: Iterable[Atom]) -> int:
    from pathlib import Path

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with p.open("w", encoding="utf-8") as f:
        for atom in atoms:
            f.write(json.dumps(atom.to_row(), ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def read_atoms_jsonl(path: str | Any) -> list[Atom]:
    from pathlib import Path

    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        d = json.loads(line)
        rows.append(Atom(**{k: d[k] for k in Atom.__dataclass_fields__ if k in d}))
    return rows
