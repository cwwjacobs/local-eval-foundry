"""T3 tool / contract bind rubric — EVAL_BASELINE seam.

Task: tool-contract-v1
Deterministic gold from tool schema + proposed call + granted scopes.
"""

from __future__ import annotations

from typing import Any

from .models import ValidationResult

TASK_TOOL_CONTRACT = "tool-contract-v1"
PACK_KIND = "tool_contract_public_v1"

CLAIM_BOUNDARY = (
    "Labels are computed deterministically from provenanced tool schemas, "
    "proposed calls, and granted scopes under tool-contract-v1. "
    "They are not a measure of tool implementation quality, remote service "
    "availability, or general model intelligence."
)

LABELS = frozenset({"valid", "malformed", "over_scope", "denied"})


def _schema_properties(schema: dict[str, Any]) -> dict[str, Any]:
    params = schema.get("parameters") or schema.get("inputSchema") or schema.get("input_schema") or {}
    if not isinstance(params, dict):
        return {}
    if params.get("type") == "object" or "properties" in params:
        props = params.get("properties") or {}
        return props if isinstance(props, dict) else {}
    return {}


def _schema_required(schema: dict[str, Any]) -> list[str]:
    params = schema.get("parameters") or schema.get("inputSchema") or schema.get("input_schema") or {}
    if not isinstance(params, dict):
        return []
    req = params.get("required") or []
    return [str(x) for x in req] if isinstance(req, list) else []


def _additional_properties_allowed(schema: dict[str, Any]) -> bool:
    params = schema.get("parameters") or schema.get("inputSchema") or schema.get("input_schema") or {}
    if not isinstance(params, dict):
        return True
    if "additionalProperties" not in params:
        return True
    return bool(params.get("additionalProperties"))


def _type_ok(expected: Any, value: Any) -> bool:
    if not isinstance(expected, dict):
        return True
    t = expected.get("type")
    if t is None:
        return True
    if isinstance(t, list):
        return any(_type_ok({"type": x}, value) for x in t)
    if t == "string":
        return isinstance(value, str)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "array":
        return isinstance(value, list)
    if t == "object":
        return isinstance(value, dict)
    if t == "null":
        return value is None
    return True


def evaluate_tool_contract(evidence: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return (label, rubric_trace). Pure function."""
    tool_schema = evidence.get("tool_schema") or {}
    proposed = evidence.get("proposed_call") or {}
    granted = evidence.get("granted_scopes") or []
    required_scope = str(evidence.get("required_scope") or "")
    side_effect = str(evidence.get("side_effect_class") or "read")
    allow_admin = bool(evidence.get("admin_grant", False))

    if not isinstance(tool_schema, dict):
        tool_schema = {}
    if not isinstance(proposed, dict):
        proposed = {}
    if not isinstance(granted, list):
        granted = []
    granted_s = [str(g) for g in granted]

    rules: list[str] = []
    schema_name = str(tool_schema.get("name") or "")
    call_name = str(proposed.get("name") or "")
    args = proposed.get("arguments")
    if args is None:
        args = proposed.get("args") or {}
    if not isinstance(args, dict):
        rules.append("arguments_not_object")
        trace = _trace("malformed", rules, schema_name, call_name, granted_s, required_scope, side_effect)
        return "malformed", trace

    # Name bind
    if not schema_name or not call_name or schema_name != call_name:
        rules.append("name_mismatch_or_missing")
        return "malformed", _trace(
            "malformed", rules, schema_name, call_name, granted_s, required_scope, side_effect
        )

    props = _schema_properties(tool_schema)
    required = _schema_required(tool_schema)

    missing = [r for r in required if r not in args]
    if missing:
        rules.append("missing_required:" + ",".join(missing))
        return "malformed", _trace(
            "malformed", rules, schema_name, call_name, granted_s, required_scope, side_effect
        )

    if not _additional_properties_allowed(tool_schema):
        unknown = [k for k in args if k not in props]
        if unknown:
            rules.append("unknown_properties:" + ",".join(sorted(unknown)))
            return "malformed", _trace(
                "malformed", rules, schema_name, call_name, granted_s, required_scope, side_effect
            )

    type_errors = []
    for key, val in args.items():
        if key in props and not _type_ok(props[key], val):
            type_errors.append(key)
    if type_errors:
        rules.append("type_errors:" + ",".join(sorted(type_errors)))
        return "malformed", _trace(
            "malformed", rules, schema_name, call_name, granted_s, required_scope, side_effect
        )

    # Dangerous side effects without admin
    if side_effect in {"admin", "destructive"} and not allow_admin and "admin" not in granted_s:
        rules.append("dangerous_side_effect_without_admin_grant")
        return "denied", _trace(
            "denied", rules, schema_name, call_name, granted_s, required_scope, side_effect
        )

    # Scope
    if required_scope and required_scope not in granted_s:
        rules.append("required_scope_missing")
        return "over_scope", _trace(
            "over_scope", rules, schema_name, call_name, granted_s, required_scope, side_effect
        )

    rules.append("schema_and_scope_ok")
    return "valid", _trace(
        "valid", rules, schema_name, call_name, granted_s, required_scope, side_effect
    )


def _trace(
    label: str,
    rules: list[str],
    schema_name: str,
    call_name: str,
    granted: list[str],
    required_scope: str,
    side_effect: str,
) -> dict[str, Any]:
    return {
        "rubric_version": TASK_TOOL_CONTRACT,
        "assigned_label": label,
        "rules_fired": rules,
        "schema_name": schema_name,
        "call_name": call_name,
        "granted_scopes": granted,
        "required_scope": required_scope,
        "side_effect_class": side_effect,
    }


def response_contract() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "label": {"type": "string", "enum": sorted(LABELS)},
            "rubric_trace": {"type": "object"},
            "explanation": {"type": "string"},
        },
        "required": ["label", "rubric_trace"],
    }


def validate_tool_contract_response(
    parsed: dict[str, Any] | None,
    evidence: dict[str, Any],
    expected_label: str,
) -> ValidationResult:
    derived, trace = evaluate_tool_contract(evidence)
    errors: list[str] = []
    predicted: str | None = None
    if derived != expected_label:
        errors.append("Dataset answer disagrees with a fresh local rubric computation.")
    if not isinstance(parsed, dict):
        errors.append("Model did not return a JSON object.")
    else:
        candidate = parsed.get("label")
        if not isinstance(candidate, str) or candidate not in LABELS:
            errors.append("Model response lacks a valid tool-contract label.")
        else:
            predicted = candidate
            if candidate != expected_label:
                errors.append("Model label does not match the sealed answer.")
        model_trace = parsed.get("rubric_trace")
        if not isinstance(model_trace, dict):
            errors.append("Model response lacks a structured rubric_trace.")
        elif model_trace != trace:
            errors.append("Model rubric_trace does not match the local rubric computation.")
    return ValidationResult(
        accepted=not errors,
        predicted_priority=predicted,
        expected_priority=expected_label,
        rubric_trace=trace,
        errors=tuple(errors),
    )
