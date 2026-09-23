"""The published source-priority-v2.0 rule, implemented without an LLM."""

from __future__ import annotations

from typing import Any

from .models import ValidationResult

RUBRIC_VERSION = "source-priority-v2.0"
LABELS = frozenset({"critical", "high", "medium", "low"})
CLAIM_BOUNDARY = (
    "Source-priority labels are computed deterministically from included "
    "NVD-derived fields. They are not human adjudication, environment-aware "
    "risk, or remediation guidance."
)


def vector_parts(vector: str) -> dict[str, str]:
    """Parse the CVSS vector exactly as the frozen dataset builder does."""
    parts: dict[str, str] = {}
    for segment in vector.split("/"):
        if ":" in segment:
            key, value = segment.split(":", 1)
            parts[key] = value
    return parts


def evaluate_rubric(evidence: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return the dataset's deterministic label and complete rubric trace.

    The duplicate CISA_KEV signals are intentional: the source package's
    builder encodes known exploitation as two urgency points.
    """
    try:
        score = float(evidence["cvss_score"])
        vector = str(evidence["cvss_vector"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Evidence must include numeric cvss_score and cvss_vector") from error

    parts = vector_parts(vector)
    base_points = 8 if score >= 9 else 5 if score >= 7 else 3 if score >= 4 else 1
    urgency: list[str] = []
    dampening: list[str] = []

    if bool(evidence.get("known_exploited")):
        urgency.extend(["CISA_KEV", "CISA_KEV"])
    if parts.get("AV") == "N":
        urgency.append("NETWORK")
    if parts.get("PR") == "N" or parts.get("Au") == "N":
        urgency.append("NO_AUTH")

    if parts.get("AV") in {"L", "P"}:
        dampening.append("LOCAL_OR_PHYSICAL")
    if parts.get("AC") == "H":
        dampening.append("HIGH_COMPLEXITY")
    if parts.get("PR") == "H" or parts.get("Au") == "M":
        dampening.append("HIGH_PRIVILEGE_OR_MULTIPLE_AUTH")

    final_points = base_points + len(urgency) - len(dampening)
    label = (
        "critical"
        if final_points >= 8
        else "high"
        if final_points >= 5
        else "medium"
        if final_points >= 2
        else "low"
    )
    trace = {
        "rubric_version": RUBRIC_VERSION,
        "base_points": base_points,
        "urgency_signals": urgency,
        "dampening_signals": dampening,
        "final_points": final_points,
        "assigned_triage_priority": label,
    }
    return label, trace


def response_contract() -> dict[str, Any]:
    """A richer local response contract; the benchmark remains label-first."""
    return {
        "type": "object",
        "properties": {
            "triage_priority": {"type": "string", "enum": sorted(LABELS)},
            "rubric_trace": {
                "type": "object",
                "properties": {
                    "rubric_version": {"const": RUBRIC_VERSION},
                    "base_points": {"type": "integer"},
                    "urgency_signals": {"type": "array", "items": {"type": "string"}},
                    "dampening_signals": {"type": "array", "items": {"type": "string"}},
                    "final_points": {"type": "integer"},
                    "assigned_triage_priority": {"type": "string", "enum": sorted(LABELS)},
                },
                "required": [
                    "rubric_version",
                    "base_points",
                    "urgency_signals",
                    "dampening_signals",
                    "final_points",
                    "assigned_triage_priority",
                ],
            },
            "explanation": {
                "type": "string",
                "description": "Optional model-authored explanation; it is not benchmark ground truth.",
            },
        },
        "required": ["triage_priority", "rubric_trace"],
    }


def validate_response(
    parsed: dict[str, Any] | None,
    evidence: dict[str, Any],
    expected_priority: str,
    *,
    task: str | None = None,
    pack_kind: str | None = None,
) -> ValidationResult:
    """Validate a model answer without trusting its explanation as ground truth."""
    if pack_kind == "policy_gate_public_v1" or task == "policy-shall-gate-v1":
        from .policy_gate_rubric import validate_policy_gate_response

        return validate_policy_gate_response(parsed, evidence, expected_priority)

    if pack_kind == "tool_contract_public_v1" or task == "tool-contract-v1":
        from .tool_contract_rubric import validate_tool_contract_response

        return validate_tool_contract_response(parsed, evidence, expected_priority)

    if pack_kind == "agent_ops_public_v1" or (
        task
        and task
        in {
            "agent-domain-multi-hit-v1",
            "action-gate-v1",
            "skill-pack-checklist-v1",
        }
    ):
        from .agent_ops_rubric import validate_agent_ops_response

        if not task:
            raise ValueError("agent-ops validation requires task")
        return validate_agent_ops_response(parsed, task, evidence, expected_priority)

    derived_priority, trace = evaluate_rubric(evidence)
    errors: list[str] = []
    predicted: str | None = None

    if expected_priority not in LABELS:
        errors.append("Dataset answer is outside the published label set.")
    if derived_priority != expected_priority:
        errors.append("Dataset answer disagrees with a fresh local rubric computation.")
    if not isinstance(parsed, dict):
        errors.append("Model did not return a JSON object.")
    else:
        candidate = parsed.get("triage_priority")
        if not isinstance(candidate, str) or candidate not in LABELS:
            errors.append("Model response lacks a valid triage_priority.")
        else:
            predicted = candidate
            if candidate != expected_priority:
                errors.append("Model triage_priority does not match the sealed answer.")

        model_trace = parsed.get("rubric_trace")
        if not isinstance(model_trace, dict):
            errors.append("Model response lacks a structured rubric_trace.")
        elif model_trace != trace:
            errors.append("Model rubric_trace does not match the local rubric computation.")

    return ValidationResult(
        accepted=not errors,
        predicted_priority=predicted,
        expected_priority=expected_priority,
        rubric_trace=trace,
        errors=tuple(errors),
    )
