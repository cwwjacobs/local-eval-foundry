"""Small immutable data objects shared by the engine modules."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class CaseRecord:
    """A blind, model-safe view of one dataset record."""

    case_id: str
    source_id: str
    split: str
    task: str
    evidence: dict[str, Any]

    def model_payload(self) -> dict[str, Any]:
        """Return the public case contract exposed to a local UI."""
        return {
            "id": self.case_id,
            "source_id": self.source_id,
            "task": self.task,
            "input": deepcopy(self.evidence),
        }

    def model_prompt_payload(self) -> dict[str, Any]:
        """Omit the canonical record id; the model only needs the evidence."""
        return {
            "source_id": self.source_id,
            "task": self.task,
            "input": deepcopy(self.evidence),
        }


@dataclass(frozen=True)
class ArchiveReport:
    archive_path: str
    archive_sha256: str
    expected_archive_sha256: str | None
    provenance_pinned: bool
    root: str
    zip_entry_count: int
    file_count: int
    manifest_entries_verified: int
    record_counts: dict[str, int]
    rubric_alignment_failures: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ModelConfig:
    endpoint: str
    model: str
    timeout_seconds: int = 45
    max_tokens: int = 220
    temperature: float = 0.0
    seed: int | None = None
    allow_remote: bool = False
    transport: str = "openai_compatible"


@dataclass(frozen=True)
class Completion:
    raw_content: str
    parsed: dict[str, Any] | None
    usage: dict[str, Any]
    provider_request_id: str | None
    provider_stats: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ValidationResult:
    accepted: bool
    predicted_priority: str | None
    expected_priority: str
    rubric_trace: dict[str, Any]
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "predicted_priority": self.predicted_priority,
            "expected_priority": self.expected_priority,
            "rubric_trace": self.rubric_trace,
            "errors": list(self.errors),
        }


@dataclass
class RunReceipt:
    run_id: str
    created_at: str
    status: str
    scope: str
    archive_sha256: str
    case: CaseRecord
    model: dict[str, Any]
    prompt_sha256: str
    completion: dict[str, Any] | None = None
    validation: dict[str, Any] | None = None
    error: str | None = None
    selection_seed: str | None = None
    call_budget: int = 1
    calls_used: int = 0
    claim_boundary: str = (
        "Source-priority labels are computed from included NVD-derived fields. "
        "They are not human adjudication, environment-aware risk, or remediation guidance."
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["case"] = self.case.model_payload() | {"split": self.case.split}
        return result
