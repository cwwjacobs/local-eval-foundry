"""Serialized, receipt-first model execution with no fallback generation."""

from __future__ import annotations

import hashlib
import threading
import uuid
from typing import Any

from .errors import BudgetExceeded, ModelBusy
from .model_client import OpenAICompatibleClient, build_messages, prompt_hash
from .models import CaseRecord, RunReceipt
from .receipts import ReceiptStore, utc_now
from .rubric import CLAIM_BOUNDARY, validate_response
from .vault import (
    PACK_KIND_AGENT_OPS,
    PACK_KIND_POLICY_GATE,
    PACK_KIND_TOOL_CONTRACT,
    DatasetVault,
)
from . import agent_ops_rubric
from . import policy_gate_rubric
from . import tool_contract_rubric


class SingleFlightGate:
    """One local model call across the process, never a hidden agent farm."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if not self._lock.acquire(blocking=False):
            raise ModelBusy("A model call is already active. Wait for its receipt before starting another.")

    def release(self) -> None:
        self._lock.release()


class RunEngine:
    """Execute one explicit diagnostic case, persist, then validate it locally."""

    def __init__(self, vault: DatasetVault, store: ReceiptStore, client: OpenAICompatibleClient) -> None:
        self.vault = vault
        self.store = store
        self.client = client
        self._gate = SingleFlightGate()

    def run_case(
        self,
        *,
        split: str,
        case_id: str,
        selection_seed: str | None = None,
        scope: str = "diagnostic",
        max_calls: int = 1,
    ) -> dict[str, Any]:
        """Run exactly one case. There are no retries, fallbacks, or background hops."""
        if scope != "diagnostic":
            raise BudgetExceeded(
                "A single-case call is diagnostic only. Full benchmark scoring requires an explicit full-split runner."
            )
        if max_calls != 1:
            raise BudgetExceeded("A one-case run has a fixed call budget of exactly one.")

        if selection_seed is not None:
            _, selected = self.vault.select_cases(split, 1, selection_seed)
            if selected[0].case_id != case_id:
                raise BudgetExceeded(
                    "case_id does not match the deterministic one-case selection for selection_seed."
                )
        case = self.vault.get_case(split, case_id)
        self._gate.acquire()
        try:
            return self._run_locked(case, selection_seed=selection_seed, scope=scope)
        finally:
            self._gate.release()

    def _claim_boundary(self) -> str:
        kind = getattr(self.vault, "pack_kind", None)
        if kind == PACK_KIND_POLICY_GATE:
            return policy_gate_rubric.CLAIM_BOUNDARY
        if kind == PACK_KIND_TOOL_CONTRACT:
            return tool_contract_rubric.CLAIM_BOUNDARY
        if kind == PACK_KIND_AGENT_OPS:
            return agent_ops_rubric.CLAIM_BOUNDARY
        return CLAIM_BOUNDARY

    def _run_locked(self, case: CaseRecord, *, selection_seed: str | None, scope: str) -> dict[str, Any]:
        run_id = str(uuid.uuid4())
        created_at = utc_now()
        messages = build_messages(case, pack_kind=getattr(self.vault, "pack_kind", None))
        prompt_digest = prompt_hash(messages)
        attempted_call = False
        claim = self._claim_boundary()
        try:
            attempted_call = True
            completion, messages = self.client.complete(case, pack_kind=getattr(self.vault, "pack_kind", None))
        except Exception as error:
            receipt = RunReceipt(
                run_id=run_id,
                created_at=created_at,
                status="FAILED",
                scope=scope,
                archive_sha256=self.vault.archive_sha256,
                case=case,
                model=self.client.public_config,
                prompt_sha256=prompt_digest,
                error=str(error),
                selection_seed=selection_seed,
                calls_used=int(attempted_call),
                claim_boundary=claim,
                metadata={
                    "full_split_size": self.vault.split_sizes[case.split],
                    "expected_archive_sha256": self.vault.expected_archive_sha256,
                    "archive_provenance_pinned": self.vault.provenance_pinned,
                    "isolation_mode": "prompt_only_no_tools",
                    "answer_access": "not_opened",
                    "fallback_used": False,
                    "call_attempted": attempted_call,
                },
            )
            self.store.save(receipt)
            return self.store.get(run_id) or receipt.as_dict()

        completion_dict = {
            "raw_content": completion.raw_content,
            "raw_content_sha256": hashlib.sha256(completion.raw_content.encode("utf-8")).hexdigest(),
            "parsed": completion.parsed,
            "usage": completion.usage,
            "provider_request_id": completion.provider_request_id,
        }
        if completion.provider_stats:
            completion_dict["stats"] = completion.provider_stats
        receipt = RunReceipt(
            run_id=run_id,
            created_at=created_at,
            status="UNSCORED",
            scope=scope,
            archive_sha256=self.vault.archive_sha256,
            case=case,
            model=self.client.public_config,
            prompt_sha256=prompt_hash(messages),
            completion=completion_dict,
            selection_seed=selection_seed,
            calls_used=1,
            claim_boundary=claim,
            metadata={
                "full_split_size": self.vault.split_sizes[case.split],
                "expected_archive_sha256": self.vault.expected_archive_sha256,
                "archive_provenance_pinned": self.vault.provenance_pinned,
                "pack_kind": getattr(self.vault, "pack_kind", None),
                "score_label": f"diagnostic 1/{self.vault.split_sizes[case.split]}",
                "isolation_mode": "prompt_only_no_tools",
                "answer_access": "not_opened_yet",
                "fallback_used": False,
                "call_attempted": True,
                "provider_usage_reported": bool(completion.usage or completion.provider_stats),
            },
        )
        # Persist raw model output before the scorer opens a sealed answer.
        self.store.save(receipt)

        try:
            expected, _ = self.vault.scoring_context(case)
            validation = validate_response(
                completion.parsed,
                case.evidence,
                expected,
                task=case.task,
                pack_kind=getattr(self.vault, "pack_kind", None),
            )
            completion_tokens = completion.usage.get("completion_tokens")
            configured_max_tokens = getattr(getattr(self.client, "config", None), "max_tokens", None)
            over_completion_budget = (
                isinstance(completion_tokens, int)
                and isinstance(configured_max_tokens, int)
                and completion_tokens > configured_max_tokens
            )
            receipt.status = "SCORED" if validation.accepted and not over_completion_budget else "HOLD"
            receipt.validation = validation.as_dict()
            if over_completion_budget:
                receipt.error = (
                    "Provider reported completion token usage above EvalFoundry's requested max_tokens."
                )
            receipt.metadata["answer_access"] = "post_response_only"
        except Exception as error:
            # A scorer fault must not erase the raw model artifact already stored.
            receipt.status = "HOLD"
            receipt.error = f"Post-response validation failed: {error}"
            receipt.metadata["answer_access"] = "post_response_validation_failed"
        self.store.save(receipt)
        return self.store.get(run_id) or receipt.as_dict()
