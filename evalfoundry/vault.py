"""Read-only access to a frozen package with split and leakage boundaries."""

from __future__ import annotations

import hashlib
import io
import json
import secrets
import zipfile
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterator

from .errors import ArchiveValidationError, SplitAccessError
from .models import ArchiveReport, CaseRecord
from .rubric import evaluate_rubric

RUN_SPLITS = frozenset({"eval", "challenge"})
ALL_SPLITS = frozenset({"train", "eval", "challenge", "preview"})
_BLIND_KEYS = frozenset({"id", "source_id", "task", "input"})
APPROVED_FROZEN_ARCHIVE_SHA256 = "1dad63c829b358e45ebb2f9e76a76791142fdf7c96470d9f3a193ff4f0ea3b4e"
APPROVED_AGENT_OPS_PUBLIC_V1_SHA256 = (
    "f3ca97b715f93c2134121911f12b76ee3298af26cb1d65c1673377aada117941"
)
APPROVED_POLICY_GATE_PUBLIC_V1_SHA256 = (
    "0ba8ffd4fb13194dfcd7dfb762b25d3442d73d871791325bd12376a06972b86f"
)
APPROVED_TOOL_CONTRACT_PUBLIC_V1_SHA256 = (
    "b9b36224b05c35ccb375708b53ead922310bb4c3d9e4fb52a4d1a725511b433c"
)
PACK_KIND_NVD = "nvd_source_priority_v1"
PACK_KIND_AGENT_OPS = "agent_ops_public_v1"
PACK_KIND_POLICY_GATE = "policy_gate_public_v1"
PACK_KIND_TOOL_CONTRACT = "tool_contract_public_v1"
# Contract packs: flexible splits + label answers + task-dispatched rubric
CONTRACT_PACK_KINDS = frozenset(
    {PACK_KIND_AGENT_OPS, PACK_KIND_POLICY_GATE, PACK_KIND_TOOL_CONTRACT}
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class DatasetVault:
    """An immutable, model-safe view over the frozen buyer-full ZIP.

    Labels are held privately in process memory for post-response scoring only.
    Public case methods cannot return canonical rows, answer keys, provenance, or
    rubric traces.
    """

    def __init__(
        self,
        archive_path: str | Path,
        *,
        verify_manifest: bool = True,
        expected_sha256: str | None = None,
        strict_contract: bool = False,
    ) -> None:
        self.archive_path = Path(archive_path).expanduser().resolve()
        if not self.archive_path.is_file():
            raise ArchiveValidationError(f"Archive not found: {self.archive_path}")

        self.archive_sha256 = _sha256_file(self.archive_path)
        self.expected_archive_sha256 = expected_sha256.lower() if expected_sha256 else None
        if self.expected_archive_sha256 and (
            len(self.expected_archive_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.expected_archive_sha256)
        ):
            raise ArchiveValidationError("expected_sha256 must be a 64-character lowercase or uppercase hex digest.")
        if self.expected_archive_sha256 and self.archive_sha256 != self.expected_archive_sha256:
            raise ArchiveValidationError(
                "Archive SHA-256 does not match the approved frozen archive digest."
            )
        self.provenance_pinned = self.expected_archive_sha256 is not None
        self.strict_contract = strict_contract
        self.root = ""
        self.pack_kind = PACK_KIND_NVD
        self.pack_contract: dict[str, Any] | None = None
        self._manifest: dict[str, tuple[int, str]] = {}
        self._entry_hashes: dict[str, str] = {}
        self._cases: dict[str, dict[str, CaseRecord]] = {split: {} for split in RUN_SPLITS}
        self._labels: dict[str, dict[str, str]] = {split: {} for split in RUN_SPLITS}
        self._entry_by_split: dict[str, str] = {}
        self._train_count = 0
        self._preview_count = 0
        self._zip_entry_count = 0
        self._file_count = 0
        self._load(verify_manifest=verify_manifest)

    @staticmethod
    def _physical_jsonl_rows(handle: Any) -> Iterator[dict[str, Any]]:
        """Read physical newline records; do not treat U+2028 as a row separator."""
        text = io.TextIOWrapper(handle, encoding="utf-8", newline="\n")
        for line_number, raw in enumerate(text, start=1):
            if not raw.strip():
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError as error:
                raise ArchiveValidationError(
                    f"Invalid JSONL at physical line {line_number}: {error.msg}"
                ) from error

    def _load(self, *, verify_manifest: bool) -> None:
        try:
            with zipfile.ZipFile(self.archive_path) as archive:
                infos = archive.infolist()
                self._zip_entry_count = len(infos)
                self._file_count = sum(not info.is_dir() for info in infos)
                self.root = self._discover_root(archive)
                self._manifest = self._read_manifest(archive)
                self._entry_hashes = {
                    relative: digest for relative, (_, digest) in self._manifest.items()
                }
                if verify_manifest:
                    self._verify_zip_and_manifest(archive)
                self._load_pack_contract(archive)
                self._load_cases(archive)
        except zipfile.BadZipFile as error:
            raise ArchiveValidationError("Archive is not a readable ZIP file.") from error

    def _load_pack_contract(self, archive: zipfile.ZipFile) -> None:
        """Optional PACK_CONTRACT.json selects non-NVD pack kinds (e.g. agent_ops_public_v1)."""
        name = self.root + "reports/PACK_CONTRACT.json"
        try:
            raw = archive.read(name).decode("utf-8")
        except KeyError:
            self.pack_kind = PACK_KIND_NVD
            self.pack_contract = None
            return
        try:
            contract = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ArchiveValidationError("reports/PACK_CONTRACT.json is not valid JSON.") from error
        if not isinstance(contract, dict) or "pack_kind" not in contract:
            raise ArchiveValidationError("PACK_CONTRACT.json must include pack_kind.")
        self.pack_contract = contract
        self.pack_kind = str(contract["pack_kind"])

    def _discover_root(self, archive: zipfile.ZipFile) -> str:
        suffix = "reports/FILE_MANIFEST.tsv"
        candidates = [name for name in archive.namelist() if name.endswith(suffix)]
        if len(candidates) != 1:
            raise ArchiveValidationError("Expected exactly one reports/FILE_MANIFEST.tsv entry.")
        return candidates[0][: -len(suffix)]

    def _read_manifest(self, archive: zipfile.ZipFile) -> dict[str, tuple[int, str]]:
        name = self.root + "reports/FILE_MANIFEST.tsv"
        try:
            content = archive.read(name).decode("utf-8")
        except KeyError as error:
            raise ArchiveValidationError("Package has no file manifest.") from error
        rows = content.splitlines()
        if not rows or rows[0] != "path\tbytes\tsha256":
            raise ArchiveValidationError("Package file manifest has an unknown header.")
        manifest: dict[str, tuple[int, str]] = {}
        for row in rows[1:]:
            try:
                relative, byte_count, digest = row.split("\t")
                manifest[relative] = (int(byte_count), digest)
            except ValueError as error:
                raise ArchiveValidationError("Package file manifest has a malformed row.") from error
        return manifest

    def _verify_zip_and_manifest(self, archive: zipfile.ZipFile) -> None:
        corrupt = archive.testzip()
        if corrupt is not None:
            raise ArchiveValidationError(f"ZIP CRC validation failed: {corrupt}")
        mismatches: list[str] = []
        for relative, (expected_size, expected_hash) in self._manifest.items():
            entry = self.root + relative
            try:
                data = archive.read(entry)
            except KeyError:
                mismatches.append(relative + " (missing)")
                continue
            if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_hash:
                mismatches.append(relative)
        if mismatches:
            detail = ", ".join(mismatches[:5])
            raise ArchiveValidationError(f"Manifest mismatch: {detail}")

    def _read_entry_rows(self, archive: zipfile.ZipFile, relative: str) -> Iterator[dict[str, Any]]:
        try:
            with archive.open(self.root + relative) as handle:
                yield from self._physical_jsonl_rows(handle)
        except KeyError as error:
            raise ArchiveValidationError(f"Missing expected package entry: {relative}") from error

    @staticmethod
    def _case_from_row(row: dict[str, Any], split: str) -> CaseRecord:
        allowed = {"id", "source_id", "task", "input"}
        if not allowed.issubset(row):
            raise ArchiveValidationError(f"{split} record is missing blind-case fields.")
        evidence = row["input"]
        if not isinstance(evidence, dict):
            raise ArchiveValidationError(f"{split} record input is not an object.")
        return CaseRecord(
            case_id=str(row["id"]),
            source_id=str(row["source_id"]),
            split=split,
            task=str(row["task"]),
            evidence=evidence,
        )

    def _load_cases(self, archive: zipfile.ZipFile) -> None:
        if self.pack_kind in CONTRACT_PACK_KINDS:
            self._load_contract_pack_cases(archive)
            return
        self._load_nvd_cases(archive)

    def _load_nvd_cases(self, archive: zipfile.ZipFile) -> None:
        # Training is deliberately not a runnable split. Its labeled rows stay
        # inside the frozen artifact for explicit fine-tuning workflows only.
        train_entry = "canonical/train_8000.canonical.jsonl"
        for row in self._read_entry_rows(archive, train_entry):
            label = row.get("target", {}).get("triage_priority")
            if not isinstance(label, str):
                raise ArchiveValidationError("Train canonical record has no target label.")
            self._case_from_row(row, "train")
            self._train_count += 1
        if self.strict_contract and self._train_count != 8000:
            raise ArchiveValidationError("Train entry count does not match its package contract.")

        for split, count in (("eval", 1000), ("challenge", 750)):
            entry = f"export/{split}_{count}.inputs.jsonl"
            answer_entry = f"answers/{split}_{count}.answers.jsonl"
            self._entry_by_split[split] = entry
            rows = list(self._read_entry_rows(archive, entry))
            if any(set(row) != _BLIND_KEYS for row in rows):
                raise ArchiveValidationError(f"{split} inputs are not blind records.")
            answer_rows = list(self._read_entry_rows(archive, answer_entry))
            answers = {str(row.get("id")): row.get("triage_priority") for row in answer_rows}
            if len(rows) != count or len(answers) != count:
                raise ArchiveValidationError(f"{split} entry count does not match its package contract.")
            for row in rows:
                case = self._case_from_row(row, split)
                label = answers.get(case.case_id)
                if not isinstance(label, str):
                    raise ArchiveValidationError(f"{split} answer alignment failed for {case.case_id}.")
                self._add_case(case, label)

        preview_entry = "export/preview_250.jsonl"
        self._preview_count = sum(1 for _ in self._read_entry_rows(archive, preview_entry))
        if self._preview_count != 250:
            raise ArchiveValidationError("Preview entry count does not match its package contract.")

    def _evaluate_contract_task(
        self, task: str, evidence: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        """Dispatch deterministic rubric for contract packs (agent_ops, policy_gate, …)."""
        if self.pack_kind == PACK_KIND_POLICY_GATE or task == "policy-shall-gate-v1":
            from .policy_gate_rubric import evaluate_policy_shall_gate

            return evaluate_policy_shall_gate(evidence)
        if self.pack_kind == PACK_KIND_TOOL_CONTRACT or task == "tool-contract-v1":
            from .tool_contract_rubric import evaluate_tool_contract

            return evaluate_tool_contract(evidence)
        from .agent_ops_rubric import evaluate_agent_ops

        return evaluate_agent_ops(task, evidence)

    def _load_contract_pack_cases(self, archive: zipfile.ZipFile) -> None:
        """Load PACK_CONTRACT-driven packs (agent_ops, policy_gate, …)."""
        contract = self.pack_contract or {}
        splits = contract.get("splits") or {}
        try:
            n_train = int(splits["train"])
            n_eval = int(splits["eval"])
            n_challenge = int(splits["challenge"])
            n_preview = int(splits["preview"])
        except (KeyError, TypeError, ValueError) as error:
            raise ArchiveValidationError(
                "contract pack requires splits.train/eval/challenge/preview in PACK_CONTRACT.json"
            ) from error

        # PROVENANCE.jsonl required for T2/T3 (EVAL_BASELINE)
        if self.pack_kind in {PACK_KIND_POLICY_GATE, PACK_KIND_TOOL_CONTRACT}:
            prov_name = self.root + "reports/PROVENANCE.jsonl"
            try:
                archive.read(prov_name)
            except KeyError as error:
                raise ArchiveValidationError(
                    f"{self.pack_kind} packs require reports/PROVENANCE.jsonl"
                ) from error

        train_entry = f"canonical/train_{n_train}.canonical.jsonl"
        for row in self._read_entry_rows(archive, train_entry):
            label = row.get("target", {}).get("label")
            if not isinstance(label, str):
                raise ArchiveValidationError("Train canonical record has no target.label.")
            case = self._case_from_row(row, "train")
            derived, trace = self._evaluate_contract_task(case.task, case.evidence)
            if derived != label:
                raise ArchiveValidationError(
                    f"Train label/rubric mismatch for {case.case_id}: {label} != {derived}"
                )
            if row.get("rubric_trace") != trace:
                raise ArchiveValidationError(f"Train rubric_trace mismatch for {case.case_id}.")
            self._train_count += 1
        if self.strict_contract and self._train_count != n_train:
            raise ArchiveValidationError("Train entry count does not match its package contract.")

        for split, count in (("eval", n_eval), ("challenge", n_challenge)):
            entry = f"export/{split}_{count}.inputs.jsonl"
            answer_entry = f"answers/{split}_{count}.answers.jsonl"
            self._entry_by_split[split] = entry
            rows = list(self._read_entry_rows(archive, entry))
            if any(set(row) != _BLIND_KEYS for row in rows):
                raise ArchiveValidationError(f"{split} inputs are not blind records.")
            answer_rows = list(self._read_entry_rows(archive, answer_entry))
            answers = {str(row.get("id")): row.get("label") for row in answer_rows}
            if len(rows) != count or len(answers) != count:
                raise ArchiveValidationError(f"{split} entry count does not match its package contract.")
            for row in rows:
                case = self._case_from_row(row, split)
                label = answers.get(case.case_id)
                if not isinstance(label, str):
                    raise ArchiveValidationError(f"{split} answer alignment failed for {case.case_id}.")
                derived, _ = self._evaluate_contract_task(case.task, case.evidence)
                if derived != label:
                    raise ArchiveValidationError(
                        f"{split} sealed answer disagrees with rubric for {case.case_id}."
                    )
                self._add_case(case, label)

        preview_entry = f"export/preview_{n_preview}.jsonl"
        self._preview_count = sum(1 for _ in self._read_entry_rows(archive, preview_entry))
        if self._preview_count != n_preview:
            raise ArchiveValidationError("Preview entry count does not match its package contract.")

    def _add_case(self, case: CaseRecord, label: str) -> None:
        if case.case_id in self._cases[case.split]:
            raise ArchiveValidationError(f"Duplicate {case.split} case id: {case.case_id}")
        self._cases[case.split][case.case_id] = case
        self._labels[case.split][case.case_id] = label

    @property
    def split_sizes(self) -> dict[str, int]:
        return {"train": self._train_count} | {
            split: len(cases) for split, cases in self._cases.items()
        } | {"preview": self._preview_count}

    def get_case(self, split: str, case_id: str) -> CaseRecord:
        if split not in RUN_SPLITS:
            raise SplitAccessError(f"{split!r} is not a runnable split.")
        try:
            return self._copy_case(self._cases[split][case_id])
        except KeyError as error:
            raise SplitAccessError(f"Case {case_id!r} is not in split {split!r}.") from error

    def select_cases(self, split: str, count: int, selection_seed: str | None = None) -> tuple[str, list[CaseRecord]]:
        if split not in RUN_SPLITS:
            raise SplitAccessError(f"{split!r} is not a runnable split.")
        if count < 1 or count > len(self._cases[split]):
            raise SplitAccessError(f"count must be between 1 and {len(self._cases[split])} for {split}.")
        seed = selection_seed or secrets.token_hex(16)

        def rank(case_id: str) -> bytes:
            material = f"{self.archive_sha256}\0{split}\0{seed}\0{case_id}".encode("utf-8")
            return hashlib.sha256(material).digest()

        ordered = sorted(self._cases[split], key=rank)
        return seed, [self._copy_case(self._cases[split][case_id]) for case_id in ordered[:count]]

    @staticmethod
    def _copy_case(case: CaseRecord) -> CaseRecord:
        return CaseRecord(
            case_id=case.case_id,
            source_id=case.source_id,
            split=case.split,
            task=case.task,
            evidence=deepcopy(case.evidence),
        )

    def _expected_label(self, case: CaseRecord) -> str:
        """Private scoring path; never call this from a public case endpoint."""
        return self._labels[case.split][case.case_id]

    def scoring_context(self, case: CaseRecord) -> tuple[str, dict[str, Any]]:
        """Return sealed target and recomputed trace after a response is persisted."""
        expected = self._expected_label(case)
        if self.pack_kind in CONTRACT_PACK_KINDS:
            derived, trace = self._evaluate_contract_task(case.task, case.evidence)
        else:
            derived, trace = evaluate_rubric(case.evidence)
        if expected != derived:
            raise ArchiveValidationError(
                f"Sealed answer and local rubric disagree for {case.case_id}: {expected} != {derived}"
            )
        return expected, trace

    def training_artifact(self) -> dict[str, Any]:
        """Metadata only; the engine never streams training labels to a model run."""
        if self.pack_kind in CONTRACT_PACK_KINDS:
            n = (self.pack_contract or {}).get("splits", {}).get("train", self._train_count)
            entry = f"export/train_{n}.sft_messages.jsonl"
            id_semantics = "provenanced public source_id"
        else:
            entry = "export/train_8000.sft_messages.jsonl"
            id_semantics = "CVE source_id, not canonical prediction id"
        size, digest = self._manifest[entry]
        return {
            "entry": entry,
            "sha256": digest,
            "bytes": size,
            "records": self._train_count,
            "id_semantics": id_semantics,
            "pack_kind": self.pack_kind,
        }

    def iter_train_trace_records(self) -> Iterator[tuple[CaseRecord, str, dict[str, Any]]]:
        """Yield train-only records for an explicit derived-SFT build.

        This route is not available to live model runs. Every returned label and
        trace is freshly recomputed before it can become training material.
        """
        train_entry = "canonical/train_8000.canonical.jsonl"
        with zipfile.ZipFile(self.archive_path) as archive:
            for row in self._read_entry_rows(archive, train_entry):
                case = self._case_from_row(row, "train")
                expected = row.get("target", {}).get("triage_priority")
                derived, trace = evaluate_rubric(case.evidence)
                if expected != derived or row.get("rubric_trace") != trace:
                    raise ArchiveValidationError(
                        f"Train record does not match the local rubric: {case.case_id}"
                    )
                yield self._copy_case(case), derived, trace

    def verify_deep(self) -> ArchiveReport:
        """Recompute the exact rubric for every canonical record on demand."""
        failures = 0
        full_entry = "canonical/full_10000.canonical.jsonl"
        with zipfile.ZipFile(self.archive_path) as archive:
            split_counts: Counter[str] = Counter()
            unique_ids: set[str] = set()
            for row in self._read_entry_rows(archive, full_entry):
                case = self._case_from_row(row, str(row.get("split", "")))
                expected = row.get("target", {}).get("triage_priority")
                trace = row.get("rubric_trace")
                derived, fresh_trace = evaluate_rubric(case.evidence)
                if derived != expected or fresh_trace != trace:
                    failures += 1
                split_counts[case.split] += 1
                unique_ids.add(case.case_id)
        if len(unique_ids) != 10000:
            raise ArchiveValidationError("Full canonical archive does not contain 10,000 unique records.")
        expected_counts = {"train": 8000, "eval": 1000, "challenge": 750, "preview": 250}
        if dict(split_counts) != expected_counts:
            raise ArchiveValidationError("Canonical split distribution differs from the package contract.")
        return ArchiveReport(
            archive_path=str(self.archive_path),
            archive_sha256=self.archive_sha256,
            expected_archive_sha256=self.expected_archive_sha256,
            provenance_pinned=self.provenance_pinned,
            root=self.root,
            zip_entry_count=self._zip_entry_count,
            file_count=self._file_count,
            manifest_entries_verified=len(self._manifest),
            record_counts=self.split_sizes,
            rubric_alignment_failures=failures,
        )
