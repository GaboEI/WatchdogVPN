"""Durable transaction journal (Phase 23.7.5.6a).

Its own schema and its own recovery semantics -- this is deliberately NOT the
``config.persistence`` restore-transaction journal (that one is scoped to
backup/restore rollback and triggers its own recovery side effects on any
``file_lock`` use under the shared config directory). Only the primitive
atomic-write/fsync helpers are reused here.
"""

from __future__ import annotations

from collections.abc import Mapping as MappingABC
import dataclasses
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Mapping, Sequence

from config.persistence import atomic_write_text, fsync_parent_directory

from compat.provisioning.errors import JournalError
from compat.provisioning.model import (
    OwnershipCandidate,
    OwnershipRecord,
    StepState,
    TRANSACTION_TRANSITIONS,
    TransactionState,
    transition_step,
    transition_transaction,
)

SCHEMA_VERSION = 1
TRANSACTIONS_DIR = "transactions"
HISTORY_DIR = "history"
OWNERSHIP_DIR = "ownership"
LOCK_FILE_NAME = "provisioner.lock"

_SENSITIVE_KEY_MARKERS = ("password", "secret", "token", "credential", "api_key", "apikey")
_CREDENTIALED_URL_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+:[^/@\s]+@")


@dataclass(frozen=True)
class StepRecord:
    sequence: int
    step_id: str
    action_type: str
    state: StepState
    intent: Mapping[str, object]
    target: str | None = None
    before_state: Mapping[str, object] | None = None
    started_at: str | None = None
    completed_at: str | None = None
    verification: Mapping[str, object] | None = None
    undo_record: Mapping[str, object] | None = None
    error_kind: str | None = None
    error: str | None = None

    def with_state(self, new_state: StepState, **updates: object) -> "StepRecord":
        transition_step(self.state, new_state)
        return dataclasses.replace(self, state=new_state, **updates)


@dataclass(frozen=True)
class TransactionJournal:
    schema_version: int
    transaction_id: str
    operation: str
    state: TransactionState
    created_at: str
    updated_at: str
    plan_digest: str
    capability_id: str
    dependency_id: str
    target: str
    architecture: str
    support_classification: str
    selected_method: Mapping[str, str]
    executor: Mapping[str, str]
    steps: tuple[StepRecord, ...]
    ownership_candidates: tuple[Mapping[str, object], ...] = ()
    provenance: Mapping[str, object] | None = None
    failure: Mapping[str, object] | None = None
    recovery: Mapping[str, object] | None = None

    def is_terminal(self) -> bool:
        return TRANSACTION_TRANSITIONS[self.state] == frozenset()

    def with_state(self, new_state: TransactionState, *, now: str, **updates: object) -> "TransactionJournal":
        transition_transaction(self.state, new_state)
        return dataclasses.replace(self, state=new_state, updated_at=now, **updates)

    def step(self, sequence: int) -> StepRecord:
        for step in self.steps:
            if step.sequence == sequence:
                return step
        raise JournalError("journal %s has no step with sequence %d" % (self.transaction_id, sequence))

    def with_step(self, updated: StepRecord) -> "TransactionJournal":
        new_steps = tuple(updated if step.sequence == updated.sequence else step for step in self.steps)
        return dataclasses.replace(self, steps=new_steps)


def transactions_dir(state_root: Path) -> Path:
    return Path(state_root) / TRANSACTIONS_DIR


def history_dir(state_root: Path) -> Path:
    return Path(state_root) / HISTORY_DIR


def ownership_dir(state_root: Path) -> Path:
    return Path(state_root) / OWNERSHIP_DIR


def lock_path(state_root: Path) -> Path:
    return Path(state_root) / LOCK_FILE_NAME


def transaction_path(state_root: Path, transaction_id: str) -> Path:
    return transactions_dir(state_root) / ("%s.json" % transaction_id)


def history_path(state_root: Path, transaction_id: str) -> Path:
    return history_dir(state_root) / ("%s.json" % transaction_id)


def ownership_path(state_root: Path, capability_id: str) -> Path:
    return ownership_dir(state_root) / ("%s.json" % capability_id)


def write_journal(state_root: Path, journal: TransactionJournal) -> None:
    payload = json.dumps(to_jsonable(journal), indent=2, sort_keys=True) + "\n"
    path = transaction_path(state_root, journal.transaction_id)
    atomic_write_text(path, payload)
    if journal.is_terminal():
        atomic_write_text(history_path(state_root, journal.transaction_id), payload)


def read_journal(state_root: Path, transaction_id: str) -> TransactionJournal:
    path = transaction_path(state_root, transaction_id)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise JournalError("cannot read journal %s: %s" % (path, exc)) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise JournalError("corrupt journal %s: %s" % (path, exc)) from exc
    return from_jsonable(data)


def list_transaction_ids(state_root: Path) -> list[str]:
    directory = transactions_dir(state_root)
    if not directory.exists():
        return []
    return sorted(entry.stem for entry in directory.glob("*.json"))


def list_pending_transaction_ids(state_root: Path) -> list[str]:
    """Every non-terminal transaction id, plus any journal that fails to parse
    (a corrupt/unknown-schema/invalid journal must block the provisioner, not
    be silently skipped)."""
    pending = []
    for transaction_id in list_transaction_ids(state_root):
        try:
            journal = read_journal(state_root, transaction_id)
        except JournalError:
            pending.append(transaction_id)
            continue
        if not journal.is_terminal():
            pending.append(transaction_id)
    return pending


def write_ownership_records(state_root: Path, capability_id: str, records: Sequence[OwnershipRecord]) -> None:
    payload = json.dumps([_ownership_to_jsonable(record) for record in records], indent=2, sort_keys=True) + "\n"
    atomic_write_text(ownership_path(state_root, capability_id), payload)


def read_ownership_records(state_root: Path, capability_id: str) -> list[OwnershipRecord]:
    path = ownership_path(state_root, capability_id)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise JournalError("cannot read ownership records %s: %s" % (path, exc)) from exc
    if not isinstance(data, list):
        raise JournalError("ownership records %s must be a JSON array" % path)
    return [_ownership_from_jsonable(item) for item in data]


def delete_ownership_records(state_root: Path, capability_id: str) -> None:
    path = ownership_path(state_root, capability_id)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    fsync_parent_directory(path)


def _ownership_to_jsonable(record: OwnershipRecord) -> dict:
    candidate = record.candidate
    return {
        "capability_id": record.capability_id,
        "product_owned": record.product_owned,
        "created_by_transaction": record.created_by_transaction,
        "executor_id": record.executor_id,
        "executor_version": record.executor_version,
        "recorded_at": record.recorded_at,
        "candidate": {
            "artifact_type": candidate.artifact_type,
            "resource_identity": candidate.resource_identity,
            "pre_existing": candidate.pre_existing,
            "method_id": candidate.method_id,
            "source": candidate.source,
            "version": candidate.version,
            "integrity": candidate.integrity,
            "uid": candidate.uid,
            "gid": candidate.gid,
            "mode": candidate.mode,
            "post_install_fingerprint": candidate.post_install_fingerprint,
        },
    }


def _ownership_from_jsonable(data: object) -> OwnershipRecord:
    if not isinstance(data, dict):
        raise JournalError("ownership record must be a JSON object")
    try:
        candidate_data = data["candidate"]
        candidate = OwnershipCandidate(
            artifact_type=candidate_data["artifact_type"],
            resource_identity=candidate_data["resource_identity"],
            pre_existing=candidate_data["pre_existing"],
            method_id=candidate_data.get("method_id"),
            source=candidate_data.get("source"),
            version=candidate_data.get("version"),
            integrity=candidate_data.get("integrity"),
            uid=candidate_data.get("uid"),
            gid=candidate_data.get("gid"),
            mode=candidate_data.get("mode"),
            post_install_fingerprint=candidate_data.get("post_install_fingerprint"),
        )
        return OwnershipRecord(
            capability_id=data["capability_id"],
            candidate=candidate,
            product_owned=data["product_owned"],
            created_by_transaction=data.get("created_by_transaction"),
            executor_id=data["executor_id"],
            executor_version=data["executor_version"],
            recorded_at=data["recorded_at"],
        )
    except (KeyError, TypeError) as exc:
        raise JournalError("invalid ownership record structure: %s" % exc) from exc


def redact_for_journal(value: object) -> object:
    if isinstance(value, MappingABC):
        return {
            str(key): ("***redacted***" if _is_sensitive_key(key) else redact_for_journal(item))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_for_journal(item) for item in value]
    if isinstance(value, str):
        return _CREDENTIALED_URL_RE.sub(lambda m: m.group(1) + "***redacted***@", value)
    return value


def _is_sensitive_key(key: object) -> bool:
    lowered = str(key).lower()
    return any(marker in lowered for marker in _SENSITIVE_KEY_MARKERS)


def to_jsonable(journal: TransactionJournal) -> dict:
    return {
        "schema_version": journal.schema_version,
        "transaction_id": journal.transaction_id,
        "operation": journal.operation,
        "state": journal.state.value,
        "created_at": journal.created_at,
        "updated_at": journal.updated_at,
        "plan_digest": journal.plan_digest,
        "capability_id": journal.capability_id,
        "dependency_id": journal.dependency_id,
        "target": journal.target,
        "architecture": journal.architecture,
        "support_classification": journal.support_classification,
        "selected_method": dict(journal.selected_method),
        "executor": dict(journal.executor),
        "steps": [_step_to_jsonable(step) for step in journal.steps],
        "ownership_candidates": [redact_for_journal(item) for item in journal.ownership_candidates],
        "provenance": redact_for_journal(journal.provenance) if journal.provenance is not None else None,
        "failure": redact_for_journal(journal.failure) if journal.failure is not None else None,
        "recovery": redact_for_journal(journal.recovery) if journal.recovery is not None else None,
    }


def _step_to_jsonable(step: StepRecord) -> dict:
    return {
        "sequence": step.sequence,
        "step_id": step.step_id,
        "action_type": step.action_type,
        "state": step.state.value,
        "intent": redact_for_journal(step.intent),
        "target": step.target,
        "before_state": redact_for_journal(step.before_state) if step.before_state is not None else None,
        "started_at": step.started_at,
        "completed_at": step.completed_at,
        "verification": redact_for_journal(step.verification) if step.verification is not None else None,
        "undo_record": redact_for_journal(step.undo_record) if step.undo_record is not None else None,
        "error_kind": step.error_kind,
        "error": step.error,
    }


def from_jsonable(data: object) -> TransactionJournal:
    if not isinstance(data, dict):
        raise JournalError("journal must be a JSON object")
    schema_version = data.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise JournalError("unsupported journal schema_version: %r" % (schema_version,))
    try:
        return TransactionJournal(
            schema_version=schema_version,
            transaction_id=_require_str(data, "transaction_id"),
            operation=_require_str(data, "operation"),
            state=_require_enum(data, "state", TransactionState),
            created_at=_require_str(data, "created_at"),
            updated_at=_require_str(data, "updated_at"),
            plan_digest=_require_hex_digest(data, "plan_digest"),
            capability_id=_require_str(data, "capability_id"),
            dependency_id=_require_str(data, "dependency_id"),
            target=_require_str(data, "target"),
            architecture=_require_str(data, "architecture"),
            support_classification=_require_str(data, "support_classification"),
            selected_method=_require_mapping(data, "selected_method"),
            executor=_require_mapping(data, "executor"),
            steps=tuple(_step_from_jsonable(item) for item in _require_list(data, "steps")),
            ownership_candidates=tuple(_require_list(data, "ownership_candidates", default=[])),
            provenance=data.get("provenance"),
            failure=data.get("failure"),
            recovery=data.get("recovery"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise JournalError("invalid journal structure: %s" % exc) from exc


def _step_from_jsonable(data: object) -> StepRecord:
    if not isinstance(data, dict):
        raise JournalError("journal step must be a JSON object")
    try:
        return StepRecord(
            sequence=_require_int(data, "sequence"),
            step_id=_require_str(data, "step_id"),
            action_type=_require_str(data, "action_type"),
            state=_require_enum(data, "state", StepState),
            intent=_require_mapping(data, "intent"),
            target=data.get("target"),
            before_state=data.get("before_state"),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            verification=data.get("verification"),
            undo_record=data.get("undo_record"),
            error_kind=data.get("error_kind"),
            error=data.get("error"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise JournalError("invalid journal step structure: %s" % exc) from exc


def _require_str(data: Mapping, field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise JournalError("journal field %r must be a non-empty string" % field)
    return value


def _require_int(data: Mapping, field: str) -> int:
    value = data.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise JournalError("journal field %r must be an integer" % field)
    return value


def _require_mapping(data: Mapping, field: str) -> dict:
    value = data.get(field)
    if not isinstance(value, dict):
        raise JournalError("journal field %r must be an object" % field)
    return value


def _require_list(data: Mapping, field: str, *, default: list | None = None) -> Sequence:
    value = data.get(field, default)
    if not isinstance(value, list):
        raise JournalError("journal field %r must be an array" % field)
    return value


def _require_hex_digest(data: Mapping, field: str) -> str:
    value = _require_str(data, field)
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise JournalError("journal field %r must be a lowercase sha256 hex digest" % field)
    return value


def _require_enum(data: Mapping, field: str, enum_cls) -> object:
    value = data.get(field)
    if not isinstance(value, str):
        raise JournalError("journal field %r must be a string" % field)
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise JournalError("journal field %r has unknown value %r" % (field, value)) from exc
