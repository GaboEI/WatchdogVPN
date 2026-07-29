"""Durable transaction journal (Phase 23.7.5.6a).

Its own schema and its own recovery semantics -- this is deliberately NOT the
``config.persistence`` restore-transaction journal (that one is scoped to
backup/restore rollback and triggers its own recovery side effects on any
``file_lock`` use under the shared config directory). Storage is fully
private to this module: see ``compat.provisioning.storage`` for why the
shared-group ``config.persistence`` primitives are never reused here.
"""

from __future__ import annotations

from collections.abc import Mapping as MappingABC
import dataclasses
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Mapping, Sequence

from compat.provisioning.errors import CorruptStateError, IdentifierError, JournalError
from compat.provisioning.model import (
    IntermediateIdentity,
    OwnershipCandidate,
    OwnershipRecord,
    PathAuthority,
    PathComponentIdentity,
    StepState,
    TRANSACTION_TRANSITIONS,
    TransactionState,
    transition_step,
    transition_transaction,
)
from compat.provisioning.paths import validate_identifier
from compat.provisioning.storage import (
    StateRootHandle,
    atomic_write_private_text,
    atomic_write_private_text_relative,
    delete_private_relative,
    ensure_private_subdir,
    fsync_parent_directory,
    list_json_names_relative,
    read_private_relative,
)

StateRootLike = "Path | StateRootHandle"

SCHEMA_VERSION = 1
TRANSACTIONS_DIR = "transactions"
HISTORY_DIR = "history"
OWNERSHIP_DIR = "ownership"

_SENSITIVE_KEY_MARKERS = ("password", "secret", "token", "credential", "api_key", "apikey")
_CREDENTIALED_URL_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+:[^/@\s]+@")

_OWNERSHIP_RECORD_FIELDS = frozenset(
    {"capability_id", "product_owned", "created_by_transaction", "executor_id", "executor_version", "recorded_at", "candidate"}
)
_OWNERSHIP_CANDIDATE_FIELDS = frozenset(
    {
        "artifact_type", "resource_identity", "pre_existing", "method_id", "source",
        "version", "integrity", "uid", "gid", "mode", "nlink", "post_install_fingerprint",
        "intermediate_identities",
        "path_authority",
    }
)

_INTERMEDIATE_IDENTITY_FIELDS = frozenset({"relative_name", "dev", "ino", "uid", "mode"})
_PATH_AUTHORITY_FIELDS = frozenset({"root_path", "target_relative_path", "component_count", "components"})
_PATH_COMPONENT_IDENTITY_FIELDS = frozenset({"index", "relative_name", "dev", "ino", "uid", "mode"})


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
    selected_asset: Mapping[str, object] | None = None
    ownership_candidates: tuple[Mapping[str, object], ...] = ()
    owned_snapshot: tuple[OwnershipRecord, ...] = ()
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


def transaction_path(state_root: Path, transaction_id: str) -> Path:
    validate_identifier(transaction_id, field="transaction_id")
    return transactions_dir(state_root) / ("%s.json" % transaction_id)


def history_path(state_root: Path, transaction_id: str) -> Path:
    validate_identifier(transaction_id, field="transaction_id")
    return history_dir(state_root) / ("%s.json" % transaction_id)


def ownership_path(state_root: Path, capability_id: str) -> Path:
    validate_identifier(capability_id, field="capability_id")
    return ownership_dir(state_root) / ("%s.json" % capability_id)


def write_journal(state_root: StateRootLike, journal: TransactionJournal) -> None:
    """Accepts either a bare ``state_root: Path`` (legacy/read-only callers
    outside a lock-protected transaction, e.g. status/dry-run) or a
    ``StateRootHandle`` (point 1: every mutating call inside
    prepare()/uninstall()/recover_pending() threads the SAME handle
    established once when the provisioner lock was acquired, so the write
    is bound to that exact directory via ``dir_fd``, never a fresh
    path-based lookup that an external rename/replace could redirect).

    When given a handle, ``state_root.verify_identity()`` is re-confirmed
    immediately before this mutating write (point 1, fifth correction
    round) -- covering every mutation, every terminal-state write, and
    every ownership publication in one place, since they all funnel through
    this module's write functions. A ``StateRootIdentityError`` here means
    the canonical, configured path no longer refers to the exact directory
    this transaction is bound to; the caller must never report a clean
    outcome in that case."""
    validate_identifier(journal.transaction_id, field="transaction_id")
    payload = json.dumps(to_jsonable(journal), indent=2, sort_keys=True) + "\n"
    name = "%s.json" % journal.transaction_id
    if isinstance(state_root, StateRootHandle):
        state_root.verify_identity()
        atomic_write_private_text_relative(state_root.subdir_fd(TRANSACTIONS_DIR), name, payload)
        if journal.is_terminal():
            atomic_write_private_text_relative(state_root.subdir_fd(HISTORY_DIR), name, payload)
    else:
        ensure_private_subdir(state_root, TRANSACTIONS_DIR)
        atomic_write_private_text(transaction_path(state_root, journal.transaction_id), payload)
        if journal.is_terminal():
            ensure_private_subdir(state_root, HISTORY_DIR)
            atomic_write_private_text(history_path(state_root, journal.transaction_id), payload)


def read_journal(state_root: StateRootLike, transaction_id: str) -> TransactionJournal:
    validate_identifier(transaction_id, field="transaction_id")
    name = "%s.json" % transaction_id
    if isinstance(state_root, StateRootHandle):
        try:
            raw = read_private_relative(state_root.subdir_fd(TRANSACTIONS_DIR), name)
        except (OSError, CorruptStateError) as exc:
            raise JournalError("cannot read journal %s: %s" % (transaction_id, exc)) from exc
    else:
        path = transaction_path(state_root, transaction_id)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise JournalError("cannot read journal %s: %s" % (path, exc)) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise JournalError("corrupt journal %s: %s" % (transaction_id, exc)) from exc
    return from_jsonable(data)


def list_transaction_ids(state_root: StateRootLike) -> list[str]:
    if isinstance(state_root, StateRootHandle):
        try:
            return list_json_names_relative(state_root.subdir_fd(TRANSACTIONS_DIR))
        except CorruptStateError as exc:
            raise JournalError("cannot list transactions: %s" % exc) from exc
    directory = transactions_dir(state_root)
    try:
        os.lstat(directory)
    except FileNotFoundError:
        return []
    return sorted(entry.stem for entry in directory.glob("*.json"))


def list_pending_transaction_ids(state_root: StateRootLike) -> list[str]:
    """Every non-terminal transaction id, plus any journal that fails to parse
    (a corrupt/unknown-schema/invalid journal must block the provisioner, not
    be silently skipped)."""
    pending = []
    for transaction_id in list_transaction_ids(state_root):
        try:
            journal = read_journal(state_root, transaction_id)
        except (JournalError, IdentifierError):
            pending.append(transaction_id)
            continue
        if not journal.is_terminal():
            pending.append(transaction_id)
    return pending


def write_ownership_records(state_root: StateRootLike, capability_id: str, records: Sequence[OwnershipRecord]) -> None:
    validate_identifier(capability_id, field="capability_id")
    payload = json.dumps(
        [redact_for_journal(_ownership_to_jsonable(record)) for record in records], indent=2, sort_keys=True
    ) + "\n"
    name = "%s.json" % capability_id
    if isinstance(state_root, StateRootHandle):
        state_root.verify_identity()
        atomic_write_private_text_relative(state_root.subdir_fd(OWNERSHIP_DIR), name, payload)
    else:
        ensure_private_subdir(state_root, OWNERSHIP_DIR)
        atomic_write_private_text(ownership_path(state_root, capability_id), payload)


def read_ownership_records(state_root: StateRootLike, capability_id: str) -> list[OwnershipRecord]:
    validate_identifier(capability_id, field="capability_id")
    name = "%s.json" % capability_id
    if isinstance(state_root, StateRootHandle):
        try:
            raw = read_private_relative(state_root.subdir_fd(OWNERSHIP_DIR), name)
        except FileNotFoundError:
            return []
        except (OSError, CorruptStateError) as exc:
            raise JournalError("cannot read ownership records %s: %s" % (capability_id, exc)) from exc
        descriptor = capability_id
    else:
        path = ownership_path(state_root, capability_id)
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise JournalError("cannot read ownership records %s: %s" % (path, exc)) from exc
        descriptor = path
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise JournalError("cannot read ownership records %s: %s" % (descriptor, exc)) from exc
    if not isinstance(data, list):
        raise JournalError("ownership records %s must be a JSON array" % descriptor)
    return [_ownership_from_jsonable(item) for item in data]


def delete_ownership_records(state_root: StateRootLike, capability_id: str) -> None:
    validate_identifier(capability_id, field="capability_id")
    name = "%s.json" % capability_id
    if isinstance(state_root, StateRootHandle):
        state_root.verify_identity()
        delete_private_relative(state_root.subdir_fd(OWNERSHIP_DIR), name)
        return
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
            "nlink": candidate.nlink,
            "post_install_fingerprint": candidate.post_install_fingerprint,
            "intermediate_identities": [_intermediate_identity_to_jsonable(item) for item in candidate.intermediate_identities],
            "path_authority": _path_authority_to_jsonable(candidate.path_authority) if candidate.path_authority is not None else None,
        },
    }


def _ownership_from_jsonable(data: object) -> OwnershipRecord:
    if not isinstance(data, dict):
        raise JournalError("ownership record must be a JSON object")
    unknown = set(data) - _OWNERSHIP_RECORD_FIELDS
    if unknown:
        raise JournalError("ownership record has unknown field(s): %s" % sorted(unknown))
    candidate_data = data.get("candidate")
    if not isinstance(candidate_data, dict):
        raise JournalError("ownership record field 'candidate' must be an object")
    unknown_candidate = set(candidate_data) - _OWNERSHIP_CANDIDATE_FIELDS
    if unknown_candidate:
        raise JournalError("ownership candidate has unknown field(s): %s" % sorted(unknown_candidate))
    try:
        candidate = OwnershipCandidate(
            artifact_type=_require_str(candidate_data, "artifact_type"),
            resource_identity=_require_absolute_path(candidate_data, "resource_identity"),
            pre_existing=_require_bool(candidate_data, "pre_existing"),
            method_id=_require_optional_str(candidate_data, "method_id"),
            source=_require_optional_str(candidate_data, "source"),
            version=_require_optional_str(candidate_data, "version"),
            integrity=_require_optional_hex_digest(candidate_data, "integrity"),
            uid=_require_optional_non_negative_int(candidate_data, "uid"),
            gid=_require_optional_non_negative_int(candidate_data, "gid"),
            mode=_require_optional_mode(candidate_data, "mode"),
            nlink=_require_optional_non_negative_int(candidate_data, "nlink"),
            post_install_fingerprint=_require_optional_str(candidate_data, "post_install_fingerprint"),
            intermediate_identities=tuple(
                _intermediate_identity_from_jsonable(item)
                for item in _require_list(candidate_data, "intermediate_identities", default=[])
            ),
            path_authority=_path_authority_from_jsonable(candidate_data.get("path_authority")),
        )
        return OwnershipRecord(
            capability_id=_require_identifier(data, "capability_id"),
            candidate=candidate,
            product_owned=_require_bool(data, "product_owned"),
            created_by_transaction=_require_optional_identifier(data, "created_by_transaction"),
            executor_id=_require_str(data, "executor_id"),
            executor_version=_require_str(data, "executor_version"),
            recorded_at=_require_str(data, "recorded_at"),
        )
    except (KeyError, TypeError) as exc:
        raise JournalError("invalid ownership record structure: %s" % exc) from exc


def _intermediate_identity_to_jsonable(identity: IntermediateIdentity) -> dict:
    return {
        "relative_name": identity.relative_name,
        "dev": identity.dev,
        "ino": identity.ino,
        "uid": identity.uid,
        "mode": identity.mode,
    }


def _intermediate_identity_from_jsonable(data: object) -> IntermediateIdentity:
    if not isinstance(data, dict):
        raise JournalError("intermediate identity must be a JSON object")
    unknown = set(data) - _INTERMEDIATE_IDENTITY_FIELDS
    if unknown:
        raise JournalError("intermediate identity has unknown field(s): %s" % sorted(unknown))
    relative_name = _require_str(data, "relative_name")
    relative_path = Path(relative_name)
    if relative_path.is_absolute() or ".." in relative_path.parts or not relative_path.parts:
        raise JournalError("intermediate identity relative_name must be a non-empty relative path without '..': %s" % relative_name)
    return IntermediateIdentity(
        relative_name=relative_name,
        dev=_require_non_negative_int(data, "dev"),
        ino=_require_non_negative_int(data, "ino"),
        uid=_require_non_negative_int(data, "uid"),
        mode=_require_mode(data, "mode"),
    )


def _path_authority_to_jsonable(authority: PathAuthority | None) -> dict | None:
    if authority is None:
        return None
    return {
        "root_path": authority.root_path,
        "target_relative_path": authority.target_relative_path,
        "component_count": authority.component_count,
        "components": [
            {
                "index": component.index,
                "relative_name": component.relative_name,
                "dev": component.dev,
                "ino": component.ino,
                "uid": component.uid,
                "mode": component.mode,
            }
            for component in authority.components
        ],
    }


def _path_authority_from_jsonable(data: object) -> PathAuthority | None:
    if data is None:
        return None
    if not isinstance(data, dict):
        raise JournalError("path authority must be a JSON object or null")
    unknown = set(data) - _PATH_AUTHORITY_FIELDS
    if unknown:
        raise JournalError("path authority has unknown field(s): %s" % sorted(unknown))
    root_path = _require_absolute_path(data, "root_path")
    target_relative_path = _require_str(data, "target_relative_path")
    target_relative = Path(target_relative_path)
    if target_relative.is_absolute() or ".." in target_relative.parts or not target_relative.parts:
        raise JournalError("path authority target_relative_path must be a non-empty relative path without '..': %s" % target_relative_path)
    components = tuple(_path_component_identity_from_jsonable(item) for item in _require_list(data, "components"))
    component_count = _require_non_negative_int(data, "component_count")
    if component_count != len(components):
        raise JournalError("path authority component_count does not match components length")
    indexes = [component.index for component in components]
    if indexes != list(range(len(components))):
        raise JournalError("path authority components must have exact contiguous indexes")
    return PathAuthority(
        root_path=root_path,
        target_relative_path=target_relative_path,
        component_count=component_count,
        components=components,
    )


def _path_component_identity_from_jsonable(data: object) -> PathComponentIdentity:
    if not isinstance(data, dict):
        raise JournalError("path authority component must be a JSON object")
    unknown = set(data) - _PATH_COMPONENT_IDENTITY_FIELDS
    if unknown:
        raise JournalError("path authority component has unknown field(s): %s" % sorted(unknown))
    relative_name = data.get("relative_name")
    if not isinstance(relative_name, str):
        raise JournalError("path authority component relative_name must be a string")
    if relative_name != "":
        relative_path = Path(relative_name)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise JournalError("path authority component relative_name must be relative without '..': %s" % relative_name)
    return PathComponentIdentity(
        index=_require_non_negative_int(data, "index"),
        relative_name=relative_name,
        dev=_require_non_negative_int(data, "dev"),
        ino=_require_non_negative_int(data, "ino"),
        uid=_require_non_negative_int(data, "uid"),
        mode=_require_mode(data, "mode"),
    )


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
        "selected_asset": redact_for_journal(journal.selected_asset) if journal.selected_asset is not None else None,
        "ownership_candidates": [redact_for_journal(item) for item in journal.ownership_candidates],
        "owned_snapshot": [redact_for_journal(_ownership_to_jsonable(record)) for record in journal.owned_snapshot],
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
            transaction_id=_require_identifier(data, "transaction_id"),
            operation=_require_str(data, "operation"),
            state=_require_enum(data, "state", TransactionState),
            created_at=_require_str(data, "created_at"),
            updated_at=_require_str(data, "updated_at"),
            plan_digest=_require_hex_digest(data, "plan_digest"),
            capability_id=_require_identifier(data, "capability_id"),
            dependency_id=_require_identifier(data, "dependency_id"),
            target=_require_str(data, "target"),
            architecture=_require_str(data, "architecture"),
            support_classification=_require_str(data, "support_classification"),
            selected_method=_require_mapping(data, "selected_method"),
            executor=_require_mapping(data, "executor"),
            steps=tuple(_step_from_jsonable(item) for item in _require_list(data, "steps")),
            selected_asset=_require_optional_mapping(data, "selected_asset"),
            ownership_candidates=tuple(_require_list(data, "ownership_candidates", default=[])),
            owned_snapshot=tuple(_ownership_from_jsonable(item) for item in _require_list(data, "owned_snapshot", default=[])),
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


def _require_optional_str(data: Mapping, field: str) -> str | None:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise JournalError("journal field %r must be a string or null" % field)
    return value


def _require_identifier(data: Mapping, field: str) -> str:
    value = data.get(field)
    try:
        return validate_identifier(value, field=field)
    except IdentifierError as exc:
        raise JournalError(str(exc)) from exc


def _require_optional_identifier(data: Mapping, field: str) -> str | None:
    value = data.get(field)
    if value is None:
        return None
    try:
        return validate_identifier(value, field=field)
    except IdentifierError as exc:
        raise JournalError(str(exc)) from exc


def _require_bool(data: Mapping, field: str) -> bool:
    value = data.get(field)
    if not isinstance(value, bool):
        raise JournalError("journal field %r must be a boolean" % field)
    return value


def _require_absolute_path(data: Mapping, field: str) -> str:
    value = _require_str(data, field)
    if "\x00" in value:
        raise JournalError("journal field %r must not contain a NUL byte" % field)
    candidate_path = Path(value)
    if not candidate_path.is_absolute() or ".." in candidate_path.parts:
        raise JournalError("journal field %r must be an absolute path without '..' components" % field)
    return value


def _require_optional_hex_digest(data: Mapping, field: str) -> str | None:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise JournalError("journal field %r must be a lowercase sha256 hex digest or null" % field)
    return value


def _require_optional_non_negative_int(data: Mapping, field: str) -> int | None:
    value = data.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise JournalError("journal field %r must be a non-negative integer or null" % field)
    return value


def _require_non_negative_int(data: Mapping, field: str) -> int:
    value = data.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise JournalError("journal field %r must be a non-negative integer" % field)
    return value


def _require_optional_mode(data: Mapping, field: str) -> int | None:
    value = _require_optional_non_negative_int(data, field)
    if value is not None and value > 0o7777:
        raise JournalError("journal field %r must be a valid file mode (<= 0o7777)" % field)
    return value


def _require_mode(data: Mapping, field: str) -> int:
    value = _require_non_negative_int(data, field)
    if value > 0o7777:
        raise JournalError("journal field %r must be a valid file mode (<= 0o7777)" % field)
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


def _require_optional_mapping(data: Mapping, field: str) -> dict | None:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise JournalError("journal field %r must be an object or null" % field)
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
