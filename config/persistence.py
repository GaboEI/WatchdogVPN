from __future__ import annotations

import base64
import json
import os
import tempfile
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Iterator

import fcntl


class PersistentStoreError(RuntimeError):
    pass


class PersistentValidationError(PersistentStoreError):
    pass


SHARED_DIR_SETGID_MODE = 0o2770
SHARED_FILE_MODE = 0o660
RESTORE_TRANSACTION_JOURNAL_NAME = ".watchdogvpn-restore-transaction.json"
RESTORE_TRANSACTION_JOURNAL_SCHEMA_VERSION = 2

_held_lock_paths: ContextVar[frozenset[str]] = ContextVar(
    "watchdogvpn_held_lock_paths",
    default=frozenset(),
)
_restore_recovery_depth: ContextVar[int] = ContextVar(
    "watchdogvpn_restore_recovery_depth",
    default=0,
)


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    path = Path(path)
    path_key = str(path.resolve(strict=False))
    held_paths = _held_lock_paths.get()
    if path_key in held_paths:
        yield
        return
    if _restore_recovery_depth.get() == 0 and path.name != RESTORE_TRANSACTION_JOURNAL_NAME:
        directory = _restore_journal_directory(path.parent)
        if directory is not None:
            recover_pending_restore_transaction(directory)
    _ensure_parent_dir(path)
    lock_path = path.with_name(f"{path.name}.lock")
    with lock_path.open("a", encoding="utf-8") as handle:
        _ensure_shared_file_mode(lock_path)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        token = _held_lock_paths.set(held_paths | {path_key})
        try:
            yield
        finally:
            _held_lock_paths.reset(token)
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def atomic_write_text(path: Path, text: str) -> None:
    _atomic_write(path, text.encode("utf-8"))


def atomic_write_bytes(path: Path, data: bytes) -> None:
    _atomic_write(path, data)


def _atomic_write(path: Path, data: bytes) -> None:
    _ensure_parent_dir(path)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _ensure_shared_file_mode(tmp_path)
        os.replace(tmp_path, path)
        _ensure_shared_file_mode(path)
        fsync_parent_directory(path)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def fsync_parent_directory(path: Path) -> None:
    """Make a successful atomic replacement durable across a host crash.

    fsyncing the temporary file makes its contents durable, but the directory
    entry created by ``os.replace`` is not durable until its parent directory
    is fsynced too.  A failure after replace cannot be rolled back safely: the
    new inode may already be visible. Raise an explicit error so callers never
    certify that security-relevant state was durably published.
    """
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(path.parent, flags)
    except OSError as exc:
        raise PersistentStoreError(
            f"cannot open parent directory for durable atomic write {path}: {exc}"
        ) from exc
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise PersistentStoreError(
            f"atomic replacement of {path} was published but parent-directory fsync failed; "
            f"durability is not confirmed: {exc}"
        ) from exc
    finally:
        try:
            os.close(directory_fd)
        except OSError:
            pass


def _ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if _is_shared_state_path(path):
        _chmod_shared_dirs(path.parent)


def _chmod_shared_dirs(path: Path) -> None:
    from config import paths as config_paths

    system_dir = config_paths.SYSTEM_CONFIG_DIR
    try:
        current = path.resolve(strict=False)
        root = system_dir.resolve(strict=False)
        current.relative_to(root)
    except ValueError:
        return
    while True:
        try:
            current.chmod(SHARED_DIR_SETGID_MODE)
        except OSError:
            return
        if current == root:
            return
        current = current.parent


def _ensure_shared_file_mode(path: Path) -> None:
    if not _is_shared_state_path(path):
        return
    try:
        path.chmod(SHARED_FILE_MODE)
    except OSError:
        pass


def _is_shared_state_path(path: Path) -> bool:
    from config import paths as config_paths

    try:
        path.resolve(strict=False).relative_to(config_paths.SYSTEM_CONFIG_DIR.resolve(strict=False))
        return True
    except ValueError:
        return False


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PersistentStoreError(f"invalid JSON in {path}: {exc}") from exc
    except OSError as exc:
        raise PersistentStoreError(f"cannot read {path}: {exc}") from exc


def dump_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def require_mapping(value: Any, path: Path) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PersistentValidationError(f"{path} must contain a JSON object")
    return value


def require_list(value: Any, path: Path) -> list[Any]:
    if not isinstance(value, list):
        raise PersistentValidationError(f"{path} must contain a JSON array")
    return value


def strict_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    raise PersistentValidationError(f"{field} must be a boolean")


def strict_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PersistentValidationError(f"{field} must be an integer")
    return value


def strict_float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PersistentValidationError(f"{field} must be a number")
    return float(value)


def reject_unknown_keys(data: dict[str, Any], allowed: set[str], object_name: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        names = ", ".join(unknown)
        raise PersistentValidationError(f"{object_name} contains unsupported fields: {names}")

def restore_transaction_journal_path(directory: Path) -> Path:
    return Path(directory) / RESTORE_TRANSACTION_JOURNAL_NAME


def write_restore_transaction_journal(
    directory: Path,
    snapshots: dict[Path, bytes | None],
    *,
    prune_unlisted_rule_files: bool = False,
) -> Path:
    directory = Path(directory)
    journal = restore_transaction_journal_path(directory)
    if journal.exists():
        raise PersistentStoreError(f"pending restore transaction journal: {journal}")
    entries: list[dict[str, str | None]] = []
    for path, content in sorted(snapshots.items(), key=lambda item: str(item[0])):
        relative = Path(path).relative_to(directory)
        if relative.name == RESTORE_TRANSACTION_JOURNAL_NAME:
            raise PersistentStoreError("restore journal cannot include itself")
        entries.append({"name": str(relative), "content_b64": (
            base64.b64encode(content).decode("ascii") if content is not None else None
        )})
    atomic_write_text(journal, json.dumps({
        "schema_version": RESTORE_TRANSACTION_JOURNAL_SCHEMA_VERSION,
        "kind": "watchdogvpn-restore-rollback",
        "prune_unlisted_rule_files": prune_unlisted_rule_files,
        "files": entries,
    }, indent=2, sort_keys=True) + "\n")
    return journal


def clear_restore_transaction_journal(directory: Path) -> None:
    journal = restore_transaction_journal_path(directory)
    try:
        journal.unlink()
    except FileNotFoundError:
        return
    fsync_parent_directory(journal)


def recover_pending_restore_transaction(directory: Path) -> bool:
    directory = Path(directory)
    journal = restore_transaction_journal_path(directory)
    if not journal.exists():
        return False
    token = _restore_recovery_depth.set(_restore_recovery_depth.get() + 1)
    try:
        with ExitStack() as stack:
            stack.enter_context(file_lock(journal))
            if not journal.exists():
                return False
            try:
                data = json.loads(journal.read_text(encoding="utf-8"))
                files, prune_unlisted_rule_files = _restore_journal_payload(data, directory)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise PersistentStoreError(f"invalid restore transaction journal {journal}: {exc}") from exc
            lock_paths = set(files)
            rules_dir = directory / "rules"
            if prune_unlisted_rule_files and rules_dir.exists():
                lock_paths.update(rules_dir.glob("*.json"))
            for path in sorted(lock_paths, key=lambda item: str(item.resolve(strict=False))):
                stack.enter_context(file_lock(path))
            if prune_unlisted_rule_files and rules_dir.exists():
                for path in rules_dir.glob("*.json"):
                    if path not in files:
                        path.unlink(missing_ok=True)
                        fsync_parent_directory(path)
            for path, content in files.items():
                if content is None:
                    path.unlink(missing_ok=True)
                    fsync_parent_directory(path)
                else:
                    atomic_write_bytes(path, content)
            clear_restore_transaction_journal(directory)
            return True
    finally:
        _restore_recovery_depth.reset(token)


def _restore_journal_payload(
    data: object,
    directory: Path,
) -> tuple[dict[Path, bytes | None], bool]:
    if not isinstance(data, dict):
        raise ValueError("journal must be an object")
    schema_version = data.get("schema_version")
    if schema_version not in {1, RESTORE_TRANSACTION_JOURNAL_SCHEMA_VERSION}:
        raise ValueError("unsupported schema_version")
    if data.get("kind") != "watchdogvpn-restore-rollback":
        raise ValueError("unsupported journal kind")
    if schema_version == 1:
        # Version 1 used a dangerously broad name. Restore only the class of
        # paths a backup restore itself can create: top-level rule documents.
        prune_unlisted_rule_files = data.get("remove_unlisted_json", False)
    else:
        prune_unlisted_rule_files = data.get("prune_unlisted_rule_files", False)
    entries = data.get("files")
    if not isinstance(prune_unlisted_rule_files, bool) or not isinstance(entries, list):
        raise ValueError("journal structure is invalid")
    files: dict[Path, bytes | None] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("journal file entry is invalid")
        relative = Path(entry["name"])
        if not relative.parts or relative.is_absolute() or ".." in relative.parts:
            raise ValueError("journal file name is invalid")
        path = directory / relative
        encoded = entry.get("content_b64")
        if path in files:
            raise ValueError("journal contains duplicate file entries")
        if encoded is None:
            files[path] = None
        elif isinstance(encoded, str):
            files[path] = base64.b64decode(encoded.encode("ascii"), validate=True)
        else:
            raise ValueError("journal content is invalid")
    return files, prune_unlisted_rule_files


def _restore_journal_directory(directory: Path) -> Path | None:
    current = Path(directory)
    while True:
        if restore_transaction_journal_path(current).exists():
            return current
        if current.parent == current:
            return None
        current = current.parent
