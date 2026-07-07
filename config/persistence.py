from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import fcntl


class PersistentStoreError(RuntimeError):
    pass


class PersistentValidationError(PersistentStoreError):
    pass


SHARED_DIR_SETGID_MODE = 0o2770
SHARED_FILE_MODE = 0o660


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    _ensure_parent_dir(path)
    lock_path = path.with_name(f"{path.name}.lock")
    with lock_path.open("a", encoding="utf-8") as handle:
        _ensure_shared_file_mode(lock_path)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def atomic_write_text(path: Path, text: str) -> None:
    _ensure_parent_dir(path)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        _ensure_shared_file_mode(tmp_path)
        os.replace(tmp_path, path)
        _ensure_shared_file_mode(path)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_bytes(path: Path, data: bytes) -> None:
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
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


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
