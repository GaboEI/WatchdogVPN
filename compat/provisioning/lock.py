"""Dedicated provisioner exclusion lock (Phase 23.7.5.6a).

Distinct from ``config.persistence``'s restore-transaction lock/journal: the
provisioner needs its own kernel-level lock and its own recovery semantics,
never coupled to backup/restore recovery side effects. Only ``atomic_write``/
``fsync``-style primitives are shared, not the restore journal itself.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import stat as stat_module
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from compat.provisioning.errors import PathPolicyError, ProvisionerLockHeldError
from compat.provisioning.storage import ensure_private_dir

LOCK_FILE_NAME = "provisioner.lock"
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.05

_LOCK_OPEN_FLAGS = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_and_verify_lock_fd(lock_path: Path) -> int:
    """Open the lock file with ``O_NOFOLLOW`` and verify its identity via
    ``fstat`` BEFORE any ``fchmod`` or content mutation -- a symlink at
    ``lock_path`` (ELOOP), a directory (``IsADirectoryError``), a hardlinked
    file (``st_nlink != 1``), or a file owned by a different uid must all be
    rejected untouched; the victim they point to must never be chmod'd,
    truncated or written to."""
    expected_uid = os.getuid()
    try:
        fd = os.open(str(lock_path), _LOCK_OPEN_FLAGS, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PathPolicyError("lock path is a symlink, refusing: %s" % lock_path) from exc
        if exc.errno == errno.EISDIR:
            raise PathPolicyError("lock path is a directory, refusing: %s" % lock_path) from exc
        raise PathPolicyError("cannot open lock path %s: %s" % (lock_path, exc)) from exc
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISREG(st.st_mode):
            raise PathPolicyError("lock path %s is not a regular file, refusing" % lock_path)
        if st.st_nlink != 1:
            raise PathPolicyError("lock path %s has unexpected hard link count %d, refusing" % (lock_path, st.st_nlink))
        if st.st_uid != expected_uid:
            raise PathPolicyError("lock path %s is owned by uid %d, expected %d, refusing" % (lock_path, st.st_uid, expected_uid))
        if stat_module.S_IMODE(st.st_mode) != 0o600:
            os.fchmod(fd, 0o600)
    except Exception:
        os.close(fd)
        raise
    return fd


@contextmanager
def acquire_provisioner_lock(
    lock_path: Path,
    *,
    transaction_id: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> Iterator[None]:
    """Acquire the single machine-wide provisioner lock.

    Non-blocking flock attempts are retried until ``timeout`` elapses; if the
    lock is still held, a controlled ``ProvisionerLockHeldError`` is raised
    instead of blocking forever. The informational metadata written into the
    lock file (PID, start time, transaction id) is for operator diagnostics
    only -- the kernel flock, not this metadata, is what actually excludes a
    second mutating provisioner.
    """
    lock_path = Path(lock_path)
    ensure_private_dir(lock_path.parent)
    fd = _open_and_verify_lock_fd(lock_path)
    handle = os.fdopen(fd, "r+", encoding="utf-8")
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    holder_pid, holder_transaction_id = _read_holder_metadata(handle)
                    raise ProvisionerLockHeldError(
                        "provisioner lock is held by another process (pid=%s, transaction_id=%s)"
                        % (holder_pid, holder_transaction_id),
                        holder_pid=holder_pid,
                        holder_transaction_id=holder_transaction_id,
                    ) from exc
                time.sleep(poll_interval)
        _write_holder_metadata(handle, transaction_id=transaction_id)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _write_holder_metadata(handle, *, transaction_id: str) -> None:
    metadata = {
        "pid": os.getpid(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "transaction_id": transaction_id,
    }
    handle.seek(0)
    handle.truncate()
    handle.write(json.dumps(metadata))
    handle.flush()
    os.fsync(handle.fileno())


def _read_holder_metadata(handle) -> tuple[int | None, str | None]:
    try:
        handle.seek(0)
        raw = handle.read()
        if not raw.strip():
            return None, None
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None, None
        pid = data.get("pid")
        transaction_id = data.get("transaction_id")
        return (pid if isinstance(pid, int) else None, transaction_id if isinstance(transaction_id, str) else None)
    except (OSError, ValueError):
        return None, None
