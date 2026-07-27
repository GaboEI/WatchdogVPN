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
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from compat.provisioning.errors import ProvisionerLockHeldError

LOCK_FILE_NAME = "provisioner.lock"
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.05


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
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "a+")
    try:
        os.fchmod(handle.fileno(), 0o600)
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
