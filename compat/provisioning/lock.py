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
from compat.provisioning.storage import StateRootHandle, open_state_root

LOCK_FILE_NAME = "provisioner.lock"
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.05

_LOCK_OPEN_FLAGS = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_and_verify_lock_fd_relative(state_root_fd: int, name: str) -> int:
    """Open the lock file with ``O_NOFOLLOW``, strictly within
    ``state_root_fd`` (point 1: never a fresh path-based lookup once the
    state root's own identity has been established), and verify its
    identity via ``fstat`` BEFORE any ``fchmod`` or content mutation -- a
    symlink at ``name`` (ELOOP), a directory (``IsADirectoryError``), a
    hardlinked file (``st_nlink != 1``), or a file owned by a different uid
    must all be rejected untouched; the victim they point to must never be
    chmod'd, truncated or written to."""
    expected_uid = os.getuid()
    try:
        fd = os.open(name, _LOCK_OPEN_FLAGS, 0o600, dir_fd=state_root_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PathPolicyError("lock path is a symlink, refusing: %s" % name) from exc
        if exc.errno == errno.EISDIR:
            raise PathPolicyError("lock path is a directory, refusing: %s" % name) from exc
        raise PathPolicyError("cannot open lock path %s: %s" % (name, exc)) from exc
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISREG(st.st_mode):
            raise PathPolicyError("lock path %s is not a regular file, refusing" % name)
        if st.st_nlink != 1:
            raise PathPolicyError("lock path %s has unexpected hard link count %d, refusing" % (name, st.st_nlink))
        if st.st_uid != expected_uid:
            raise PathPolicyError("lock path %s is owned by uid %d, expected %d, refusing" % (name, st.st_uid, expected_uid))
        if stat_module.S_IMODE(st.st_mode) != 0o600:
            os.fchmod(fd, 0o600)
    except Exception:
        os.close(fd)
        raise
    return fd


@contextmanager
def acquire_provisioner_lock(
    state_root: Path,
    *,
    transaction_id: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> Iterator[StateRootHandle]:
    """Acquire the single machine-wide provisioner lock, bound to
    ``state_root``'s own identity for the whole transaction (point 1,
    fourth correction round).

    ``state_root`` is opened ONCE via ``storage.open_state_root`` (its
    external parent verified read-only, ``state_root`` itself verified/
    tightened to ``0700``, its ``st_dev``/``st_ino`` captured) and the
    resulting handle's file descriptor is held open for as long as the
    lock is held. The lock file itself is opened RELATIVE TO that
    descriptor, never via a fresh path lookup -- an external rename,
    symlink-swap, or directory-replace of ``state_root`` after this point
    can never redirect the lock (or any journal/ownership operation the
    caller performs using the yielded handle) to a different physical
    directory. The yielded ``StateRootHandle`` must be passed to every
    ``journal`` module call for the remainder of the critical section
    instead of a bare path.

    Non-blocking flock attempts are retried until ``timeout`` elapses; if the
    lock is still held, a controlled ``ProvisionerLockHeldError`` is raised
    instead of blocking forever. The informational metadata written into the
    lock file (PID, start time, transaction id) is for operator diagnostics
    only -- the kernel flock, not this metadata, is what actually excludes a
    second mutating provisioner.
    """
    state_root_handle = open_state_root(state_root)
    try:
        fd = _open_and_verify_lock_fd_relative(state_root_handle.fd, LOCK_FILE_NAME)
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
                yield state_root_handle
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
    finally:
        state_root_handle.close()


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
