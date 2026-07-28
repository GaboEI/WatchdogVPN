"""Dedicated provisioner exclusion lock (Phase 23.7.5.6a).

Distinct from ``config.persistence``'s restore-transaction lock/journal: the
provisioner needs its own kernel-level lock and its own recovery semantics,
never coupled to backup/restore recovery side effects. Only ``atomic_write``/
``fsync``-style primitives are shared, not the restore journal itself.

Fifth correction round, point 1: the lock itself no longer lives inside
``state_root`` (a tree that can be renamed/replaced by anything that can
write to its shared parent while the lock is held). It lives under a
dedicated, stable ``global_lock_root`` -- e.g. ``/run/lock/watchdogvpn/
provisioning`` in production, or a per-test tmp directory kept OUTSIDE any
single test's own renamable ``state_root`` tree -- keyed by a stable hash of
``state_root``'s own CONFIGURED path string (never a resolved/canonicalized
one, and never the directory's own identity), so two processes configured
with the SAME ``state_root`` path always contend for the exact same lock
file regardless of what has since happened to that path physically. The
global lock is acquired BEFORE ``state_root`` is ever created, opened or
recovered.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import stat as stat_module
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from compat.provisioning.errors import PathPolicyError, ProvisionerLockHeldError
from compat.provisioning.journal import HISTORY_DIR, OWNERSHIP_DIR, TRANSACTIONS_DIR
from compat.provisioning.storage import StateRootHandle, ensure_private_lock_root, open_state_root

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.05

_LOCK_OPEN_FLAGS = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_ROOT_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _global_lock_file_name(state_root: Path) -> str:
    """A stable, deterministic lock filename derived from ``state_root``'s
    own CONFIGURED path string -- never its resolved/canonicalized form
    (which could itself be affected by the very swap being defended
    against), and never its physical identity (``st_dev``/``st_ino``, which
    is exactly what may have changed). Two processes given the identical
    configured path always compute the identical filename, so they always
    contend for the same lock regardless of what has happened to the path
    physically in between -- satisfying the invariant that two processes
    using the same logical installation can never acquire distinct locks
    even if ``state_root`` is renamed, deleted or replaced."""
    state_root = Path(state_root)
    if not state_root.is_absolute():
        raise PathPolicyError("state root must be an absolute path: %s" % state_root)
    digest = hashlib.sha256(str(state_root).encode("utf-8")).hexdigest()
    return "%s.lock" % digest


def _open_global_root(global_lock_root: Path) -> int:
    global_lock_root = ensure_private_lock_root(Path(global_lock_root))
    try:
        fd = os.open(str(global_lock_root), _ROOT_OPEN_FLAGS)
    except OSError as exc:
        raise PathPolicyError("cannot open global lock root %s: %s" % (global_lock_root, exc)) from exc
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISDIR(st.st_mode):
            raise PathPolicyError("global lock root is not a directory: %s" % global_lock_root)
        if st.st_uid != os.getuid():
            raise PathPolicyError("global lock root %s is owned by uid %d, expected %d" % (global_lock_root, st.st_uid, os.getuid()))
    except Exception:
        os.close(fd)
        raise
    return fd


def _open_and_verify_lock_fd_relative(root_fd: int, name: str) -> int:
    """Open the lock file with ``O_NOFOLLOW``, strictly within ``root_fd``
    (the global, stable lock root -- never a fresh path-based lookup, and
    never inside the renamable ``state_root`` tree), and verify its
    identity via ``fstat`` BEFORE any ``fchmod`` or content mutation -- a
    symlink at ``name`` (ELOOP), a directory (``IsADirectoryError``), a
    hardlinked file (``st_nlink != 1``), or a file owned by a different uid
    must all be rejected untouched; the victim they point to must never be
    chmod'd, truncated or written to."""
    expected_uid = os.getuid()
    try:
        fd = os.open(name, _LOCK_OPEN_FLAGS, 0o600, dir_fd=root_fd)
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
    global_lock_root: Path,
    transaction_id: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> Iterator[StateRootHandle]:
    """Acquire the single machine-wide provisioner lock for ``state_root``,
    then bind a ``StateRootHandle`` to its identity for the whole
    transaction (fifth correction round, point 1).

    Order matters and is never reversed: the global lock (under
    ``global_lock_root``, a dedicated root never renamed/replaced by
    anything that can write to ``state_root``'s own shared parent) is
    acquired FIRST; only once it is held is ``state_root`` itself ever
    created, opened, or recovered. This is what lets two processes
    configured with the identical ``state_root`` path always contend for
    the exact same lock even if ``state_root`` itself has been renamed,
    deleted, or replaced by something else in between -- the lock's own
    identity was never inside that tree to begin with.

    Once the state root is opened, ``transactions``/``ownership``/
    ``history`` are EAGERLY opened (their descriptors cached on the
    returned handle) before this contextmanager ever yields -- i.e. before
    any recovery pass or other use gets a chance to run -- so a rename/
    replace of one of those subdirectories that happens afterward can never
    make a later listing of it silently reflect the wrong (empty,
    replacement) directory instead of the real one this transaction is
    bound to.

    The yielded ``StateRootHandle`` must be passed to every ``journal``
    module call for the remainder of the critical section instead of a
    bare path; its ``verify_identity()`` is also re-checked by those calls
    before every mutating write.

    Non-blocking flock attempts are retried until ``timeout`` elapses; if
    the lock is still held, a controlled ``ProvisionerLockHeldError`` is
    raised instead of blocking forever. The informational metadata written
    into the lock file (PID, start time, transaction id, state root path)
    is for operator diagnostics only -- the kernel flock, not this
    metadata, is what actually excludes a second mutating provisioner.
    """
    global_root_fd = _open_global_root(Path(global_lock_root))
    try:
        lock_name = _global_lock_file_name(Path(state_root))
        fd = _open_and_verify_lock_fd_relative(global_root_fd, lock_name)
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
            _write_holder_metadata(handle, transaction_id=transaction_id, state_root=state_root)
            try:
                state_root_handle = open_state_root(Path(state_root))
                try:
                    for subdir_name in (TRANSACTIONS_DIR, OWNERSHIP_DIR, HISTORY_DIR):
                        state_root_handle.subdir_fd(subdir_name)
                    yield state_root_handle
                finally:
                    state_root_handle.close()
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
    finally:
        os.close(global_root_fd)


def _write_holder_metadata(handle, *, transaction_id: str, state_root: Path) -> None:
    metadata = {
        "pid": os.getpid(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "transaction_id": transaction_id,
        "state_root": str(state_root),
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
