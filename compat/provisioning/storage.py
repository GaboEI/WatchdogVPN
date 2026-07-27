"""Private state-root storage primitives for transactional provisioning.

Deliberately NOT ``config.persistence.atomic_write_text``: that primitive
widens permissions to ``0660``/``02770`` (group-shared, setgid) for state
under ``/var/lib/watchdogvpn`` so multiple system groups can cooperate on
shared config. The provisioner's own journals/ownership records/lock are never
shared with any other group -- they must stay ``0700``/``0600`` no matter
where ``state_root`` happens to live, including under
``/var/lib/watchdogvpn``. This module is the only place that writes them.
"""

from __future__ import annotations

import errno
import os
import stat as stat_module
import tempfile
from pathlib import Path

from compat.provisioning.errors import DurabilityError, PathPolicyError

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600

_DIR_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` (and any missing parents) as real, non-symlink
    directories owned by our own uid, with mode 0700. Never trusts
    ``Path.is_dir()`` (which follows symlinks): every component is verified
    via an ``O_NOFOLLOW`` open + ``fstat``, so a symlink swapped in for any
    part of the state root is rejected rather than silently followed. A
    pre-existing directory owned by a different uid is rejected outright
    (fail closed, no chmod); one owned by us but with looser permissions is
    tightened via ``fchmod`` on the already-opened, already-verified
    descriptor (never a separate lstat-then-chmod, which would leave a
    symlink-swap race window).

    Recursion stops at the first ancestor that already exists (exactly like
    the previous ``Path.is_dir()``-based version): an already-existing
    ancestor above the state root (a system temp dir, ``$HOME``, ...) is
    verified in place but never walked further upward -- only the state
    root's own subtree is ever created or has its ownership/mode enforced."""
    path = Path(path)
    try:
        fd = _open_directory_nofollow(path)
    except FileNotFoundError:
        parent = path.parent
        if parent != path:
            ensure_private_dir(parent)
        try:
            os.mkdir(path, PRIVATE_DIR_MODE)
        except FileExistsError:
            pass  # lost a creation race with another process; fall through and verify below
        else:
            fsync_parent_directory(path)
        fd = _open_directory_nofollow(path)
    _verify_and_secure_directory_fd(path, fd)


def _open_directory_nofollow(path: Path) -> int:
    """Open ``path`` with ``O_NOFOLLOW``, translating a symlink/non-directory
    into a clear ``PathPolicyError``. A genuinely absent path re-raises
    ``FileNotFoundError`` verbatim so the caller can decide whether to create
    it."""
    try:
        return os.open(str(path), _DIR_OPEN_FLAGS)
    except FileNotFoundError:
        raise
    except NotADirectoryError as exc:
        raise PathPolicyError("state path exists but is not a directory: %s" % path) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PathPolicyError("state path is a symlink, refusing: %s" % path) from exc
        raise PathPolicyError("cannot open state directory %s: %s" % (path, exc)) from exc


def _verify_and_secure_directory_fd(path: Path, fd: int) -> None:
    expected_uid = os.getuid()
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISDIR(st.st_mode):
            raise PathPolicyError("state path is not a directory: %s" % path)
        if st.st_uid != expected_uid:
            raise PathPolicyError(
                "state path %s is owned by uid %d, expected %d; refusing to use it" % (path, st.st_uid, expected_uid)
            )
        if stat_module.S_IMODE(st.st_mode) != PRIVATE_DIR_MODE:
            os.fchmod(fd, PRIVATE_DIR_MODE)
    finally:
        os.close(fd)


def fsync_parent_directory(path: Path) -> None:
    """Make a create/replace/unlink durable across a host crash by fsyncing
    the directory entry, not just the file/action itself. Raises
    ``DurabilityError`` on failure -- callers must never declare the action
    verified/committed/undone/uninstalled when this raises."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(str(Path(path).parent), flags)
    except OSError as exc:
        raise DurabilityError("cannot open parent directory of %s for durability fsync: %s" % (path, exc)) from exc
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise DurabilityError(
            "write to %s completed but its parent directory could not be durably fsynced: %s" % (path, exc)
        ) from exc
    finally:
        try:
            os.close(directory_fd)
        except OSError:
            pass


def atomic_write_private(path: Path, data: bytes) -> None:
    """Atomically write ``data`` to ``path`` at mode 0600, durably. Creates
    any missing parent directories at 0700. Never applies the shared-group
    mode that ``config.persistence.atomic_write_text`` uses for multi-group
    state -- provisioning state is always private to this engine."""
    path = Path(path)
    ensure_private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=".%s." % path.name, suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    fsync_parent_directory(path)


def atomic_write_private_text(path: Path, text: str) -> None:
    atomic_write_private(path, text.encode("utf-8"))
