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

import os
import tempfile
from pathlib import Path

from compat.provisioning.errors import DurabilityError

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` (and any missing parents) with mode 0700. Never widens
    the permissions of a directory that already exists."""
    path = Path(path)
    if path.is_dir():
        return
    parent = path.parent
    if parent != path:
        ensure_private_dir(parent)
    try:
        path.mkdir(mode=PRIVATE_DIR_MODE)
    except FileExistsError:
        return
    os.chmod(path, PRIVATE_DIR_MODE)


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
