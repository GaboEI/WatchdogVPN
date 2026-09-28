"""Descriptor-relative, no-follow creation and validation of privileged state paths.

The shared watch state tree ``/var/lib/watchdogvpn`` is ``root:watchdogvpn`` mode
``02770``, so a member of the ``watchdogvpn`` group can pre-create entries there.
This helper therefore never follows a pre-existing symlink: it opens the trusted
parent as ``O_DIRECTORY | O_NOFOLLOW``, creates or opens the child relative to
that descriptor, applies owner/mode only through a descriptor that has been
validated with ``fstat``, re-confirms the directory entry before returning, and
fails closed on every unsafe or racing condition.

``open_state_directory`` returns an owned directory descriptor so callers can
perform every subsequent create, rename, read, unlink and fsync of their state
file relative to that descriptor instead of a pathname. This is the single
primitive used by the installer, the DNS restore helper and the TUN ownership
helper for ``/var/lib/watchdogvpn/nm-dns-restore`` and ``/var/lib/watchdogvpn/nm-tun``.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


# Root-owned, root-only state: the durable DNS/TUN authority must never be
# readable or writable by the watchdogvpn group that shares the parent tree.
EXPECTED_STATE_UID = 0
EXPECTED_STATE_GID = 0
EXPECTED_DIRECTORY_MODE = 0o700
EXPECTED_FILE_MODE = 0o600


class PrivilegedStateError(RuntimeError):
    """Raised for any unsafe, untrusted, or racing privileged state condition."""


def prepare_state_directory(
    directory: Path,
    state_file: str | None = None,
    *,
    uid: int | None = None,
    gid: int | None = None,
    directory_mode: int | None = None,
    file_mode: int | None = None,
) -> None:
    """Ensure ``directory`` is a root-only state directory.

    When ``state_file`` is given and already exists inside the directory, it is
    validated no-follow as a regular root-owned file with the required mode; a
    symlink or any incompatible entry fails closed without touching its target.
    """
    expected_file_mode = EXPECTED_FILE_MODE if file_mode is None else file_mode
    child_fd = open_state_directory(
        directory, uid=uid, gid=gid, directory_mode=directory_mode
    )
    try:
        if state_file is not None:
            _validate_state_file(child_fd, state_file, uid, gid, expected_file_mode)
    finally:
        os.close(child_fd)


def open_state_directory(
    directory: Path,
    *,
    create: bool = True,
    uid: int | None = None,
    gid: int | None = None,
    directory_mode: int | None = None,
) -> int:
    """Open ``directory`` as a validated root-only directory and return its fd.

    The caller owns the returned descriptor and must close it. When ``create``
    is false and the directory (or its parent) is absent, ``FileNotFoundError``
    is raised; any unsafe condition raises ``PrivilegedStateError``.
    """
    expected_uid = EXPECTED_STATE_UID if uid is None else uid
    expected_gid = EXPECTED_STATE_GID if gid is None else gid
    expected_mode = EXPECTED_DIRECTORY_MODE if directory_mode is None else directory_mode
    parent_fd = _open_parent_directory(directory.parent, create=create)
    try:
        name = directory.name
        created = False
        if not _entry_exists(parent_fd, name):
            if not create:
                raise FileNotFoundError(directory)
            _create_child_directory(parent_fd, name, expected_mode)
            created = True
        child_fd = _open_child_directory(parent_fd, name)
        try:
            _require_directory(child_fd)
            if created:
                _apply_directory_metadata(child_fd, expected_uid, expected_gid, expected_mode)
            _require_expected_directory(child_fd, expected_uid, expected_gid, expected_mode)
            _confirm_inode(parent_fd, name, child_fd)
        except BaseException:
            os.close(child_fd)
            raise
        return child_fd
    finally:
        os.close(parent_fd)


def confirm_state_directory_identity(directory: Path, directory_fd: int) -> None:
    """Re-confirm that ``directory`` still names the validated descriptor."""
    parent_fd = _open_parent_directory(directory.parent, create=False)
    try:
        _confirm_inode(parent_fd, directory.name, directory_fd)
    finally:
        os.close(parent_fd)


def _open_parent_directory(directory: Path, *, create: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(directory, flags)
    except FileNotFoundError:
        if create:
            raise PrivilegedStateError("state parent directory is missing: %s" % directory) from None
        raise
    except OSError as exc:
        raise PrivilegedStateError(
            "state parent is not a safe, non-symlink directory: %s" % directory
        ) from exc


def _entry_exists(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PrivilegedStateError("cannot inspect state entry: %s" % name) from exc
    return True


def _create_child_directory(parent_fd: int, name: str, mode: int) -> None:
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
    except OSError as exc:
        raise PrivilegedStateError("cannot create state directory: %s" % name) from exc


def _open_child_directory(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise PrivilegedStateError(
            "state path is a symlink or not a directory: %s" % name
        ) from exc


def _require_directory(child_fd: int) -> None:
    if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
        raise PrivilegedStateError("state path is not a directory")


def _apply_directory_metadata(child_fd: int, uid: int, gid: int, mode: int) -> None:
    # A freshly created child inherits the parent's setgid bit and group, so set
    # the exact owner and mode through the validated descriptor (never the
    # pathname) before the directory is trusted.
    try:
        os.fchown(child_fd, uid, gid)
        os.fchmod(child_fd, mode)
    except OSError as exc:
        raise PrivilegedStateError("cannot apply state directory metadata") from exc


def _require_expected_directory(child_fd: int, uid: int, gid: int, mode: int) -> None:
    info = os.fstat(child_fd)
    if (
        info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise PrivilegedStateError("state directory is not root-owned and root-only")


def _confirm_inode(parent_fd: int, name: str, child_fd: int) -> None:
    # Re-read the directory entry without following symlinks: if it no longer
    # names the inode we validated, a racing party swapped it and we fail closed.
    try:
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise PrivilegedStateError("cannot re-confirm state directory identity") from exc
    opened = os.fstat(child_fd)
    if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
        raise PrivilegedStateError("state directory identity changed during preparation")


def _validate_state_file(
    directory_fd: int, name: str, uid: int | None, gid: int | None, file_mode: int
) -> None:
    expected_uid = EXPECTED_STATE_UID if uid is None else uid
    expected_gid = EXPECTED_STATE_GID if gid is None else gid
    try:
        file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PrivilegedStateError(
            "state file is a symlink or cannot be opened safely: %s" % name
        ) from exc
    try:
        info = os.fstat(file_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != file_mode
        ):
            raise PrivilegedStateError(
                "state file is not a regular root-owned file with the required mode: %s" % name
            )
    finally:
        os.close(file_fd)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "prepare":
        directory, state_file = args[1], None
    elif len(args) == 3 and args[0] == "prepare":
        directory, state_file = args[1], args[2]
    else:
        print("usage: watchdogvpn-state-guard prepare <directory> [state-file]", file=sys.stderr)
        return 2
    try:
        prepare_state_directory(Path(directory), state_file)
    except PrivilegedStateError as exc:
        print("watchdogvpn-state-guard: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
