"""Private state-root storage primitives for transactional provisioning.

Deliberately NOT ``config.persistence.atomic_write_text``: that primitive
widens permissions to ``0660``/``02770`` (group-shared, setgid) for state
under ``/var/lib/watchdogvpn`` so multiple system groups can cooperate on
shared config. The provisioner's own journals/ownership records/lock are never
shared with any other group -- they must stay ``0700``/``0600`` no matter
where ``state_root`` happens to live, including under
``/var/lib/watchdogvpn``. This module is the only place that writes them.

This module is explicitly aware of the state-root boundary: only
``state_root`` itself and its own descendants (``ensure_private_state_root``/
``ensure_private_subdir``) may ever be created or have their mode/ownership
enforced. The directory that sits directly ABOVE ``state_root`` -- the real
product's own ``/var/lib/watchdogvpn``, a dedicated lab root, ``$HOME``, a
system temp dir, whatever it is -- is verified read-only (must exist, must
not be a symlink, must be a real directory) and is NEVER chmod'd, chown'd,
created or replaced. A state root created fresh under a parent at ``02770``
(setgid, group-shared product config), ``0755`` or ``01777`` must leave that
parent's mode exactly as it found it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import errno
import os
import stat as stat_module
import tempfile
import uuid
from pathlib import Path

from compat.provisioning.errors import DurabilityError, PathPolicyError

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600

_DIR_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


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


def _check_and_secure_directory_fd(path_desc: object, fd: int) -> None:
    """Verifies ``fd`` is a real directory owned by us, tightening its mode
    to ``0700`` if loose. Never closes ``fd`` -- the caller decides whether
    this is a one-shot check (see ``_verify_and_secure_directory_fd``, which
    closes it) or a lasting handle it intends to keep open (see
    ``StateRootHandle``)."""
    expected_uid = os.getuid()
    st = os.fstat(fd)
    if not stat_module.S_ISDIR(st.st_mode):
        raise PathPolicyError("state path is not a directory: %s" % path_desc)
    if st.st_uid != expected_uid:
        raise PathPolicyError(
            "state path %s is owned by uid %d, expected %d; refusing to use it" % (path_desc, st.st_uid, expected_uid)
        )
    if stat_module.S_IMODE(st.st_mode) != PRIVATE_DIR_MODE:
        os.fchmod(fd, PRIVATE_DIR_MODE)


def _verify_and_secure_directory_fd(path: Path, fd: int) -> None:
    try:
        _check_and_secure_directory_fd(path, fd)
    finally:
        os.close(fd)


def _open_dir_relative(parent_fd: int, name: str) -> int:
    """Descriptor-relative equivalent of ``_open_directory_nofollow``: opens
    ``name`` strictly within the directory ``parent_fd`` refers to, never
    resolving any path from the filesystem root. A genuinely absent
    component re-raises ``FileNotFoundError`` verbatim."""
    try:
        return os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except NotADirectoryError as exc:
        raise PathPolicyError("state path exists but is not a directory: %s" % name) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PathPolicyError("state path is a symlink, refusing: %s" % name) from exc
        raise PathPolicyError("cannot open state directory %s: %s" % (name, exc)) from exc


def _verify_external_parent_readonly(parent: Path) -> None:
    """Verify, but never mutate, the directory directly ABOVE the state
    root. It must already exist as a real, non-symlink directory; this
    module never creates it and never touches its mode or ownership --
    a parent at ``02770``, ``0755`` or ``01777`` keeps that exact mode."""
    try:
        fd = _open_directory_nofollow(parent)
    except FileNotFoundError as exc:
        raise PathPolicyError("state root's parent directory does not exist: %s" % parent) from exc
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISDIR(st.st_mode):
            raise PathPolicyError("state root's parent is not a directory: %s" % parent)
    finally:
        os.close(fd)


def ensure_private_state_root(state_root: Path) -> Path:
    """Create (if missing) and verify ``state_root`` itself, at mode
    ``0700``, owned by us, never following a symlink. The external parent is
    verified read-only via ``_verify_external_parent_readonly`` and is never
    mutated -- only ``state_root`` itself is ever created or has its mode
    enforced. A newly created ``state_root`` has its parent directory entry
    fsynced for durability."""
    state_root = Path(state_root)
    parent = state_root.parent
    if parent == state_root:
        raise PathPolicyError("state root must not be the filesystem root: %s" % state_root)
    _verify_external_parent_readonly(parent)
    try:
        fd = _open_directory_nofollow(state_root)
    except FileNotFoundError:
        try:
            os.mkdir(state_root, PRIVATE_DIR_MODE)
        except FileExistsError:
            pass  # lost a creation race with another process; fall through and verify below
        else:
            fsync_parent_directory(state_root)
        fd = _open_directory_nofollow(state_root)
    _verify_and_secure_directory_fd(state_root, fd)
    return state_root


def ensure_private_subdir(state_root: Path, relative_path: Path | str) -> Path:
    """Create (if missing) and verify a directory strictly inside
    ``state_root`` (e.g. ``transactions``, ``ownership``, ``history``).
    Establishes ``state_root`` itself first via ``ensure_private_state_root``,
    then walks only the given relative components, one at a time, each via
    an ``O_NOFOLLOW`` open + ``fstat`` -- a symlink swapped in for any
    component is rejected rather than silently followed. Never walks or
    mutates anything outside ``state_root``."""
    state_root = Path(state_root)
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise PathPolicyError("subdir must be a non-empty relative path with no '..' components: %s" % relative_path)
    ensure_private_state_root(state_root)
    current = state_root
    for part in relative.parts:
        current = current / part
        try:
            fd = _open_directory_nofollow(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, PRIVATE_DIR_MODE)
            except FileExistsError:
                pass
            else:
                fsync_parent_directory(current)
            fd = _open_directory_nofollow(current)
        _verify_and_secure_directory_fd(current, fd)
    return current


@dataclass
class StateRootHandle:
    """An OPEN, identity-bound handle to ``state_root`` (point 1, fourth
    correction round) -- captured once via ``open_state_root()`` and held
    for the entire duration of a lock-protected transaction. Every
    descriptor-relative operation (``os.open``/``os.mkdir``/``os.replace``/
    ``os.unlink`` with ``dir_fd=``) resolves against this handle's file
    descriptors, which continue to reference the SAME physical directory
    regardless of any external rename, symlink-swap, or directory-replace
    of ``state_root``'s path afterward. Once this handle exists, a fresh
    path-based lookup of ``state_root`` (or its subdirectories) is never
    used again for the rest of the transaction -- that is precisely the
    TOCTOU window this handle closes: a process holding it either keeps
    operating correctly on the original directory via the descriptor, or
    fails closed (a subdirectory it never opened before now raising
    ``PathPolicyError`` if the replacement is a symlink or wrong type), but
    never silently starts operating on a newly created directory at the
    same path."""

    path: Path
    fd: int
    dev: int
    ino: int
    _subdir_fds: dict = field(default_factory=dict, repr=False, compare=False)

    def subdir_fd(self, name: str) -> int:
        """Returns a cached, verified directory fd for ``name`` (e.g.
        ``"transactions"``) strictly inside this handle's state root,
        opening/creating it on first use and reusing the SAME fd for the
        rest of this handle's lifetime -- an external rename/replace of
        that subdirectory after the first call cannot redirect subsequent
        operations, for the same reason the state root fd itself is
        immune to it."""
        if name not in self._subdir_fds:
            self._subdir_fds[name] = _ensure_private_subdir_relative(self.fd, name)
        return self._subdir_fds[name]

    def close(self) -> None:
        for fd in self._subdir_fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self._subdir_fds.clear()
        try:
            os.close(self.fd)
        except OSError:
            pass


def open_state_root(state_root: Path) -> StateRootHandle:
    """Descriptor-relative equivalent of ``ensure_private_state_root``: does
    the SAME boundary verification (external parent verified read-only and
    never mutated, ``state_root`` itself created/verified/tightened to
    ``0700``), but returns an OPEN file descriptor -- with its ``st_dev``/
    ``st_ino`` captured at open time -- instead of closing it. Callers MUST
    hold this handle, and use it (never a re-resolved path) for every state
    operation, for the entire duration of a lock-protected transaction."""
    state_root = Path(state_root)
    parent = state_root.parent
    if parent == state_root:
        raise PathPolicyError("state root must not be the filesystem root: %s" % state_root)
    _verify_external_parent_readonly(parent)
    try:
        fd = _open_directory_nofollow(state_root)
    except FileNotFoundError:
        try:
            os.mkdir(state_root, PRIVATE_DIR_MODE)
        except FileExistsError:
            pass
        else:
            fsync_parent_directory(state_root)
        fd = _open_directory_nofollow(state_root)
    _check_and_secure_directory_fd(state_root, fd)
    st = os.fstat(fd)
    return StateRootHandle(path=state_root, fd=fd, dev=st.st_dev, ino=st.st_ino)


def _ensure_private_subdir_relative(parent_fd: int, name: str) -> int:
    """Create (if missing) and verify a directory named ``name`` strictly
    within ``parent_fd``, returning an OPEN, verified fd for it -- never
    closed here, since the caller (``StateRootHandle.subdir_fd``) caches
    and reuses it for the handle's whole lifetime."""
    try:
        fd = _open_dir_relative(parent_fd, name)
    except FileNotFoundError:
        try:
            os.mkdir(name, PRIVATE_DIR_MODE, dir_fd=parent_fd)
        except FileExistsError:
            pass
        else:
            os.fsync(parent_fd)  # durability of the new directory entry
        fd = _open_dir_relative(parent_fd, name)
    _check_and_secure_directory_fd(name, fd)
    return fd


def atomic_write_private_relative(dir_fd: int, name: str, data: bytes) -> None:
    """Descriptor-relative equivalent of ``atomic_write_private``: writes
    ``data`` atomically and durably to ``name`` strictly within ``dir_fd``,
    never resolving any path from the filesystem root. Uses ``os.replace``
    with ``src_dir_fd``/``dst_dir_fd`` (``renameat``) so the rename itself
    is bound to the same held descriptor as the temp file's creation."""
    tmp_name = ".%s.%s.tmp" % (name, uuid.uuid4().hex)
    fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE_MODE, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except Exception:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        raise
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        raise DurabilityError("write to %s completed but its directory could not be durably fsynced: %s" % (name, exc)) from exc


def atomic_write_private_text_relative(dir_fd: int, name: str, text: str) -> None:
    atomic_write_private_relative(dir_fd, name, text.encode("utf-8"))


def read_private_relative(dir_fd: int, name: str) -> str:
    """Reads a UTF-8 text file named ``name`` strictly within ``dir_fd``.
    ``FileNotFoundError`` propagates verbatim so callers can distinguish
    genuine absence from any other inspection error."""
    fd = os.open(name, os.O_RDONLY, dir_fd=dir_fd)
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        return handle.read()


def delete_private_relative(dir_fd: int, name: str) -> None:
    """Unlinks ``name`` strictly within ``dir_fd`` and durably fsyncs the
    directory entry. A genuinely absent file is treated as an idempotent
    no-op; any other ``OSError`` propagates."""
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return
    os.fsync(dir_fd)


def list_json_names_relative(dir_fd: int) -> list[str]:
    """Lists the ``*.json`` entry stems (filename without extension)
    directly within ``dir_fd``, sorted -- descriptor-relative equivalent of
    globbing a transactions/ownership/history directory by path."""
    try:
        entries = os.listdir(dir_fd)
    except FileNotFoundError:
        return []
    return sorted(name[: -len(".json")] for name in entries if name.endswith(".json"))


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
    """Atomically write ``data`` to ``path`` at mode 0600, durably. The
    parent directory must already exist and be secured -- callers establish
    it ahead of time via ``ensure_private_state_root``/
    ``ensure_private_subdir``; this function only verifies it (``O_NOFOLLOW``
    + ``fstat``), it never creates or climbs to any parent itself. Never
    applies the shared-group mode that ``config.persistence.atomic_write_text``
    uses for multi-group state -- provisioning state is always private to
    this engine."""
    path = Path(path)
    try:
        parent_fd = _open_directory_nofollow(path.parent)
    except FileNotFoundError as exc:
        raise PathPolicyError(
            "cannot write %s: parent directory does not exist (call ensure_private_subdir first): %s"
            % (path, path.parent)
        ) from exc
    _verify_and_secure_directory_fd(path.parent, parent_fd)
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
